//go:build windows

package proxy

import (
	"net"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessRoutingSupported reports whether the platform can resolve the process
// behind a local TCP connection.
func ProcessRoutingSupported() bool { return true }

// iphlpapi GetExtendedTcpTable binding: x/sys/windows does not export it, so
// bind the call and the row layouts the API needs here.
var (
	modIphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable  = modIphlpapi.NewProc("GetExtendedTcpTable")
	procQueryFullProcessImageNm = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")
)

const (
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL: all rows, owner PID, no offload state
	tcpStateEstablished = 5 // MIB_TCP_STATE_ESTAB
)

type tcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint16
	RemoteAddr uint32
	RemotePort uint16
	OwningPid  uint32
}

type tcp6RowOwnerPid struct {
	LocalAddr   [16]byte
	LocalPort   uint16
	RemoteAddr  [16]byte
	RemotePort  uint16
	State       uint32
	OwningPid   uint32
}

// findProcessName returns the executable base name (lower-cased, e.g.
// "chrome.exe") of the process that owns the established TCP connection whose
// remote (client) endpoint is remoteAddr, or "" when it cannot be identified.
//
// The client endpoint (127.0.0.1:<ephemeral port>) is unique system-wide while
// the connection is established, so one table scan per lookup is enough.
// Callers must run it on the live request path, before the tunnel is handed
// off; an unidentified process fails closed for per-application rules.
func findProcessName(remoteAddr string) string {
	remote, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil || remote.Port == 0 {
		return ""
	}
	if remote.IP.To4() != nil {
		if pid := findOwnerPID4(remote); pid != 0 {
			return processNameByPID(pid)
		}
		return ""
	}
	if pid := findOwnerPID6(remote); pid != 0 {
		return processNameByPID(pid)
	}
	return ""
}

func findOwnerPID4(remote *net.TCPAddr) uint32 {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPidAll, 0)
	if ret != 0 && ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return 0
	}
	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPidAll, 0)
	if ret != 0 {
		return 0
	}
	if len(buf) < int(unsafe.Sizeof(uint32(0))) {
		return 0
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	header := int(unsafe.Sizeof(uint32(0)))
	rowSize := int(unsafe.Sizeof(tcpRowOwnerPid{}))
	for i := 0; i < int(count); i++ {
		off := header + i*rowSize
		if off+rowSize > len(buf) {
			return 0
		}
		row := (*tcpRowOwnerPid)(unsafe.Pointer(&buf[off]))
		if row.State != tcpStateEstablished {
			continue
		}
		ip := make([]byte, 4)
		*(*uint32)(unsafe.Pointer(&ip[0])) = row.RemoteAddr
		if remote.IP.To4().Equal(net.IP(ip)) && portFromNet(row.RemotePort) == remote.Port {
			return row.OwningPid
		}
	}
	return 0
}

func findOwnerPID6(remote *net.TCPAddr) uint32 {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET6, tcpTableOwnerPidAll, 0)
	if ret != 0 && ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return 0
	}
	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET6, tcpTableOwnerPidAll, 0)
	if ret != 0 {
		return 0
	}
	if len(buf) < int(unsafe.Sizeof(uint32(0))) {
		return 0
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	header := int(unsafe.Sizeof(uint32(0)))
	rowSize := int(unsafe.Sizeof(tcp6RowOwnerPid{}))
	for i := 0; i < int(count); i++ {
		off := header + i*rowSize
		if off+rowSize > len(buf) {
			return 0
		}
		row := (*tcp6RowOwnerPid)(unsafe.Pointer(&buf[off]))
		if row.State != tcpStateEstablished {
			continue
		}
		if remote.IP.To16().Equal(net.IP(row.RemoteAddr[:])) && portFromNet(row.RemotePort) == remote.Port {
			return row.OwningPid
		}
	}
	return 0
}

// portFromNet converts the big-endian-in-low-bits port stored in the TCP
// table to an int.
func portFromNet(raw uint16) int {
	return int(raw&0xff)<<8 | int(raw&0xff00)>>8
}

var processNameCache sync.Map // pid uint32 -> name ("" caches unresolvable pids too)

func processNameByPID(pid uint32) string {
	if v, ok := processNameCache.Load(pid); ok {
		name, _ := v.(string)
		return name
	}
	name := ""
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err == nil {
		var buf [windows.MAX_PATH]uint16
		size := uint32(len(buf))
		ret, _, _ := procQueryFullProcessImageNm.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		if ret != 0 {
			full := windows.UTF16ToString(buf[:size])
			if idx := strings.LastIndexByte(full, '\\'); idx >= 0 {
				full = full[idx+1:]
			}
			name = strings.ToLower(strings.TrimSpace(full))
		}
		_ = windows.CloseHandle(handle)
	}
	processNameCache.Store(pid, name)
	return name
}
