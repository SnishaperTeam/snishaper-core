//go:build linux

package proxy

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessRoutingSupported reports whether the platform can resolve the process
// behind a local TCP connection.
func ProcessRoutingSupported() bool { return true }

// findProcessName returns the executable base name (lower-cased) of the
// process that owns the established TCP connection whose remote endpoint is
// remoteAddr, or "" when it cannot be identified.
//
// Linux implementation: walk /proc/net/tcp{,6} for the ESTABLISHED row with a
// matching remote endpoint, take its socket inode, then scan /proc/<pid>/fd
// symlinks for that inode and read the process name from /proc/<pid>/comm.
func findProcessName(remoteAddr string) string {
	remote, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil || remote.Port == 0 {
		return ""
	}

	inode, err := lookupProcSocketInode(remote)
	if err != nil || inode == "" {
		return ""
	}
	return procNameByInode(inode)
}

// lookupProcSocketInode scans /proc/net/tcp and /proc/net/tcp6 for an
// ESTABLISHED connection whose remote endpoint matches and returns its inode.
func lookupProcSocketInode(remote *net.TCPAddr) (string, error) {
	var files []string
	if remote.IP.To4() != nil {
		files = []string{"/proc/net/tcp"}
	} else {
		files = []string{"/proc/net/tcp6"}
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		wantRem := procHexAddr(remote.IP, remote.Port)
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "01" { // 01 = ESTABLISHED
				continue
			}
			if fields[2] == wantRem {
				return fields[9], nil // inode column
			}
		}
	}
	return "", os.ErrNotExist
}

// procHexAddr renders ip:port in the hexadecimal form used by /proc/net/tcp*:
// the kernel prints the address as native-order u32 words in uppercase hex
// (each 4-byte group byte-swapped on little-endian hosts, e.g. 127.0.0.1 ->
// 0100007F) and the port as 4 uppercase hex digits.
func procHexAddr(ip net.IP, port int) string {
	portHex := strings.ToUpper(strconv.FormatInt(int64(port), 16))
	if v4 := ip.To4(); v4 != nil {
		return hexEncode(nativeOrderWords(v4)) + ":" + portHex
	}
	return hexEncode(nativeOrderWords(ip.To16())) + ":" + portHex
}

// littleEndian reports the host byte order; /proc/net/tcp* prints u32 words
// in host order, so only little-endian hosts need the swap.
var littleEndian = binary.NativeEndian.Uint16([]byte{0x01, 0x00}) == 0x0001

// nativeOrderWords byte-swaps every 4-byte word on little-endian hosts,
// matching the address form the kernel prints in /proc/net/tcp*.
func nativeOrderWords(b []byte) []byte {
	if !littleEndian {
		return b
	}
	out := make([]byte, len(b))
	for i := 0; i+4 <= len(b); i += 4 {
		out[i], out[i+1], out[i+2], out[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return out
}

func hexEncode(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}

// procNameByInode scans /proc/<pid>/fd for the socket inode and returns the
// owning process name from /proc/<pid>/comm.
func procNameByInode(inode string) string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	want := "socket:[" + inode + "]"
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", pid, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", pid, "fd", fd.Name()))
			if err == nil && link == want {
				if comm, err := os.ReadFile(filepath.Join("/proc", pid, "comm")); err == nil {
					return strings.ToLower(strings.TrimSpace(string(comm)))
				}
				return ""
			}
		}
	}
	return ""
}
