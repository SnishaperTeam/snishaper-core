//go:build windows

package singtun

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/SnishaperTeam/snishaper-core/config"

	"golang.org/x/sys/windows"
)

var netClassGUID = windows.GUID{
	Data1: 0x4d36e972,
	Data2: 0xe325,
	Data3: 0x11ce,
	Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18},
}

var (
	setupapiDLL                      = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiSetClassInstallParams = setupapiDLL.NewProc("SetupDiSetClassInstallParamsW")
	procSetupDiCallClassInstaller    = setupapiDLL.NewProc("SetupDiCallClassInstaller")
)

// matchesBrandAdapter 判断某个网卡设备是否由本应用自己创建。
//
// 必须严格限定在本项目创建的适配器上：sing-tun 与 sing-box / mihomo 共用同一套
// Wintun 驱动，设备描述同样含 "sing-tun"。若仅凭描述匹配，用户同时运行
// sing-box 时，本应用每次启停都会把对方的网卡删掉。
// 判定依据是本项目独有的名称（网卡片 / 友好名 / 描述中的产品名）或
// wintun 描述 + 本项目友好名。
//
// brand 让嵌入方（如 FlowWeaver）清理自己的网卡：产品名与参考产品不同，
// 硬编码参考产品名会导致其他嵌入方（如 FlowWeaver）的残留网卡永远清不掉。
func matchesBrandAdapter(brand config.Brand, desc string, friendly string) bool {
	d := strings.ToLower(desc)
	f := strings.ToLower(friendly)
	// 本项目自有命名（网卡片 / 友好名 / 描述）。只认产品名本身：
	// 共享的 "sing-tun" 驱动名不能作为删除依据，否则会误删 sing-box /
	// mihomo 的网卡（见 OwnNames 的说明）。
	for _, token := range brand.OwnNames() {
		if token == "" {
			continue
		}
		if strings.Contains(d, token) || strings.Contains(f, token) {
			return true
		}
	}
	// Wintun 驱动 + 本项目友好名：描述里的驱动名已漂移为 "sing-tun Tunnel"，
	// 单看描述无法区分产品，因此必须再要求友好名正是本产品名
	// （"FlowWeaver" 或 "flow-weaver" 这类 Wintun 命名形式）。
	//
	// 这里只能用 OwnNames：Tunnels() 含共享的 "sing-tun"，
	// 而 sing-box / mihomo 的友好名正是 "sing-tun"，用它会把对方的网卡删掉。
	if !strings.Contains(d, "wintun") {
		return false
	}
	for _, token := range brand.OwnNames() {
		if token != "" && strings.EqualFold(f, token) {
			return true
		}
	}
	return false
}

// cleanupStaleAdapters 移除本项目遗留的虚拟网卡，返回移除数量。
// 返回值供启动清理阶段记入日志（US1：用户需在启动日志中看到"清了几个"）。
func cleanupStaleAdapters(brand config.Brand, logf func(string)) int {
	devInfo, err := windows.SetupDiGetClassDevsEx(&netClassGUID, "", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		logf("[sing-tun] stale adapter scan unavailable: " + err.Error())
		return 0
	}
	defer devInfo.Close()
	removed := 0
	for i := 0; ; i++ {
		data, err := windows.SetupDiEnumDeviceInfo(devInfo, i)
		if err != nil {
			break
		}
		desc := deviceStringProperty(devInfo, data, windows.SPDRP_DEVICEDESC)
		friendly := deviceStringProperty(devInfo, data, windows.SPDRP_FRIENDLYNAME)
		if !matchesBrandAdapter(brand, desc, friendly) {
			continue
		}
		label := friendly
		if label == "" {
			label = desc
		}
		if removeNetDevice(devInfo, data) {
			removed++
			logf("[sing-tun] removed stale adapter: " + label)
		} else {
			logf("[sing-tun] failed to remove stale adapter: " + label)
		}
	}
	if removed > 0 {
		logf("[sing-tun] stale adapter cleanup removed " + fmt.Sprint(removed) + " device(s)")
	}
	return removed
}

func deviceStringProperty(devInfo windows.DevInfo, data *windows.DevInfoData, property windows.SPDRP) string {
	value, err := windows.SetupDiGetDeviceRegistryProperty(devInfo, data, property)
	if err != nil {
		return ""
	}
	s, _ := value.(string)
	return s
}

func removeNetDevice(devInfo windows.DevInfo, data *windows.DevInfoData) bool {
	params := &windows.RemoveDeviceParams{
		ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE),
		Scope:              windows.DI_REMOVEDEVICE_GLOBAL,
	}
	r1, _, _ := procSetupDiSetClassInstallParams.Call(
		uintptr(devInfo),
		uintptr(unsafe.Pointer(data)),
		uintptr(unsafe.Pointer(params)),
		unsafe.Sizeof(*params),
	)
	if r1 == 0 {
		return false
	}
	r1, _, _ = procSetupDiCallClassInstaller.Call(
		uintptr(windows.DIF_REMOVE),
		uintptr(devInfo),
		uintptr(unsafe.Pointer(data)),
	)
	return r1 != 0
}
