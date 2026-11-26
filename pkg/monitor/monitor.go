package monitor

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dean2021/goss"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/shirou/gopsutil/v4/sensors"

	"github.com/xos/serveragent/model"
	"github.com/xos/serveragent/pkg/gpu"
	gpustat "github.com/xos/serveragent/pkg/gpu/stat"
	"github.com/xos/serveragent/pkg/util"
)

var (
	Version           string
	expectDiskFsTypes = []string{
		"apfs", "ext4", "ext3", "ext2", "f2fs", "reiserfs", "jfs", "btrfs",
		"fuseblk", "zfs", "simfs", "ntfs", "fat32", "exfat", "xfs", "fuse.rclone",
	}
	excludeNetInterfaces = []string{
		"lo", "tun", "docker", "veth", "br-", "vmbr", "vnet", "kube",
		"wg", "tailscale", "zt", "virbr", "cni", "flannel", "cali",
		"cilium", "podman", "tap", "dummy", "bond", "sing-box", "clash",
		"meta", "awdl", "p2p", "llw", "gif", "stf", "vethernet", "npcap",
		"bridge", "br0", "br1",
	}
	agentConfig *model.AgentConfig
)

var (
	netInSpeed, netOutSpeed, netInTransfer, netOutTransfer uint64
	lastUpdateNetStats                                     time.Time
	cachedNetIOCounters                                    map[string]net.IOCountersStat
	cachedBootTime                                         time.Time
	// 磁盘分区缓存，避免频繁查询
	cachedDiskDevices     map[string]string
	cachedDiskDevicesTime time.Time
)

// 获取设备数据的最大尝试次数
const maxDeviceDataFetchAttempts = 3

// 获取主机数据的尝试次数，Key 为 Host 的属性名
var hostDataFetchAttempts = map[string]int{
	"CPU": 0,
	"GPU": 0,
}

// 获取状态数据的尝试次数，Key 为 HostState 的属性名
var statDataFetchAttempts = map[string]int{
	"CPU":  0,
	"Load": 0,
	"GPU":  0,
}

const temperatureRetryInterval = 10 * time.Second

var (
	temperatureStat     atomic.Pointer[[]model.SensorTemperature]
	updatingTemperature atomic.Bool
	temperatureRetryAt  time.Time                        // accessed only by the active collector
	sensorIgnoreList    = []string{"PMU tcal", "noname"} // includes the fixed Apple Silicon calibration sensor
)

func InitConfig(cfg *model.AgentConfig) {
	agentConfig = cfg
}

// GetHost 获取主机硬件信息
func GetHost() *model.Host {
	var ret model.Host

	hi, err := host.Info()
	if err != nil {
		util.Printf(agentConfig.Debug, "host.Info error: %v", err)
	} else {
		ret.Platform = hi.Platform
		ret.PlatformVersion = hi.PlatformVersion
		ret.Arch = hi.KernelArch
		ret.BootTime = hi.BootTime
	}
	cpuType := "Physical"
	ret.Virtualization = detectVirtualization(hi)
	if ret.Virtualization != "" {
		cpuType = "Virtual"
		util.Printf(agentConfig.Debug, "Detected virtualization: %s", ret.Virtualization)
	}
	if ret.BootTime == 0 {
		if bootTime, bootErr := host.BootTime(); bootErr == nil && bootTime > 0 {
			ret.BootTime = bootTime
		}
	}

	cpuModelCount := make(map[string]int)
	if hostDataFetchAttempts["CPU"] < maxDeviceDataFetchAttempts {
		ci, err := cpu.Info()
		if err != nil {
			hostDataFetchAttempts["CPU"]++
			util.Printf(agentConfig.Debug, "cpu.Info error: %v, attempt: %d", err, hostDataFetchAttempts["CPU"])
		} else {
			hostDataFetchAttempts["CPU"] = 0
			for i := 0; i < len(ci); i++ {
				cpuModelCount[ci[i].ModelName]++
			}
			for model, count := range cpuModelCount {
				if len(ci) > 1 {
					ret.CPU = append(ret.CPU, fmt.Sprintf("%s %d %s Core", model, count, cpuType))
				} else {
					ret.CPU = append(ret.CPU, fmt.Sprintf("%s %d %s Core", model, ci[0].Cores, cpuType))
				}
			}
		}
	}

	if agentConfig.GPU {
		if hostDataFetchAttempts["GPU"] < maxDeviceDataFetchAttempts {
			ret.GPU, err = gpu.GetGPUModel()
			if err != nil {
				hostDataFetchAttempts["GPU"]++
				util.Printf(agentConfig.Debug, "gpu.GetGPUModel error: %v, attempt: %d", err, hostDataFetchAttempts["GPU"])
			} else {
				hostDataFetchAttempts["GPU"] = 0
			}
		}
	}

	ret.DiskTotal, _ = getDiskTotalAndUsed()

	vm, err := mem.VirtualMemory()
	if err != nil {
		util.Printf(agentConfig.Debug, "mem.VirtualMemory error: %v", err)
	} else {
		ret.MemTotal = vm.Total
		if runtime.GOOS != "windows" {
			ret.SwapTotal = vm.SwapTotal
		}
	}

	if runtime.GOOS == "windows" {
		ms, err := mem.SwapMemory()
		if err != nil {
			util.Printf(agentConfig.Debug, "mem.SwapMemory error: %v", err)
		} else {
			ret.SwapTotal = ms.Total
		}
	}

	if ret.BootTime > 0 {
		cachedBootTime = time.Unix(int64(ret.BootTime), 0)
	} else if cachedBootTime.IsZero() {
		cachedBootTime = time.Now()
	}

	ret.IP = CachedIP
	ret.Version = Version

	return &ret
}

func GetState(skipConnectionCount bool, skipProcsCount bool) *model.HostState {
	var ret model.HostState

	if statDataFetchAttempts["CPU"] < maxDeviceDataFetchAttempts {
		cp, err := cpu.Percent(0, false)
		if err != nil || len(cp) == 0 {
			statDataFetchAttempts["CPU"]++
			util.Printf(agentConfig.Debug, "cpu.Percent error: %v, attempt: %d", err, statDataFetchAttempts["CPU"])
		} else {
			statDataFetchAttempts["CPU"] = 0
			ret.CPU = cp[0]
		}
	}

	vm, err := mem.VirtualMemory()
	if err != nil {
		util.Printf(agentConfig.Debug, "mem.VirtualMemory error: %v", err)
	} else {
		ret.MemUsed = vm.Used
		if runtime.GOOS != "windows" {
			ret.SwapUsed = vm.SwapTotal - vm.SwapFree
		}
	}
	if runtime.GOOS == "windows" {
		// gopsutil 在 Windows 下不能正确取 swap
		ms, err := mem.SwapMemory()
		if err != nil {
			util.Printf(agentConfig.Debug, "mem.SwapMemory error: %v", err)
		} else {
			ret.SwapUsed = ms.Used
		}
	}

	_, ret.DiskUsed = getDiskTotalAndUsed()

	if statDataFetchAttempts["Load"] < maxDeviceDataFetchAttempts {
		loadStat, err := load.Avg()
		if err != nil {
			statDataFetchAttempts["Load"]++
			util.Printf(agentConfig.Debug, "load.Avg error: %v, attempt: %d", err, statDataFetchAttempts["Load"])
		} else {
			statDataFetchAttempts["Load"] = 0
			ret.Load1 = loadStat.Load1
			ret.Load5 = loadStat.Load5
			ret.Load15 = loadStat.Load15
		}
	}

	var procs []int32
	if !skipProcsCount {
		procs, err = process.Pids()
		if err != nil {
			util.Printf(agentConfig.Debug, "process.Pids error: %v", err)
		} else {
			ret.ProcessCount = uint64(len(procs))
		}
	}

	if agentConfig.Temperature {
		if temperatures := temperatureStat.Load(); temperatures != nil {
			ret.Temperatures = *temperatures
		}
		go updateTemperatureStat(agentConfig.Debug)
	}

	ret.GPU = updateGPUStat()

	ret.NetInTransfer, ret.NetOutTransfer = netInTransfer, netOutTransfer
	ret.NetInSpeed, ret.NetOutSpeed = netInSpeed, netOutSpeed
	if cachedBootTime.IsZero() {
		if bootTime, err := host.BootTime(); err == nil && bootTime > 0 {
			cachedBootTime = time.Unix(int64(bootTime), 0)
		} else {
			cachedBootTime = time.Now()
		}
	}
	if uptime := time.Since(cachedBootTime); uptime > 0 {
		ret.Uptime = uint64(uptime.Seconds())
	}
	ret.TcpConnCount, ret.UdpConnCount = getConns(skipConnectionCount)

	return &ret
}

func isNetInterfaceExcluded(name string) bool {
	lower := strings.ToLower(name)
	return util.ContainsStr(excludeNetInterfaces, lower)
}

func isInterfaceMonitored(name string) bool {
	if agentConfig != nil && len(agentConfig.NICAllowlist) > 0 {
		return agentConfig.NICAllowlist[name]
	}
	return !isNetInterfaceExcluded(name)
}

// TrackNetworkSpeed NIC监控，统计流量与速度
func TrackNetworkSpeed() {
	nc, err := net.IOCounters(true)
	if err != nil {
		return
	}

	now := time.Now()
	var deltaIn, deltaOut uint64
	currentCounters := make(map[string]net.IOCountersStat, len(nc))

	// 首帧初始化：首次运行建立各网卡快照基线，避免开机历史流量产生异常增量
	if lastUpdateNetStats.IsZero() {
		var initialIn, initialOut uint64
		for _, v := range nc {
			if !isInterfaceMonitored(v.Name) {
				continue
			}
			currentCounters[v.Name] = v
			initialIn = saturatingAddUint64(initialIn, v.BytesRecv)
			initialOut = saturatingAddUint64(initialOut, v.BytesSent)
		}
		cachedNetIOCounters = currentCounters
		netInTransfer = initialIn
		netOutTransfer = initialOut
		netInSpeed = 0
		netOutSpeed = 0
		lastUpdateNetStats = now
		return
	}

	for _, v := range nc {
		if !isInterfaceMonitored(v.Name) {
			continue
		}
		currentCounters[v.Name] = v

		if lastStat, exists := cachedNetIOCounters[v.Name]; exists {
			// 仅对已建立基线的网卡计算增量
			if v.BytesRecv >= lastStat.BytesRecv {
				deltaIn = saturatingAddUint64(deltaIn, v.BytesRecv-lastStat.BytesRecv)
			} else {
				// 网卡计数器发生重置（如网卡重载/重启）
				deltaIn = saturatingAddUint64(deltaIn, v.BytesRecv)
			}

			if v.BytesSent >= lastStat.BytesSent {
				deltaOut = saturatingAddUint64(deltaOut, v.BytesSent-lastStat.BytesSent)
			} else {
				deltaOut = saturatingAddUint64(deltaOut, v.BytesSent)
			}
		}
		// 运行期间新增的网卡：仅建立初始快照基线，不把历史累计值作为瞬时增量算入，防止瞬间网速脉冲和虚高总量
	}

	cachedNetIOCounters = currentCounters

	elapsed := now.Sub(lastUpdateNetStats)
	netInSpeed = networkSpeedDelta(deltaIn, 0, elapsed)
	netOutSpeed = networkSpeedDelta(deltaOut, 0, elapsed)

	netInTransfer = saturatingAddUint64(netInTransfer, deltaIn)
	netOutTransfer = saturatingAddUint64(netOutTransfer, deltaOut)
	lastUpdateNetStats = now
}

func networkSpeedDelta(current, previous uint64, elapsed time.Duration) uint64 {
	if elapsed <= 0 || current < previous {
		return 0
	}
	delta := current - previous
	speed := float64(delta) / elapsed.Seconds()
	if speed >= float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(speed)
}

func saturatingAddUint64(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

func getDiskTotalAndUsed() (total uint64, used uint64) {
	devices := make(map[string]string)

	if len(agentConfig.HardDrivePartitionAllowlist) > 0 {
		// 如果配置了白名单，使用白名单的列表
		for i, v := range agentConfig.HardDrivePartitionAllowlist {
			devices[strconv.Itoa(i)] = v
		}
	} else {
		// 检查缓存是否过期（10分钟更新一次分区列表）
		if cachedDiskDevices != nil && time.Since(cachedDiskDevicesTime) < 10*time.Minute {
			devices = cachedDiskDevices
		} else {
			// 否则使用默认过滤规则
			diskList, _ := disk.Partitions(false)
			for _, d := range diskList {
				fsType := strings.ToLower(d.Fstype)
				// 不统计 K8s 的虚拟挂载点：https://github.com/shirou/gopsutil/issues/1007
				if devices[d.Device] == "" && util.ContainsStr(expectDiskFsTypes, fsType) && !strings.Contains(d.Mountpoint, "/var/lib/kubelet") {
					devices[d.Device] = d.Mountpoint
				}
			}
			// 更新缓存
			cachedDiskDevices = devices
			cachedDiskDevicesTime = time.Now()
		}
	}

	for _, mountPath := range devices {
		diskUsageOf, err := disk.Usage(mountPath)
		if err == nil {
			total += diskUsageOf.Total
			used += diskUsageOf.Used
		}
	}

	// Fallback 到这个方法,仅统计根路径,适用于OpenVZ之类的.
	if runtime.GOOS == "linux" && total == 0 && used == 0 {
		cmd := exec.Command("df")
		out, err := cmd.CombinedOutput()
		if err == nil {
			s := strings.Split(string(out), "\n")
			for _, c := range s {
				info := strings.Fields(c)
				if len(info) == 6 {
					if info[5] == "/" {
						total, _ = strconv.ParseUint(info[1], 0, 64)
						used, _ = strconv.ParseUint(info[2], 0, 64)
						// 默认获取的是1K块为单位的.
						total = total * 1024
						used = used * 1024
					}
				}
			}
		}
	}

	return
}

func getConns(skipConnectionCount bool) (tcpConnCount, udpConnCount uint64) {
	if !skipConnectionCount {
		ssErr := true
		if runtime.GOOS == "linux" {
			tcpStat, errTCP := goss.ConnectionsWithProtocol(goss.AF_INET, syscall.IPPROTO_TCP)
			udpStat, errUDP := goss.ConnectionsWithProtocol(goss.AF_INET, syscall.IPPROTO_UDP)
			if errTCP == nil && errUDP == nil {
				ssErr = false
				tcpConnCount = uint64(len(tcpStat))
				udpConnCount = uint64(len(udpStat))
			}
			if strings.Contains(CachedIP, ":") {
				tcpStat6, errTCP := goss.ConnectionsWithProtocol(goss.AF_INET6, syscall.IPPROTO_TCP)
				udpStat6, errUDP := goss.ConnectionsWithProtocol(goss.AF_INET6, syscall.IPPROTO_UDP)
				if errTCP == nil && errUDP == nil {
					ssErr = false
					tcpConnCount += uint64(len(tcpStat6))
					udpConnCount += uint64(len(udpStat6))
				}
			}
		}
		if ssErr {
			conns, _ := net.Connections("all")
			for i := 0; i < len(conns); i++ {
				switch conns[i].Type {
				case syscall.SOCK_STREAM:
					tcpConnCount++
				case syscall.SOCK_DGRAM:
					udpConnCount++
				}
			}
		}
	}
	return tcpConnCount, udpConnCount
}

func updateGPUStat() float64 {
	if agentConfig.GPU {
		if statDataFetchAttempts["GPU"] < maxDeviceDataFetchAttempts {
			gs, err := gpustat.GetGPUStat()
			if err != nil {
				statDataFetchAttempts["GPU"]++
				util.Printf(agentConfig.Debug, "gpustat.GetGPUStat error: %v, attempt: %d", err, statDataFetchAttempts["GPU"])
				return 0
			} else {
				statDataFetchAttempts["GPU"] = 0
				return gs
			}
		}
	}
	return 0
}

func updateTemperatureStat(debug bool) {
	if !updatingTemperature.CompareAndSwap(false, true) {
		return
	}
	defer updatingTemperature.Store(false)
	if time.Now().Before(temperatureRetryAt) {
		return
	}

	temperatures, err := readTemperatures()
	if len(temperatures) == 0 {
		temperatureRetryAt = time.Now().Add(temperatureRetryInterval)
		if err != nil {
			util.Printf(debug, "温度采集失败: %v", err)
			return
		}
		util.Println(debug, "未发现可读的温度传感器")
	} else {
		temperatureRetryAt = time.Time{}
	}

	sort.SliceStable(temperatures, func(i, j int) bool {
		return temperatures[i].Name < temperatures[j].Name
	})
	temperatureStat.Store(&temperatures)
}

func readTemperatures() ([]model.SensorTemperature, error) {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		root := os.Getenv("HOST_SYS")
		if root == "" {
			root = "/sys"
		}
		return readSysfsTemperatures(root)
	}

	readings, err := sensors.SensorsTemperatures()
	var temperatures []model.SensorTemperature
	for _, reading := range readings {
		// Some backends, including macOS SMC, return zero for unavailable sensors.
		if reading.Temperature > 0 && validTemperature(reading.SensorKey, reading.Temperature) {
			temperatures = append(temperatures, model.SensorTemperature{
				Name:        reading.SensorKey,
				Temperature: reading.Temperature,
			})
		}
	}
	return temperatures, err
}

func validTemperature(name string, celsius float64) bool {
	return name != "" && !util.ContainsStr(sensorIgnoreList, name) && celsius >= -273.15 && !math.IsInf(celsius, 0)
}

func readSysfsTemperatures(root string) ([]model.SensorTemperature, error) {
	sys := os.DirFS(root)
	var readErr error
	read := func(file, name string, scale float64) (model.SensorTemperature, bool) {
		value, err := readSysfsTemperature(sys, file, scale)
		if err != nil {
			if readErr == nil {
				readErr = err
			}
			return model.SensorTemperature{}, false
		}
		// U30 Air exposes a zero placeholder for the charging interface.
		if (name == "interface" && value == 0) || !validTemperature(name, value) {
			return model.SensorTemperature{}, false
		}
		return model.SensorTemperature{Name: name, Temperature: value}, true
	}

	var temperatures []model.SensorTemperature
	seenInputs := make(map[string]bool)
	thermalMirrors := make(map[string]int)
	for _, pattern := range []string{"class/hwmon/hwmon*/temp*_input", "class/hwmon/hwmon*/device/temp*_input"} {
		files, _ := fs.Glob(sys, pattern)
		for _, file := range files {
			resolved, resolveErr := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(file)))
			if resolveErr == nil && seenInputs[resolved] {
				continue
			}

			dir := path.Dir(file)
			hwmon := dir
			if path.Base(dir) == "device" {
				hwmon = path.Dir(dir)
			}
			chip := readTrimmedFile(sys, path.Join(dir, "name"))
			if chip == "" && dir != hwmon {
				chip = readTrimmedFile(sys, path.Join(hwmon, "name"))
			}
			if chip == "" {
				chip = path.Base(hwmon)
			}
			label := readTrimmedFile(sys, strings.TrimSuffix(file, "_input")+"_label")
			name := chip
			if label != "" {
				name += "_" + strings.ReplaceAll(strings.ToLower(label), " ", "_")
			}
			reading, ok := read(file, name, 1000)
			if !ok {
				continue
			}
			if resolveErr == nil {
				seenInputs[resolved] = true
			}
			temperatures = append(temperatures, reading)
			device, _ := os.Readlink(filepath.Join(root, filepath.FromSlash(hwmon), "device"))
			if strings.HasPrefix(filepath.Base(device), "thermal_zone") {
				thermalMirrors[strings.ReplaceAll(chip, "-", "_")]++
			}
		}
	}

	zones, _ := fs.Glob(sys, "class/thermal/thermal_zone*/temp")
	var zoneTemperatures []model.SensorTemperature
	zoneCounts := make(map[string]int)
	for _, file := range zones {
		dir := path.Dir(file)
		name := readTrimmedFile(sys, path.Join(dir, "type"))
		if name == "" {
			name = path.Base(dir)
		}
		zoneCounts[strings.ReplaceAll(name, "-", "_")]++
		if reading, ok := read(file, name, 1000); ok {
			zoneTemperatures = append(zoneTemperatures, reading)
		}
	}
	for _, reading := range zoneTemperatures {
		// The kernel can export a group of thermal zones under one hwmon name.
		// Keep the thermal readings if hwmon did not cover the whole group.
		chip := strings.ReplaceAll(reading.Name, "-", "_")
		if thermalMirrors[chip] < zoneCounts[chip] {
			temperatures = append(temperatures, reading)
		}
	}

	supplies, _ := fs.Glob(sys, "class/power_supply/*/temp")
	for _, file := range supplies {
		dir := path.Dir(file)
		if readTrimmedFile(sys, path.Join(dir, "present")) == "0" {
			continue
		}
		if reading, ok := read(file, path.Base(dir), 10); ok {
			temperatures = append(temperatures, reading)
		}
	}
	return temperatures, readErr
}

func readTrimmedFile(sys fs.FS, file string) string {
	data, _ := fs.ReadFile(sys, file)
	return strings.TrimSpace(string(data))
}

func readSysfsTemperature(sys fs.FS, file string, scale float64) (float64, error) {
	data, err := fs.ReadFile(sys, file)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", file, err)
	}
	return value / scale, nil
}

func detectVirtualization(info *host.InfoStat) string {
	var guest string
	if info != nil && info.VirtualizationRole == "guest" {
		guest = virtualizationName(info.VirtualizationSystem)
	}

	switch runtime.GOOS {
	case "linux", "android":
		root, proc, sys := os.Getenv("HOST_ROOT"), os.Getenv("HOST_PROC"), os.Getenv("HOST_SYS")
		var detected string
		if runtime.GOOS == "linux" && root == "" && proc == "" && sys == "" {
			detected = virtualizationName(virtualizationCommand("systemd-detect-virt"))
		}
		return detectLinuxVirtualization(
			os.DirFS(cmp.Or(root, "/")), os.DirFS(cmp.Or(proc, "/proc")),
			os.DirFS(cmp.Or(sys, "/sys")), detected, guest,
		)
	case "windows":
		const bios = `HKLM\HARDWARE\DESCRIPTION\System\BIOS`
		values := virtualizationCommand("reg.exe", "query", bios)
		vendor, product, firmware := windowsVirtualizationDMI(values)
		return cmp.Or(detectVirtualMachine(vendor, product, firmware), guest)
	case "freebsd":
		if virtualizationCommand("sysctl", "-n", "security.jail.jailed") == "1" {
			return "FreeBSD Jail"
		}
		return cmp.Or(virtualizationName(virtualizationCommand("sysctl", "-n", "kern.vm_guest")), guest)
	case "darwin":
		product := virtualizationCommand("sysctl", "-n", "hw.model")
		return cmp.Or(detectVirtualMachine("", product, ""), guest)
	}
	return guest
}

func virtualizationCommand(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func detectLinuxVirtualization(root, proc, sys fs.FS, detected, guest string) string {
	if container := detectLinuxContainer(root, proc); container != "" {
		if container == "Container" && isContainerVirtualization(detected) {
			return detected
		}
		return container
	}
	if detected != "" && detected != "Virtual Machine" {
		return detected
	}

	if _, err := fs.Stat(proc, "vz"); err == nil {
		// OpenVZ exposes the beancounters directory on the host.
		if _, err := fs.Stat(proc, "bc"); os.IsNotExist(err) {
			return "OpenVZ"
		}
	}

	const dmi = "class/dmi/id/"
	vendor := readTrimmedFile(sys, dmi+"sys_vendor")
	product := readTrimmedFile(sys, dmi+"product_name")
	if strings.EqualFold(vendor, "Amazon EC2") && strings.Contains(strings.ToLower(product), ".metal") {
		return ""
	}
	xenType := readTrimmedFile(sys, "hypervisor/type")
	xenHost := strings.Contains(readTrimmedFile(proc, "xen/capabilities"), "control_d")
	if xenType == "xen" {
		const xenFeatureDom0 = 1 << 11
		features, _ := strconv.ParseUint(readTrimmedFile(sys, "hypervisor/properties/features"), 16, 32)
		xenHost = xenHost || features&xenFeatureDom0 != 0
		if !xenHost {
			return "Xen"
		}
	}
	machine := detectVirtualMachine(vendor, product, readTrimmedFile(sys, dmi+"bios_vendor"))
	clocksource := readTrimmedFile(sys, "devices/system/clocksource/clocksource0/current_clocksource")
	if machine == "QEMU" && clocksource == "kvm-clock" {
		return "KVM"
	}
	if machine != "" && (machine != "Xen" || !xenHost) {
		return machine
	}
	if xenHost {
		return ""
	}

	switch clocksource {
	case "kvm-clock":
		return "KVM"
	case "hyperv_clocksource_tsc_page", "hyperv_clocksource_msr":
		return "Hyper-V"
	case "xen":
		return "Xen"
	}

	// Prefer an identified guest over the generic x86 hypervisor flag.
	if guest != "" && !isContainerVirtualization(guest) {
		return guest
	}
	for line := range strings.SplitSeq(readTrimmedFile(proc, "cpuinfo"), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "model name":
			if model := detectVirtualMachine("", strings.TrimSpace(value), ""); model != "" {
				return model
			}
		case "flags":
			for _, flag := range strings.Fields(value) {
				if flag == "hypervisor" {
					detected = "Virtual Machine"
					break
				}
			}
		}
	}
	return detected
}

func detectLinuxContainer(root, proc fs.FS) string {
	var genericContainer string
	if container := virtualizationName(readTrimmedFile(root, "run/systemd/container")); isContainerVirtualization(container) {
		if container == "Container" {
			genericContainer = container
		} else {
			return container
		}
	}
	if _, err := fs.Stat(root, "run/.containerenv"); err == nil {
		return "Podman"
	}
	if _, err := fs.Stat(root, ".dockerenv"); err == nil {
		return "Docker"
	}
	for entry := range strings.SplitSeq(readTrimmedFile(proc, "1/environ"), "\x00") {
		if id, ok := strings.CutPrefix(entry, "container="); ok {
			container := virtualizationName(id)
			if container == "Container" {
				genericContainer = container
			} else if isContainerVirtualization(container) {
				return container
			}
		}
	}
	for _, file := range []string{"self/cgroup", "1/cgroup"} {
		container := detectCgroupContainer(readTrimmedFile(proc, file))
		if container != "" && container != "Container" {
			return container
		}
		genericContainer = cmp.Or(genericContainer, container)
	}
	if genericContainer != "" {
		return genericContainer
	}
	release := strings.ToLower(readTrimmedFile(proc, "sys/kernel/osrelease"))
	if strings.Contains(release, "-microsoft-standard") || strings.HasSuffix(release, "-microsoft") {
		return "WSL"
	}
	return ""
}

func isContainerVirtualization(name string) bool {
	switch name {
	case "Docker", "Podman", "LXC", "OpenVZ", "WSL", "CRI-O", "Container", "containerd", "systemd-nspawn", "rkt", "proot", "pouch":
		return true
	}
	return false
}

func detectCgroupContainer(groups string) string {
	var genericContainer string
	for line := range strings.SplitSeq(groups, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		parts := strings.Split(fields[2], "/")
		// Match workload scopes and paths, where the runtime may be nested.
		for i := len(parts) - 1; i > 0; i-- {
			segment, parent := parts[i], parts[i-1]
			switch {
			case containerScope(segment, "libpod-"):
				return "Podman"
			case parent == "docker" && isContainerID(segment), containerScope(segment, "docker-"):
				return "Docker"
			case containerScope(segment, "cri-containerd-"):
				return "containerd"
			case containerScope(segment, "crio-"):
				return "CRI-O"
			case parent == "lxc" && segment != "", strings.HasPrefix(segment, "lxc.payload."),
				strings.HasSuffix(segment, ".scope") && strings.HasPrefix(segment, `machine-lxc\x2d`):
				return "LXC"
			case strings.HasSuffix(segment, ".scope") && strings.HasPrefix(segment, `machine-rkt\x2d`):
				return "rkt"
			case segment == "kubepods" || segment == "kubepods.slice":
				genericContainer = "Container"
			}
		}
	}
	return genericContainer
}

func containerScope(segment, prefix string) bool {
	id, found := strings.CutPrefix(segment, prefix)
	if !found {
		return false
	}
	id, found = strings.CutSuffix(id, ".scope")
	return found && isContainerID(id)
}

func isContainerID(id string) bool {
	return (len(id) == 12 || len(id) == 64) && strings.Trim(id, "0123456789abcdef") == ""
}

func windowsVirtualizationDMI(registry string) (vendor, product, firmware string) {
	for line := range strings.SplitSeq(registry, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "REG_SZ" {
			continue
		}
		value := strings.Join(fields[2:], " ")
		switch fields[0] {
		case "SystemManufacturer":
			vendor = value
		case "SystemProductName":
			product = value
		case "BIOSVendor":
			firmware = value
		}
	}
	return vendor, product, firmware
}

func detectVirtualMachine(vendor, product, firmware string) string {
	identifiers := strings.ToLower(vendor + "\n" + product + "\n" + firmware)
	switch {
	case strings.Contains(identifiers, "virtualbox"), strings.Contains(identifiers, "innotek"):
		return "VirtualBox"
	case strings.Contains(identifiers, "vmware"):
		return "VMware"
	case strings.Contains(identifiers, "parallels"):
		return "Parallels"
	case strings.EqualFold(vendor, "Microsoft Corporation") && strings.EqualFold(product, "Virtual Machine"):
		return "Hyper-V"
	case strings.EqualFold(vendor, "Amazon EC2") && product != "" && !strings.Contains(strings.ToLower(product), ".metal"):
		return "Amazon EC2"
	case strings.Contains(identifiers, "domu"), strings.EqualFold(vendor, "Xen"), strings.EqualFold(product, "Xen"):
		return "Xen"
	case strings.Contains(identifiers, "bhyve"):
		return "bhyve"
	case strings.HasPrefix(strings.ToLower(product), "virtualmac"),
		strings.EqualFold(product, "Apple Virtualization Generic Platform"):
		return "Apple Virtualization"
	case strings.Contains(identifiers, "kvm"):
		return "KVM"
	case strings.Contains(identifiers, "qemu"):
		return "QEMU"
	}
	return ""
}

func virtualizationName(id string) string {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "kvm":
		return "KVM"
	case "qemu":
		return "QEMU"
	case "vmware":
		return "VMware"
	case "vmware-esxi":
		return "VMware ESXi"
	case "microsoft", "hyperv", "hyper-v":
		return "Hyper-V"
	case "oracle", "vbox", "virtualbox":
		return "VirtualBox"
	case "amazon":
		return "Amazon EC2"
	case "google":
		return "Google Compute Engine"
	case "xen":
		return "Xen"
	case "parallels":
		return "Parallels"
	case "apple":
		return "Apple Virtualization"
	case "powervm":
		return "PowerVM"
	case "zvm", "z/vm":
		return "z/VM"
	case "docker":
		return "Docker"
	case "podman":
		return "Podman"
	case "lxc", "lxc-libvirt":
		return "LXC"
	case "openvz":
		return "OpenVZ"
	case "wsl":
		return "WSL"
	case "crio", "cri-o":
		return "CRI-O"
	case "linux-vserver":
		return "VServer"
	case "jail":
		return "FreeBSD Jail"
	case "vm-other", "guest", "generic":
		return "Virtual Machine"
	case "container-other":
		return "Container"
	case "bhyve", "systemd-nspawn", "containerd", "rkt", "proot", "pouch", "bochs", "uml", "qnx", "acrn", "sre", "zone":
		return strings.ToLower(strings.TrimSpace(id))
	}
	return ""
}
