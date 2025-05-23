package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blang/semver"
	"github.com/nezhahq/go-github-selfupdate/selfupdate"
	"github.com/nezhahq/service"
	ping "github.com/prometheus-community/pro-bing"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"

	"github.com/xos/serveragent/model"
	fm "github.com/xos/serveragent/pkg/fm"
	"github.com/xos/serveragent/pkg/monitor"
	"github.com/xos/serveragent/pkg/processgroup"
	"github.com/xos/serveragent/pkg/pty"
	"github.com/xos/serveragent/pkg/util"
	utlsx "github.com/xos/serveragent/pkg/utls"
	pb "github.com/xos/serveragent/proto"
)

// Agent 运行时参数。如需添加新参数，记得同时在 service.go 中添加
type AgentCliParam struct {
	SkipConnectionCount   bool   // 跳过连接数检查
	SkipProcsCount        bool   // 跳过进程数量检查
	DisableAutoUpdate     bool   // 关闭自动更新
	DisableForceUpdate    bool   // 关闭强制更新
	DisableCommandExecute bool   // 关闭命令执行
	Server                string // 服务器地址
	ClientSecret          string // 客户端密钥
	ReportDelay           int    // 报告间隔
	TLS                   bool   // 是否使用TLS加密传输至服务端
	InsecureTLS           bool   // 是否禁用证书检查
	Version               bool   // 当前版本号
	IPReportPeriod        uint32 // 上报IP间隔
	UseIPv6CountryCode    bool   // 默认优先展示IPv6旗帜
	UseGiteeToUpgrade     bool   // 强制从Gitee获取更新
	DisableNat            bool   // 关闭内网穿透
	DisableSendQuery      bool   // 关闭发送TCP/ICMP/HTTP请求
}

var (
	version     string
	arch        string
	client      pb.ServerServiceClient
	initialized bool
	dnsResolver = &net.Resolver{PreferGo: true}
)

var agentCmd = &cobra.Command{
	Use: "agent",
	Run: func(cmd *cobra.Command, args []string) {
		runService("", nil)
	},
	PreRun:           preRun,
	PersistentPreRun: persistPreRun,
}

var (
	agentCliParam AgentCliParam
	agentConfig   model.AgentConfig
	debugLogger   *util.DebugLogger
	httpClient    = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Second * 30,
	}
	httpClient3 = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout:   time.Second * 30,
		Transport: &http3.RoundTripper{},
	}

	hostStatus = new(atomic.Bool)
)

const (
	delayWhenError = time.Second * 10 // Agent 重连间隔
	networkTimeOut = time.Second * 5  // 普通网络超时
)

func init() {
	resolver.SetDefaultScheme("passthrough")
	net.DefaultResolver.PreferGo = true // 使用 Go 内置的 DNS 解析器解析域名
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Second * 5,
		}
		dnsServers := util.DNSServersAll
		if len(agentConfig.DNS) > 0 {
			dnsServers = agentConfig.DNS
		}
		index := int(time.Now().Unix()) % int(len(dnsServers))
		queue := generateQueue(index, len(dnsServers))
		var conn net.Conn
		var err error
		for i := 0; i < len(queue); i++ {
			conn, err = d.DialContext(ctx, "udp", dnsServers[queue[i]])
			if err == nil {
				return conn, nil
			}
		}
		return nil, err
	}

	headers := util.BrowserHeaders()
	http.DefaultClient.Timeout = time.Second * 30
	httpClient.Transport = utlsx.NewUTLSHTTPRoundTripperWithProxy(
		utls.HelloChrome_Auto, new(utls.Config),
		http.DefaultTransport, nil, &headers,
	)

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	// 初始化运行参数
	agentCmd.PersistentFlags().StringVarP(&agentCliParam.Server, "server", "s", "localhost:2222", "管理面板RPC端口")
	agentCmd.PersistentFlags().StringVarP(&agentCliParam.ClientSecret, "password", "p", "", "Agent连接Secret")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.TLS, "tls", false, "启用SSL/TLS加密")
	agentCmd.PersistentFlags().BoolVarP(&agentCliParam.InsecureTLS, "insecure", "k", false, "禁用证书检查")
	agentCmd.PersistentFlags().BoolVarP(&agentConfig.Debug, "debug", "d", true, "开启调试信息")
	agentCmd.PersistentFlags().IntVar(&agentCliParam.ReportDelay, "report-delay", 1, "系统状态上报间隔")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.SkipConnectionCount, "skip-conn", false, "不监控连接数")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.SkipProcsCount, "skip-procs", false, "不监控进程数")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.DisableCommandExecute, "disable-command-execute", false, "禁止在此机器上执行命令")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.DisableNat, "disable-nat", false, "禁止此机器内网穿透")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.DisableSendQuery, "disable-send-query", false, "禁止此机器发送TCP/ICMP/HTTP请求")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.DisableAutoUpdate, "disable-auto-update", false, "禁用自动升级")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.DisableForceUpdate, "disable-force-update", false, "禁用强制升级")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.UseIPv6CountryCode, "use-ipv6-countrycode", false, "使用IPv6的位置上报")
	agentCmd.PersistentFlags().BoolVar(&agentConfig.GPU, "gpu", false, "启用GPU监控")
	agentCmd.PersistentFlags().BoolVar(&agentConfig.Temperature, "temperature", false, "启用温度监控")
	agentCmd.PersistentFlags().BoolVar(&agentCliParam.UseGiteeToUpgrade, "gitee", false, "使用Gitee获取更新")
	agentCmd.PersistentFlags().Uint32VarP(&agentCliParam.IPReportPeriod, "ip-report-period", "u", 30*60, "本地IP更新间隔, 上报频率依旧取决于report-delay的值")
	agentCmd.Flags().BoolVarP(&agentCliParam.Version, "version", "v", false, "查看当前版本号")

	agentConfig.Read(filepath.Dir(ex) + "/config.yml")

	monitor.InitConfig(&agentConfig)
}

func main() {
	if err := agentCmd.Execute(); err != nil {
		println(err)
		os.Exit(1)
	}
}

func persistPreRun(cmd *cobra.Command, args []string) {
	// windows环境处理
	if runtime.GOOS == "windows" {
		hostArch, err := host.KernelArch()
		if err != nil {
			panic(err)
		}
		if hostArch == "i386" {
			hostArch = "386"
		}
		if hostArch == "i686" || hostArch == "ia64" || hostArch == "x86_64" {
			hostArch = "amd64"
		}
		if hostArch == "aarch64" {
			hostArch = "arm64"
		}
		if arch != hostArch {
			panic(fmt.Sprintf("与当前系统不匹配，当前运行 %s_%s, 需要下载 %s_%s", runtime.GOOS, arch, runtime.GOOS, hostArch))
		}
	}
}

func preRun(cmd *cobra.Command, args []string) {
	// 来自于 GoReleaser 的版本号
	monitor.Version = version

	if agentCliParam.Version {
		fmt.Println(version)
		os.Exit(0)
	}

	if agentCliParam.ClientSecret == "" {
		cmd.Help()
		os.Exit(1)
	}

	if agentCliParam.ReportDelay < 1 || agentCliParam.ReportDelay > 4 {
		println("report-delay 的区间为 1-4")
		os.Exit(1)
	}

	// 初始化debug logger
	debugLogger = util.NewDebugLogger(agentConfig.Debug)
}

func run() {
	auth := model.AuthHandler{
		ClientSecret: agentCliParam.ClientSecret,
	}

	// 下载远程命令执行需要的终端
	if !agentCliParam.DisableCommandExecute {
		go func() {
			if err := pty.DownloadDependency(); err != nil {
				debugLogger.Printf("pty 下载依赖失败: %v", err)
			}
		}()
	}
	// 上报服务器信息
	go reportStateDaemon()
	// 更新IP信息
	go monitor.UpdateIP(agentCliParam.UseIPv6CountryCode, agentCliParam.IPReportPeriod)

	// 定时检查更新
	if _, err := semver.Parse(version); err == nil && !agentCliParam.DisableAutoUpdate {
		doSelfUpdate(true)
		go func() {
			for range time.Tick(20 * time.Minute) {
				doSelfUpdate(true)
			}
		}()
	}

	var err error
	var conn *grpc.ClientConn

	retry := func() {
		initialized = false
		debugLogger.Println("Error to close connection ...")
		if conn != nil {
			conn.Close()
		}
		time.Sleep(delayWhenError)
		debugLogger.Println("Try to reconnect ...")
	}

	for {
		timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
		var securityOption grpc.DialOption
		if agentCliParam.TLS {
			if agentCliParam.InsecureTLS {
				securityOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}))
			} else {
				securityOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
			}
		} else {
			securityOption = grpc.WithTransportCredentials(insecure.NewCredentials())
		}
		conn, err = grpc.DialContext(timeOutCtx, agentCliParam.Server, securityOption, grpc.WithPerRPCCredentials(&auth))
		if err != nil {
			debugLogger.Printf("与面板建立连接失败: %v", err)
			cancel()
			retry()
			continue
		}
		cancel()
		client = pb.NewServerServiceClient(conn)
		// 第一步注册
		timeOutCtx, cancel = context.WithTimeout(context.Background(), networkTimeOut)
		_, err = client.ReportSystemInfo(timeOutCtx, monitor.GetHost().PB())
		if err != nil {
			debugLogger.Printf("上报系统信息失败: %v", err)
			cancel()
			retry()
			continue
		}
		cancel()
		initialized = true
		// 执行 Task
		tasks, err := client.RequestTask(context.Background(), monitor.GetHost().PB())
		if err != nil {
			debugLogger.Printf("请求任务失败: %v", err)
			retry()
			continue
		}
		err = receiveTasks(tasks)
		debugLogger.Printf("receiveTasks exit to main: %v", err)
		retry()
	}
}

func runService(action string, flags []string) {
	dir, err := os.Getwd()
	if err != nil {
		debugLogger.Printf("获取当前工作目录时出错: %v", err)
		return
	}

	winConfig := map[string]interface{}{
		"OnFailure": "restart",
	}

	svcConfig := &service.Config{
		Name:             "server-agent",
		DisplayName:      "Server Agent",
		Description:      "服务器探针监控端",
		Arguments:        flags,
		WorkingDirectory: dir,
		Option:           winConfig,
	}

	prg := &program{
		exit: make(chan struct{}),
	}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		debugLogger.Printf("创建服务时出错，以普通模式运行: %v", err)
		run()
		return
	}
	prg.service = s

	if agentConfig.Debug {
		serviceLogger, err := s.Logger(nil)
		if err != nil {
			debugLogger.Printf("获取 service logger 时出错: %+v", err)
		} else {
			util.Logger = serviceLogger
		}
	}

	if action == "install" {
		initName := s.Platform()
		debugLogger.Println("Init system is:", initName)
	}

	if len(action) != 0 {
		err := service.Control(s, action)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	err = s.Run()
	if err != nil {
		util.Logger.Error(err)
	}
}

func receiveTasks(tasks pb.ServerService_RequestTaskClient) error {
	var err error
	defer debugLogger.Printf("receiveTasks exit %v => %v", time.Now(), err)
	for {
		var task *pb.Task
		task, err = tasks.Recv()
		if err != nil {
			return err
		}
		go func() {
			defer func() {
				if err := recover(); err != nil {
					debugLogger.Println("task panic", task, err)
				}
			}()
			doTask(task)
		}()
	}
}

func doTask(task *pb.Task) {
	var result pb.TaskResult
	result.Id = task.GetId()
	result.Type = task.GetType()
	switch task.GetType() {
	case model.TaskTypeICMPPing:
		handleIcmpPingTask(task, &result)
	case model.TaskTypeTCPPing:
		handleTcpPingTask(task, &result)
	case model.TaskTypeCommand:
		handleCommandTask(task, &result)
	case model.TaskTypeUpgrade:
		handleUpgradeTask(task, &result)
	case model.TaskTypeTerminalGRPC:
		handleTerminalTask(task)
		return
	case model.TaskTypeNAT:
		handleNATTask(task)
		return
	case model.TaskTypeReportHostInfo:
		reportState(time.Time{})
		return
	case model.TaskTypeFM:
		handleFMTask(task)
		return
	case model.TaskTypeKeepalive:
		return
	default:
		debugLogger.Printf("不支持的任务: %v", task)
		return
	}
	client.ReportTask(context.Background(), &result)
}

// reportStateDaemon 向server上报状态信息
func reportStateDaemon() {
	var lastReportHostInfo time.Time
	var err error
	defer debugLogger.Printf("reportState exit %v => %v", time.Now(), err)
	for {
		// 为了更准确的记录时段流量，inited 后再上传状态信息
		lastReportHostInfo = reportState(lastReportHostInfo)
		time.Sleep(time.Second * time.Duration(agentCliParam.ReportDelay))
	}
}

func reportState(lastReportHostInfo time.Time) time.Time {
	if client != nil && initialized {
		monitor.TrackNetworkSpeed()
		timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
		_, err := client.ReportSystemState(timeOutCtx, monitor.GetState(agentCliParam.SkipConnectionCount, agentCliParam.SkipProcsCount).PB())
		cancel()
		if err != nil {
			debugLogger.Printf("reportState error: %v", err)
			time.Sleep(delayWhenError)
		}
		// 每10分钟重新获取一次硬件信息
		if lastReportHostInfo.Before(time.Now().Add(-10 * time.Minute)) {
			if reportHost() {
				lastReportHostInfo = time.Now()
			}
		}
	}
	return lastReportHostInfo
}

func reportHost() bool {
	if !hostStatus.CompareAndSwap(false, true) {
		return false
	}
	defer hostStatus.Store(false)

	if client != nil && initialized {
		client.ReportSystemInfo(context.Background(), monitor.GetHost().PB())
		if monitor.GeoQueryIP != "" {
			geoip, err := client.LookupGeoIP(context.Background(), &pb.GeoIP{Ip: monitor.GeoQueryIP})
			if err == nil {
				monitor.CachedCountryCode = geoip.GetCountryCode()
			}
		}
	}

	return true
}

// doSelfUpdate 执行更新检查 如果更新成功则会结束进程
func doSelfUpdate(useLocalVersion bool) {
	v := semver.MustParse("0.4.24")
	if useLocalVersion {
		v = semver.MustParse(version)
	}
	debugLogger.Printf("检查更新: %v", v)
	var latest *selfupdate.Release
	var err error
	if monitor.CachedCountryCode != "cn" && !agentCliParam.UseGiteeToUpgrade {
		latest, err = selfupdate.UpdateSelf(v, "xOS/ServerAgent")
	} else {
		latest, err = selfupdate.UpdateSelfGitee(v, "Ten/ServerAgent")
	}
	if err != nil {
		debugLogger.Printf("更新失败: %v", err)
		return
	}

	// 添加调试信息
	debugLogger.Printf("当前版本: %v, 最新版本: %v", v, latest.Version)

	if !latest.Version.Equals(v) {
		debugLogger.Printf("已经更新至: %v, 正在结束进程", latest.Version)
		os.Exit(1)
	}
}

func handleUpgradeTask(*pb.Task, *pb.TaskResult) {
	if agentCliParam.DisableForceUpdate {
		return
	}
	doSelfUpdate(false)
}

func handleTcpPingTask(task *pb.Task, result *pb.TaskResult) {
	if agentCliParam.DisableSendQuery {
		result.Data = "此 Agent 已禁止发送请求"
		return
	}

	host, port, err := net.SplitHostPort(task.GetData())
	if err != nil {
		result.Data = err.Error()
		return
	}
	ipAddr, err := lookupIP(host)
	if err != nil {
		result.Data = err.Error()
		return
	}
	if strings.Contains(ipAddr, ":") {
		ipAddr = fmt.Sprintf("[%s]", ipAddr)
	}
	debugLogger.Printf("TCP-Ping Task: Pinging %s:%s", ipAddr, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", ipAddr, port), time.Second*10)
	if err != nil {
		result.Data = err.Error()
	} else {
		conn.Close()
		result.Delay = float32(time.Since(start).Microseconds()) / 1000.0
		result.Successful = true
	}
}

func handleIcmpPingTask(task *pb.Task, result *pb.TaskResult) {
	if agentCliParam.DisableSendQuery {
		result.Data = "此 Agent 已禁止发送请求"
		return
	}

	ipAddr, err := lookupIP(task.GetData())
	if err != nil {
		result.Data = err.Error()
		return
	}
	debugLogger.Printf("ICMP-Ping Task: Pinging %s", ipAddr)
	pinger, err := ping.NewPinger(ipAddr)
	if err == nil {
		pinger.SetPrivileged(true)
		pinger.Count = 5
		pinger.Timeout = time.Second * 20
		err = pinger.Run() // Blocks until finished.
	}
	if err == nil {
		stat := pinger.Statistics()
		if stat.PacketsRecv == 0 {
			result.Data = "pockets recv 0"
			return
		}
		result.Delay = float32(stat.AvgRtt.Microseconds()) / 1000.0
		result.Successful = true
	} else {
		result.Data = err.Error()
	}
}

func handleCommandTask(task *pb.Task, result *pb.TaskResult) {
	if agentCliParam.DisableCommandExecute {
		result.Data = "此 Agent 已禁止命令执行"
		return
	}
	startedAt := time.Now()
	endCh := make(chan struct{})
	pg, err := processgroup.NewProcessExitGroup()
	if err != nil {
		// 进程组创建失败，直接退出
		result.Data = err.Error()
		return
	}
	timeout := time.NewTimer(time.Hour * 2)
	cmd := processgroup.NewCommand(task.GetData())
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Env = os.Environ()
	if err = cmd.Start(); err != nil {
		result.Data = err.Error()
		return
	}
	pg.AddProcess(cmd)
	go func() {
		select {
		case <-timeout.C:
			result.Data = "任务执行超时\n"
			close(endCh)
			pg.Dispose()
		case <-endCh:
			timeout.Stop()
		}
	}()
	if err = cmd.Wait(); err != nil {
		result.Data += fmt.Sprintf("%s\n%s", b.String(), err.Error())
	} else {
		close(endCh)
		result.Data = b.String()
		result.Successful = true
	}
	pg.Dispose()
	result.Delay = float32(time.Since(startedAt).Seconds())
}

type WindowSize struct {
	Cols uint32
	Rows uint32
}

func handleTerminalTask(task *pb.Task) {
	if agentCliParam.DisableCommandExecute {
		debugLogger.Println("此 Agent 已禁止命令执行")
		return
	}
	var terminal model.TerminalTask
	err := util.Json.Unmarshal([]byte(task.GetData()), &terminal)
	if err != nil {
		debugLogger.Printf("Terminal 任务解析错误: %v", err)
		return
	}

	helper, err := createIOStreamHelper("Terminal", terminal.StreamID)
	if err != nil {
		debugLogger.Printf(err.Error())
		return
	}

	tty, err := pty.Start()
	if err != nil {
		debugLogger.Printf("Terminal pty.Start失败 %v", err)
		return
	}

	defer func() {
		err := tty.Close()
		helper.closeWithLog()
		debugLogger.Println("terminal exit", terminal.StreamID, err)
	}()
	debugLogger.Println("terminal init", terminal.StreamID)

	go func() {
		for {
			buf := make([]byte, util.DefaultBufferSize)
			read, err := tty.Read(buf)
			if err != nil {
				helper.stream.Send(&pb.IOStreamData{Data: []byte(err.Error())})
				helper.stream.CloseSend()
				return
			}
			helper.stream.Send(&pb.IOStreamData{Data: buf[:read]})
		}
	}()

	for {
		var remoteData *pb.IOStreamData
		if remoteData, err = helper.stream.Recv(); err != nil {
			return
		}
		if len(remoteData.Data) == 0 {
			return
		}
		switch remoteData.Data[0] {
		case 0:
			tty.Write(remoteData.Data[1:])
		case 1:
			decoder := util.Json.NewDecoder(strings.NewReader(string(remoteData.Data[1:])))
			var resizeMessage WindowSize
			err := decoder.Decode(&resizeMessage)
			if err != nil {
				continue
			}
			tty.Setsize(resizeMessage.Cols, resizeMessage.Rows)
		}
	}
}

func handleNATTask(task *pb.Task) {
	if agentCliParam.DisableNat {
		debugLogger.Println("此 Agent 已禁止内网穿透")
		return
	}

	var nat model.TaskNAT
	err := util.Json.Unmarshal([]byte(task.GetData()), &nat)
	if err != nil {
		debugLogger.Printf("NAT 任务解析错误: %v", err)
		return
	}

	helper, err := createIOStreamHelper("NAT", nat.StreamID)
	if err != nil {
		debugLogger.Printf(err.Error())
		return
	}

	conn, err := net.Dial("tcp", nat.Host)
	if err != nil {
		debugLogger.Printf("NAT Dial %s 失败：%s", nat.Host, err)
		return
	}

	defer func() {
		err := conn.Close()
		helper.closeWithLog()
		debugLogger.Println("NAT exit", nat.StreamID, err)
	}()
	debugLogger.Println("NAT init", nat.StreamID)

	go func() {
		buf := make([]byte, util.DefaultBufferSize)
		for {
			read, err := conn.Read(buf)
			if err != nil {
				helper.stream.Send(&pb.IOStreamData{Data: []byte(err.Error())})
				helper.stream.CloseSend()
				return
			}
			helper.stream.Send(&pb.IOStreamData{Data: buf[:read]})
		}
	}()

	for {
		var remoteData *pb.IOStreamData
		if remoteData, err = helper.stream.Recv(); err != nil {
			return
		}
		conn.Write(remoteData.Data)
	}
}

func handleFMTask(task *pb.Task) {
	if agentCliParam.DisableCommandExecute {
		debugLogger.Println("此 Agent 已禁止命令执行")
		return
	}
	var fmTask model.TaskFM
	err := util.Json.Unmarshal([]byte(task.GetData()), &fmTask)
	if err != nil {
		debugLogger.Printf("FM 任务解析错误: %v", err)
		return
	}

	helper, err := createIOStreamHelper("FM", fmTask.StreamID)
	if err != nil {
		debugLogger.Printf(err.Error())
		return
	}

	defer func() {
		helper.closeWithLog()
		debugLogger.Println("FM exit", fmTask.StreamID, nil)
	}()
	debugLogger.Println("FM init", fmTask.StreamID)

	fmc := fm.NewFMClient(helper.stream, debugLogger.Printf)
	for {
		var remoteData *pb.IOStreamData
		if remoteData, err = helper.stream.Recv(); err != nil {
			return
		}
		if len(remoteData.Data) == 0 {
			return
		}
		fmc.DoTask(remoteData)
	}
}

func generateQueue(start int, size int) []int {
	var result []int
	for i := start; i < start+size; i++ {
		if i < size {
			result = append(result, i)
		} else {
			result = append(result, i-size)
		}
	}
	return result
}

func lookupIP(hostOrIp string) (string, error) {
	if net.ParseIP(hostOrIp) == nil {
		ips, err := dnsResolver.LookupIPAddr(context.Background(), hostOrIp)
		if err != nil {
			return "", err
		}
		if len(ips) == 0 {
			return "", fmt.Errorf("无法解析 %s", hostOrIp)
		}
		return ips[0].IP.String(), nil
	}
	return hostOrIp, nil
}

// IOStreamHelper handles common IOStream operations
type IOStreamHelper struct {
	stream   pb.ServerService_IOStreamClient
	streamID string
	taskName string
}

func createIOStreamHelper(taskName, streamID string) (*IOStreamHelper, error) {
	remoteIO, err := client.IOStream(context.Background())
	if err != nil {
		return nil, fmt.Errorf("%s IOStream失败: %v", taskName, err)
	}

	helper := &IOStreamHelper{
		stream:   remoteIO,
		streamID: streamID,
		taskName: taskName,
	}

	// 发送 StreamID
	if err := helper.sendStreamID(); err != nil {
		return nil, err
	}

	return helper, nil
}

func (h *IOStreamHelper) sendStreamID() error {
	data := util.CreateStreamIDData(h.streamID)
	if err := h.stream.Send(&pb.IOStreamData{Data: data}); err != nil {
		return fmt.Errorf("%s 发送StreamID失败: %v", h.taskName, err)
	}
	return nil
}

func (h *IOStreamHelper) closeWithLog() {
	err := h.stream.CloseSend()
	debugLogger.Println(fmt.Sprintf("%s exit %s %v", h.taskName, h.streamID, err))
}
