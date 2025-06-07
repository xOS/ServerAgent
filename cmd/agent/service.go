package main

import (
	"fmt"
	"os"

	"github.com/nezhahq/service"
	"github.com/spf13/cobra"
)

type AgentCliFlags struct {
	IsSpecified bool
	Flag        string
	Value       string
}

type program struct {
	exit    chan struct{}
	service service.Service
}

var serviceCmd = &cobra.Command{
	Use:    "service <install/uninstall/start/stop/restart>",
	Short:  "服务与自启动设置",
	Args:   cobra.ExactArgs(1),
	Run:    serviceActions,
	PreRun: servicePreRun,
}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	close(p.exit)
	if service.Interactive() {
		os.Exit(0)
	}
	return nil
}

func (p *program) run() {
	defer func() {
		if service.Interactive() {
			p.Stop(p.service)
		} else {
			p.service.Stop()
		}
	}()

	run()
}

func init() {
	agentCmd.AddCommand(serviceCmd)
}

func servicePreRun(cmd *cobra.Command, args []string) {
	if args[0] == "install" {
		if agentConfig.ClientSecret == "" {
			cmd.Help()
			os.Exit(1)
		}
	}

	if agentConfig.ReportDelay < 1 || agentConfig.ReportDelay > 4 {
		println("report-delay 的区间为 1-4")
		os.Exit(1)
	}
}

func serviceActions(cmd *cobra.Command, args []string) {
	var agentCliFlags []string

	flags := []AgentCliFlags{
		{agentConfig.Server != "localhost:2222", "-s", agentConfig.Server},
		{agentConfig.ClientSecret != "", "-p", agentConfig.ClientSecret},
		{agentConfig.TLS, "--tls", ""},
		{agentConfig.Debug, "-d", ""},
		{agentConfig.ReportDelay != 1, "--report-delay", fmt.Sprint(agentConfig.ReportDelay)},
		{agentConfig.SkipConnectionCount, "--skip-conn", ""},
		{agentConfig.SkipProcsCount, "--skip-procs", ""},
		{agentConfig.DisableCommandExecute, "--disable-command-execute", ""},
		{agentConfig.DisableAutoUpdate, "--disable-auto-update", ""},
		{agentConfig.DisableForceUpdate, "--disable-force-update", ""},
		{agentConfig.UseIPv6CountryCode, "--use-ipv6-countrycode", ""},
		{agentConfig.GPU, "--gpu", ""},
		{agentConfig.UseGiteeToUpgrade, "--gitee", ""},
		{agentConfig.IPReportPeriod != 30*60, "-u", fmt.Sprint(agentConfig.IPReportPeriod)},
	}

	for _, f := range flags {
		if f.IsSpecified {
			if f.Value == "" {
				agentCliFlags = append(agentCliFlags, f.Flag)
			} else {
				agentCliFlags = append(agentCliFlags, f.Flag, f.Value)
			}
		}
	}

	action := args[0]
	runService(action, agentCliFlags)
}
