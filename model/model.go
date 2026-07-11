package model

import (
	"errors"
	"os"

	"sigs.k8s.io/yaml"
)

const DefaultR2UpdateURL = "https://assets.cnic.eu.org/serveragent"

type AgentConfig struct {
	// 监控配置
	HardDrivePartitionAllowlist []string        `yaml:"harddrivePartitionAllowlist"`
	NICAllowlist                map[string]bool `yaml:"nicAllowlist"`
	DNS                         []string        `yaml:"dns"`
	GPU                         bool            `yaml:"gpu"`
	Temperature                 bool            `yaml:"temperature"`
	Debug                       bool            `yaml:"debug"`

	// 连接配置
	Server       string `yaml:"server"`
	ClientSecret string `yaml:"clientSecret"`
	TLS          bool   `yaml:"tls"`
	InsecureTLS  bool   `yaml:"insecureTLS"`

	// 功能开关
	SkipConnectionCount   bool `yaml:"skipConnectionCount"`
	SkipProcsCount        bool `yaml:"skipProcsCount"`
	DisableAutoUpdate     bool `yaml:"disableAutoUpdate"`
	DisableForceUpdate    bool `yaml:"disableForceUpdate"`
	DisableCommandExecute bool `yaml:"disableCommandExecute"`
	DisableNat            bool `yaml:"disableNat"`
	DisableSendQuery      bool `yaml:"disableSendQuery"`

	// 其他配置
	ReportDelay        int    `yaml:"reportDelay"`
	IPReportPeriod     uint32 `yaml:"ipReportPeriod"`
	UseIPv6CountryCode bool   `yaml:"useIPv6CountryCode"`
	UseR2ToUpgrade     bool   `yaml:"useR2ToUpgrade"`
	R2UpdateURL        string `yaml:"r2UpdateURL"`

	// 内部字段
	configPath string `yaml:"-"`
}

func (c *AgentConfig) applyDefaults() {
	if c.Server == "" {
		c.Server = "localhost:2222"
	}
	if c.ReportDelay == 0 {
		c.ReportDelay = 1
	}
	if c.IPReportPeriod == 0 {
		c.IPReportPeriod = 30 * 60 // 30分钟
	}
	if c.R2UpdateURL == "" {
		c.R2UpdateURL = DefaultR2UpdateURL
	}
}

// Read 从给定的文件目录加载配置文件
func (c *AgentConfig) Read(path string) error {
	*c = AgentConfig{
		Debug:          true,
		Server:         "localhost:2222",
		ReportDelay:    1,
		IPReportPeriod: 30 * 60,
		R2UpdateURL:    DefaultR2UpdateURL,
		configPath:     path,
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}
	c.configPath = path
	c.applyDefaults()
	return nil
}

func (c *AgentConfig) Save() error {
	if c.configPath == "" {
		return errors.New("configuration path is empty")
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.configPath, data, 0600); err != nil {
		return err
	}
	return os.Chmod(c.configPath, 0600)
}
