package model

import (
	"os"

	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

type AgentConfig struct {
	// 监控配置
	HardDrivePartitionAllowlist []string        `yaml:"harddrivePartitionAllowlist" mapstructure:"harddrivePartitionAllowlist"`
	NICAllowlist                map[string]bool `yaml:"nicAllowlist" mapstructure:"nicAllowlist"`
	DNS                         []string        `yaml:"dns" mapstructure:"dns"`
	GPU                         bool            `yaml:"gpu" mapstructure:"gpu"`
	Temperature                 bool            `yaml:"temperature" mapstructure:"temperature"`
	Debug                       bool            `yaml:"debug" mapstructure:"debug"`

	// 连接配置
	Server       string `yaml:"server" mapstructure:"server"`
	ClientSecret string `yaml:"clientSecret" mapstructure:"clientSecret"`
	TLS          bool   `yaml:"tls" mapstructure:"tls"`
	InsecureTLS  bool   `yaml:"insecureTLS" mapstructure:"insecureTLS"`

	// 功能开关
	SkipConnectionCount   bool `yaml:"skipConnectionCount" mapstructure:"skipConnectionCount"`
	SkipProcsCount        bool `yaml:"skipProcsCount" mapstructure:"skipProcsCount"`
	DisableAutoUpdate     bool `yaml:"disableAutoUpdate" mapstructure:"disableAutoUpdate"`
	DisableForceUpdate    bool `yaml:"disableForceUpdate" mapstructure:"disableForceUpdate"`
	DisableCommandExecute bool `yaml:"disableCommandExecute" mapstructure:"disableCommandExecute"`
	DisableNat            bool `yaml:"disableNat" mapstructure:"disableNat"`
	DisableSendQuery      bool `yaml:"disableSendQuery" mapstructure:"disableSendQuery"`

	// 其他配置
	ReportDelay        int    `yaml:"reportDelay" mapstructure:"reportDelay"`
	IPReportPeriod     uint32 `yaml:"ipReportPeriod" mapstructure:"ipReportPeriod"`
	UseIPv6CountryCode bool   `yaml:"useIPv6CountryCode" mapstructure:"useIPv6CountryCode"`
	UseGiteeToUpgrade  bool   `yaml:"useGiteeToUpgrade" mapstructure:"useGiteeToUpgrade"`

	// 内部字段
	v *viper.Viper `yaml:"-" mapstructure:"-"`
}

// SetDefaults 设置默认值
func (c *AgentConfig) SetDefaults() {
	// 连接配置默认值
	if c.Server == "" {
		c.Server = "localhost:2222"
	}
	if c.ReportDelay == 0 {
		c.ReportDelay = 1
	}
	if c.IPReportPeriod == 0 {
		c.IPReportPeriod = 30 * 60 // 30分钟
	}
	// Debug 默认为 true
	if !c.Debug {
		c.Debug = true
	}
}

// Read 从给定的文件目录加载配置文件
func (c *AgentConfig) Read(path string) error {
	// 先设置默认值
	c.SetDefaults()

	c.v = viper.New()
	c.v.SetConfigFile(path)
	err := c.v.ReadInConfig()
	if err != nil {
		// 如果配置文件不存在，使用默认值
		return nil
	}
	err = c.v.Unmarshal(c)
	if err != nil {
		return err
	}

	// 读取配置后再次确保默认值
	c.SetDefaults()
	return nil
}

func (c *AgentConfig) Save() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(c.v.ConfigFileUsed(), data, os.ModePerm)
}
