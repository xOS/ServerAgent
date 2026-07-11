package model

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAgentConfigReadPreservesExplicitDebugFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("debug: false\nserver: example.com:2222\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var config AgentConfig
	if err := config.Read(path); err != nil {
		t.Fatal(err)
	}
	if config.Debug {
		t.Fatal("explicit debug: false was replaced by the default")
	}
	if config.Server != "example.com:2222" {
		t.Fatalf("server = %q", config.Server)
	}
	if config.ReportDelay != 1 || config.IPReportPeriod != 1800 || config.R2UpdateURL != DefaultR2UpdateURL {
		t.Fatalf("defaults not applied: reportDelay=%d ipReportPeriod=%d r2=%q", config.ReportDelay, config.IPReportPeriod, config.R2UpdateURL)
	}
}

func TestAgentConfigReadUsesDefaultsForMissingFile(t *testing.T) {
	var config AgentConfig
	if err := config.Read(filepath.Join(t.TempDir(), "missing.yml")); err != nil {
		t.Fatal(err)
	}
	if !config.Debug || config.Server != "localhost:2222" || config.ReportDelay != 1 || config.IPReportPeriod != 1800 || config.R2UpdateURL != DefaultR2UpdateURL {
		t.Fatalf("unexpected defaults: %+v", config)
	}
}

func TestAgentConfigReadRejectsMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("debug: [\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var config AgentConfig
	if err := config.Read(path); err == nil {
		t.Fatal("malformed YAML was accepted")
	}
}

func TestAgentConfigSaveUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("debug: true\n"), 0777); err != nil {
		t.Fatal(err)
	}

	var config AgentConfig
	if err := config.Read(path); err != nil {
		t.Fatal(err)
	}
	config.ClientSecret = "secret"
	if err := config.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
}
