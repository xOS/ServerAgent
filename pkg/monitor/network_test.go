package monitor

import (
	"testing"
	"time"
)

func TestNetworkSpeedDelta(t *testing.T) {
	tests := []struct {
		name     string
		current  uint64
		previous uint64
		elapsed  time.Duration
		want     uint64
	}{
		{name: "normal delta", current: 1600, previous: 1000, elapsed: 3 * time.Second, want: 200},
		{name: "subsecond interval", current: 1600, previous: 1000, elapsed: 500 * time.Millisecond, want: 1200},
		{name: "zero interval", current: 1600, previous: 1000, elapsed: 0, want: 0},
		{name: "counter reset", current: 100, previous: 1000, elapsed: 3 * time.Second, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := networkSpeedDelta(tt.current, tt.previous, tt.elapsed); got != tt.want {
				t.Fatalf("networkSpeedDelta() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSaturatingAddUint64(t *testing.T) {
	if got := saturatingAddUint64(10, 20); got != 30 {
		t.Fatalf("saturatingAddUint64(10, 20) = %d, want 30", got)
	}
	if got := saturatingAddUint64(^uint64(0), 1); got != ^uint64(0) {
		t.Fatalf("saturatingAddUint64(max, 1) = %d, want max", got)
	}
}

func TestIsNetInterfaceExcluded(t *testing.T) {
	tests := []struct {
		name     string
		excluded bool
	}{
		{"eth0", false},
		{"ens3", false},
		{"enp0s3", false},
		{"eno1", false},
		{"wlan0", false},
		{"lo", true},
		{"lo0", true},
		{"docker0", true},
		{"veth12345", true},
		{"br-abc123", true},
		{"vmbr0", true},
		{"virbr0", true},
		{"virbr0-nic", true},
		{"wg0", true},
		{"wg-quick", true},
		{"tailscale0", true},
		{"zt0", true},
		{"cni0", true},
		{"cni-podman0", true},
		{"flannel.1", true},
		{"cali1234", true},
		{"cilium_host", true},
		{"tap0", true},
		{"dummy0", true},
		{"sing-box", true},
		{"clash", true},
		{"meta", true},
		{"vEthernet (WSL)", true},
		{"utun1", true},
		{"bridge0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNetInterfaceExcluded(tt.name); got != tt.excluded {
				t.Fatalf("isNetInterfaceExcluded(%q) = %v, want %v", tt.name, got, tt.excluded)
			}
		})
	}
}
