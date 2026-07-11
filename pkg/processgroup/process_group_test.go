//go:build !windows

package processgroup

import (
	"testing"
	"time"
)

func TestDisposeTerminatesRunningProcessGroup(t *testing.T) {
	group, err := NewProcessExitGroup()
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewCommand("sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := group.AddProcess(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	if err := group.Dispose(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("process group was not terminated")
	}
}
