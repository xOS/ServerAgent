//go:build !windows

package processgroup

import (
	"errors"
	"os/exec"
	"syscall"
)

type ProcessExitGroup struct {
	pgids []int
}

func NewProcessExitGroup() (*ProcessExitGroup, error) {
	return &ProcessExitGroup{}, nil
}

func NewCommand(arg string) *exec.Cmd {
	cmd := exec.Command("sh", "-c", arg)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func (g *ProcessExitGroup) Dispose() error {
	var firstErr error
	for _, pgid := range g.pgids {
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (g *ProcessExitGroup) AddProcess(cmd *exec.Cmd) error {
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		return err
	}
	g.pgids = append(g.pgids, pgid)
	return nil
}

func (g *ProcessExitGroup) Close() error {
	return nil
}
