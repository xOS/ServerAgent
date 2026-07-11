//go:build windows

package processgroup

import (
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProcessExitGroup struct {
	cmds      []*exec.Cmd
	jobHandle windows.Handle
	procs     []windows.Handle
}

func NewProcessExitGroup() (*ProcessExitGroup, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}

	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)))

	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}

	return &ProcessExitGroup{jobHandle: job}, nil
}

func NewCommand(args string) *exec.Cmd {
	cmd := exec.Command("cmd")
	cmd.SysProcAttr = &windows.SysProcAttr{
		CmdLine:       fmt.Sprintf("/c %s", args),
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd
}

func (g *ProcessExitGroup) AddProcess(cmd *exec.Cmd) error {
	proc, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_SET_QUOTA|windows.PROCESS_SET_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}

	g.procs = append(g.procs, proc)
	g.cmds = append(g.cmds, cmd)

	return windows.AssignProcessToJobObject(g.jobHandle, proc)
}

func (g *ProcessExitGroup) Dispose() error {
	if err := windows.TerminateJobObject(g.jobHandle, 1); err != nil {
		// Fall-back on error. Kill the main process only.
		for _, cmd := range g.cmds {
			cmd.Process.Kill()
		}
		return err
	}

	// wait for job to be terminated
	status, err := windows.WaitForSingleObject(g.jobHandle, windows.INFINITE)
	if err != nil {
		return err
	}
	if status != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("unexpected job wait status: %d", status)
	}

	return nil
}

func (g *ProcessExitGroup) Close() error {
	for _, proc := range g.procs {
		windows.CloseHandle(proc)
	}
	g.procs = nil
	if g.jobHandle != 0 {
		err := windows.CloseHandle(g.jobHandle)
		g.jobHandle = 0
		return err
	}
	return nil
}
