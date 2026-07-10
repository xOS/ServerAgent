//go:build windows

package selfupdate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func replaceExecutable(source io.Reader, targetPath string, targetMode os.FileMode) error {
	stagedPath, err := stageExecutable(source, targetPath, targetMode)
	if err != nil {
		return err
	}
	defer os.Remove(stagedPath)

	oldPath := oldExecutablePath(targetPath)
	if err := cleanupOldExecutable(targetPath); err != nil {
		return fmt.Errorf("remove previous executable: %w", err)
	}
	if err := os.Rename(targetPath, oldPath); err != nil {
		return fmt.Errorf("move current executable aside: %w", err)
	}
	if err := os.Rename(stagedPath, targetPath); err != nil {
		rollbackErr := os.Rename(oldPath, targetPath)
		if rollbackErr != nil {
			return fmt.Errorf("activate new executable: %w; rollback failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("activate new executable: %w", err)
	}

	path, err := windows.UTF16PtrFromString(oldPath)
	if err == nil {
		_ = windows.SetFileAttributes(path, windows.FILE_ATTRIBUTE_HIDDEN)
	}
	return nil
}

func cleanupOldExecutable(targetPath string) error {
	err := os.Remove(oldExecutablePath(targetPath))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func oldExecutablePath(targetPath string) string {
	return filepath.Join(filepath.Dir(targetPath), "."+filepath.Base(targetPath)+".old")
}
