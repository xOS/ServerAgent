//go:build !windows

package selfupdate

import (
	"io"
	"os"
	"path/filepath"
)

func replaceExecutable(source io.Reader, targetPath string, targetMode os.FileMode) error {
	stagedPath, err := stageExecutable(source, targetPath, targetMode)
	if err != nil {
		return err
	}
	defer os.Remove(stagedPath)

	if err := os.Rename(stagedPath, targetPath); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(targetPath))
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func cleanupOldExecutable(string) error {
	return nil
}
