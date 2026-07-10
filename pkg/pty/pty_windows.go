//go:build windows && !arm64

package pty

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/UserExistsError/conpty"
	"github.com/iamacarpet/go-winpty"
	"github.com/shirou/gopsutil/v4/host"
)

var isWin10 bool

const (
	winPTYArchiveURL    = "https://github.com/rprichard/winpty/releases/download/0.4.3/winpty-0.4.3-msvc2015.zip"
	winPTYArchiveSHA256 = "35a48ece2ff4acdcbc8299d4920de53eb86b1fb41e64d2fe5ae7898931bcee89"
	winPTYMinFileSize   = 300000
	winPTYMaxFileSize   = 2 << 20
)

type winPTY struct {
	tty *winpty.WinPTY
}

type conPty struct {
	tty *conpty.ConPty
}

func init() {
	isWin10 = VersionCheck()
}

func VersionCheck() bool {
	hi, err := host.Info()
	if err != nil {
		return false
	}

	re := regexp.MustCompile(`Build (\d+(\.\d+)?)`)
	match := re.FindStringSubmatch(hi.KernelVersion)
	if len(match) > 1 {
		versionStr := match[1]

		version, err := strconv.ParseFloat(versionStr, 64)
		if err != nil {
			return false
		}

		return version >= 17763
	}
	return false
}

func DownloadDependency() error {
	if !isWin10 {
		executablePath, err := getExecutableFilePath()
		if err != nil {
			return fmt.Errorf("winpty 获取文件路径失败: %v", err)
		}

		winptyAgentExe := filepath.Join(executablePath, "winpty-agent.exe")
		winptyAgentDll := filepath.Join(executablePath, "winpty.dll")

		fe, errFe := os.Stat(winptyAgentExe)
		fd, errFd := os.Stat(winptyAgentDll)
		if errFe == nil && fe.Size() > winPTYMinFileSize && errFd == nil && fd.Size() > winPTYMinFileSize {
			return nil
		}

		resp, err := http.Get(winPTYArchiveURL)
		if err != nil {
			return fmt.Errorf("winpty 下载失败: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("winpty 下载失败: HTTP %s", resp.Status)
		}
		content, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return fmt.Errorf("winpty 下载失败: %v", err)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != winPTYArchiveSHA256 {
			return fmt.Errorf("winpty 压缩包校验失败")
		}
		if err := installWinPTYArchive(content, executablePath); err != nil {
			return fmt.Errorf("winpty 安装失败: %v", err)
		}
	}
	return nil
}

func installWinPTYArchive(content []byte, destination string) error {
	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return err
	}

	arch := "x64"
	if runtime.GOARCH != "amd64" {
		arch = "ia32"
	}
	wanted := map[string]string{
		arch + "/bin/winpty-agent.exe": filepath.Join(destination, "winpty-agent.exe"),
		arch + "/bin/winpty.dll":       filepath.Join(destination, "winpty.dll"),
	}

	for _, file := range archive.File {
		name := strings.TrimPrefix(filepath.ToSlash(file.Name), "./")
		target, ok := wanted[name]
		if !ok {
			continue
		}
		if file.UncompressedSize64 > winPTYMaxFileSize {
			return fmt.Errorf("%s 文件大小异常", filepath.Base(target))
		}
		if err := extractWinPTYFile(file, target); err != nil {
			return err
		}
		delete(wanted, name)
	}
	if len(wanted) != 0 {
		return fmt.Errorf("压缩包缺少所需文件")
	}
	return nil
}

func extractWinPTYFile(file *zip.File, target string) error {
	source, err := file.Open()
	if err != nil {
		return err
	}
	defer source.Close()

	temporary, err := os.CreateTemp(filepath.Dir(target), ".winpty-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	written, copyErr := io.Copy(temporary, io.LimitReader(source, winPTYMaxFileSize+1))
	closeErr := temporary.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != int64(file.UncompressedSize64) || written > winPTYMaxFileSize {
		return fmt.Errorf("%s 文件大小异常", filepath.Base(target))
	}
	if err := os.Chmod(temporaryName, 0755); err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return err
	}
	return nil
}

func getExecutableFilePath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(ex), nil
}

func Start() (IPty, error) {
	shellPath, err := exec.LookPath("powershell.exe")
	if err != nil || shellPath == "" {
		shellPath = "cmd.exe"
	}
	path, err := getExecutableFilePath()
	if err != nil {
		return nil, err
	}
	if !isWin10 {
		tty, err := winpty.OpenDefault(path, shellPath)
		return &winPTY{tty: tty}, err
	}
	tty, err := conpty.Start(shellPath, conpty.ConPtyWorkDir(path))
	return &conPty{tty: tty}, err
}

func (w *winPTY) Write(p []byte) (n int, err error) {
	return w.tty.StdIn.Write(p)
}

func (w *winPTY) Read(p []byte) (n int, err error) {
	return w.tty.StdOut.Read(p)
}

func (w *winPTY) Getsize() (uint16, uint16, error) {
	return 80, 40, nil
}

func (w *winPTY) Setsize(cols, rows uint32) error {
	w.tty.SetSize(cols, rows)
	return nil
}

func (w *winPTY) Close() error {
	w.tty.Close()
	return nil
}

func (c *conPty) Write(p []byte) (n int, err error) {
	return c.tty.Write(p)
}

func (c *conPty) Read(p []byte) (n int, err error) {
	return c.tty.Read(p)
}

func (c *conPty) Getsize() (uint16, uint16, error) {
	return 80, 40, nil
}

func (c *conPty) Setsize(cols, rows uint32) error {
	c.tty.Resize(int(cols), int(rows))
	return nil
}

func (c *conPty) Close() error {
	if err := c.tty.Close(); err != nil {
		return err
	}
	return nil
}

var _ IPty = &winPTY{}
var _ IPty = &conPty{}
