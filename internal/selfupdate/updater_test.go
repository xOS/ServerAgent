package selfupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/blang/semver"
)

func TestUpdateInstallsVerifiedRelease(t *testing.T) {
	newExecutable := []byte("new executable")
	archive := makeArchive(t, executableName(runtime.GOOS), newExecutable)
	targetPath := filepath.Join(t.TempDir(), "renamed-agent")
	if err := os.WriteFile(targetPath, []byte("old executable"), 0o750); err != nil {
		t.Fatal(err)
	}

	server := releaseServer(t, "v1.3.0", archive, false, nil)
	result, err := update(context.Background(), updateConfig{
		Options: Options{
			Current:    semver.MustParse("1.2.0"),
			Provider:   GitHub,
			Repository: "xOS/ServerAgent",
		},
		client:         server.Client(),
		apiBaseURL:     server.URL,
		executablePath: targetPath,
		goos:           runtime.GOOS,
		goarch:         runtime.GOARCH,
		allowHTTP:      true,
	})
	if err != nil {
		t.Fatalf("update() error: %v", err)
	}
	if !result.Updated || !result.Latest.Equals(semver.MustParse("1.3.0")) {
		t.Fatalf("update() result = %+v", result)
	}
	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, newExecutable) {
		t.Fatalf("installed executable = %q, want %q", content, newExecutable)
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o750 {
		t.Fatalf("installed mode = %o, want 750", info.Mode().Perm())
	}
}

func TestUpdateDoesNotDowngrade(t *testing.T) {
	archive := makeArchive(t, executableName(runtime.GOOS), []byte("older executable"))
	var assetRequests atomic.Int32
	server := releaseServer(t, "v1.2.0", archive, false, &assetRequests)
	targetPath := filepath.Join(t.TempDir(), "server-agent")
	if err := os.WriteFile(targetPath, []byte("newer executable"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := update(context.Background(), updateConfig{
		Options: Options{Current: semver.MustParse("1.3.0"), Repository: "xOS/ServerAgent"},
		client:  server.Client(), apiBaseURL: server.URL, executablePath: targetPath,
		goos: runtime.GOOS, goarch: runtime.GOARCH, allowHTTP: true,
	})
	if err != nil {
		t.Fatalf("update() error: %v", err)
	}
	if result.Updated {
		t.Fatal("update() downgraded the executable")
	}
	if assetRequests.Load() != 0 {
		t.Fatalf("asset requests = %d, want 0", assetRequests.Load())
	}
}

func TestUpdateRejectsChecksumMismatch(t *testing.T) {
	archive := makeArchive(t, executableName(runtime.GOOS), []byte("new executable"))
	server := releaseServer(t, "v1.3.0", archive, true, nil)
	targetPath := filepath.Join(t.TempDir(), "server-agent")
	oldExecutable := []byte("old executable")
	if err := os.WriteFile(targetPath, oldExecutable, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := update(context.Background(), updateConfig{
		Options: Options{Current: semver.MustParse("1.2.0"), Repository: "xOS/ServerAgent"},
		client:  server.Client(), apiBaseURL: server.URL, executablePath: targetPath,
		goos: runtime.GOOS, goarch: runtime.GOARCH, allowHTTP: true,
	})
	if err == nil {
		t.Fatal("update() accepted a checksum mismatch")
	}
	content, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(content, oldExecutable) {
		t.Fatalf("current executable changed after failed update: %q", content)
	}
}

func TestFetchLatestReleaseReportsMissingAsset(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/repos/xOS/ServerAgent/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(releaseResponse{TagName: "v1.3.0"})
	})

	_, err := fetchLatestRelease(context.Background(), updateConfig{
		Options:    Options{Current: semver.MustParse("1.2.0"), Repository: "xOS/ServerAgent"},
		client:     server.Client(),
		apiBaseURL: server.URL,
		goos:       runtime.GOOS,
		goarch:     runtime.GOARCH,
		allowHTTP:  true,
	})
	if !errors.Is(err, ErrAssetUnavailable) {
		t.Fatalf("fetchLatestRelease() error = %v, want ErrAssetUnavailable", err)
	}
}

func TestChecksumForAsset(t *testing.T) {
	hashText := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	checksum, err := checksumForAsset([]byte(hashText+"  server-agent_linux_amd64.zip\n"), "server-agent_linux_amd64.zip")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(checksum) != hashText {
		t.Fatalf("checksum = %x, want %s", checksum, hashText)
	}
}

func TestParseReleaseVersion(t *testing.T) {
	for _, tag := range []string{"v1.2.3", "server-agent-v1.2.3", "1.2.3-beta.1"} {
		version, err := parseReleaseVersion(tag)
		if err != nil {
			t.Fatalf("parseReleaseVersion(%q) error: %v", tag, err)
		}
		if version.Major != 1 || version.Minor != 2 || version.Patch != 3 {
			t.Fatalf("parseReleaseVersion(%q) = %v", tag, version)
		}
	}
}

func releaseServer(t *testing.T, tag string, archive []byte, badChecksum bool, assetRequests *atomic.Int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	archiveName := artifactName(runtime.GOOS, runtime.GOARCH)
	digest := sha256.Sum256(archive)
	if badChecksum {
		digest[0] ^= 0xff
	}
	checksums := fmt.Sprintf("%x  %s\n", digest, archiveName)

	mux.HandleFunc("/repos/xOS/ServerAgent/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		payload := releaseResponse{TagName: tag}
		payload.Assets = append(payload.Assets,
			struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
				Size               int64  `json:"size"`
			}{Name: archiveName, BrowserDownloadURL: server.URL + "/archive", Size: int64(len(archive))},
			struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
				Size               int64  `json:"size"`
			}{Name: checksumAssetName, BrowserDownloadURL: server.URL + "/checksums"},
		)
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Errorf("encode release response: %v", err)
		}
	})
	mux.HandleFunc("/archive", func(w http.ResponseWriter, _ *http.Request) {
		if assetRequests != nil {
			assetRequests.Add(1)
		}
		_, _ = w.Write(archive)
	})
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, _ *http.Request) {
		if assetRequests != nil {
			assetRequests.Add(1)
		}
		_, _ = w.Write([]byte(checksums))
	})
	return server
}

func makeArchive(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	file, err := archive.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func executableName(goos string) string {
	if goos == "windows" {
		return "server-agent.exe"
	}
	return "server-agent"
}
