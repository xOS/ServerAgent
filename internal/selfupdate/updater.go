package selfupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/blang/semver"
)

const (
	githubAPIBaseURL = "https://api.github.com"

	checksumAssetName     = "checksums.txt"
	maxReleaseMetadata    = 2 << 20
	maxChecksumFile       = 1 << 20
	maxArchiveSize        = 256 << 20
	maxExecutableSize     = 256 << 20
	defaultRequestTimeout = 2 * time.Minute
)

var (
	versionPattern = regexp.MustCompile(`\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?`)
	updateMu       sync.Mutex
	// ErrAssetUnavailable indicates that a release exists but lacks a required update asset.
	ErrAssetUnavailable = errors.New("required release asset is unavailable")
)

type Provider uint8

const (
	GitHub Provider = iota
	R2
)

type Options struct {
	Current     semver.Version
	Provider    Provider
	Repository  string
	R2UpdateURL string
}

type Result struct {
	Latest  semver.Version
	Updated bool
}

type release struct {
	Version     semver.Version
	ArchiveName string
	ArchiveURL  string
	ArchiveSize int64
	ChecksumURL string
}

type releaseResponse struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

type updateConfig struct {
	Options
	client         *http.Client
	apiBaseURL     string
	executablePath string
	goos           string
	goarch         string
	allowHTTP      bool
}

func Update(ctx context.Context, options Options) (Result, error) {
	updateMu.Lock()
	defer updateMu.Unlock()

	executablePath, err := os.Executable()
	if err != nil {
		return Result{}, fmt.Errorf("resolve current executable: %w", err)
	}

	return update(ctx, updateConfig{
		Options:        options,
		client:         defaultHTTPClient(),
		apiBaseURL:     providerAPIBaseURL(options.Provider),
		executablePath: executablePath,
		goos:           runtime.GOOS,
		goarch:         runtime.GOARCH,
	})
}

// Cleanup removes the previous Windows executable after a successful restart.
func Cleanup() error {
	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}
	targetPath, _, err := resolveExecutable(executablePath)
	if err != nil {
		return err
	}
	return cleanupOldExecutable(targetPath)
}

func update(ctx context.Context, config updateConfig) (Result, error) {
	if config.client == nil {
		config.client = defaultHTTPClient()
	}
	if config.goos == "" {
		config.goos = runtime.GOOS
	}
	if config.goarch == "" {
		config.goarch = runtime.GOARCH
	}
	if config.apiBaseURL == "" {
		config.apiBaseURL = providerAPIBaseURL(config.Provider)
	}

	latest, err := fetchLatestRelease(ctx, config)
	if err != nil {
		return Result{}, err
	}
	result := Result{Latest: latest.Version}
	if !latest.Version.GT(config.Current) {
		return result, nil
	}

	expectedChecksum, err := downloadChecksum(ctx, config, latest.ChecksumURL, latest.ArchiveName)
	if err != nil {
		return result, err
	}
	archivePath, err := downloadArchive(ctx, config, latest, expectedChecksum)
	if err != nil {
		return result, err
	}
	defer os.Remove(archivePath)

	targetPath, targetMode, err := resolveExecutable(config.executablePath)
	if err != nil {
		return result, err
	}
	if err := installArchive(archivePath, targetPath, targetMode, config.goos); err != nil {
		return result, err
	}

	result.Updated = true
	return result, nil
}

func fetchLatestRelease(ctx context.Context, config updateConfig) (release, error) {
	if config.Provider == R2 {
		return fetchLatestReleaseR2(ctx, config)
	}
	endpoint, err := releaseEndpoint(config.apiBaseURL, config.Repository, config.allowHTTP)
	if err != nil {
		return release{}, err
	}
	body, err := downloadBytes(ctx, config, endpoint, "application/json", maxReleaseMetadata)
	if err != nil {
		return release{}, fmt.Errorf("fetch latest release: %w", err)
	}

	var payload releaseResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return release{}, fmt.Errorf("decode latest release: %w", err)
	}
	if payload.Draft || payload.Prerelease {
		return release{}, errors.New("latest release is not a stable release")
	}
	latestVersion, err := parseReleaseVersion(payload.TagName)
	if err != nil {
		return release{}, err
	}

	archiveName := artifactName(config.goos, config.goarch)
	var archiveURL, checksumURL string
	var archiveSize int64
	for _, asset := range payload.Assets {
		switch asset.Name {
		case archiveName:
			if archiveURL != "" {
				return release{}, fmt.Errorf("release contains duplicate asset %q", archiveName)
			}
			archiveURL = asset.BrowserDownloadURL
			archiveSize = asset.Size
		case checksumAssetName:
			if checksumURL != "" {
				return release{}, fmt.Errorf("release contains duplicate asset %q", checksumAssetName)
			}
			checksumURL = asset.BrowserDownloadURL
		}
	}
	if archiveURL == "" {
		return release{}, fmt.Errorf("%w: %q", ErrAssetUnavailable, archiveName)
	}
	if checksumURL == "" {
		return release{}, fmt.Errorf("%w: %q", ErrAssetUnavailable, checksumAssetName)
	}
	if archiveSize > maxArchiveSize {
		return release{}, fmt.Errorf("release asset %q is too large: %d bytes", archiveName, archiveSize)
	}
	if err := validateURL(archiveURL, config.allowHTTP); err != nil {
		return release{}, fmt.Errorf("invalid release asset URL: %w", err)
	}
	if err := validateURL(checksumURL, config.allowHTTP); err != nil {
		return release{}, fmt.Errorf("invalid checksum asset URL: %w", err)
	}

	return release{
		Version:     latestVersion,
		ArchiveName: archiveName,
		ArchiveURL:  archiveURL,
		ArchiveSize: archiveSize,
		ChecksumURL: checksumURL,
	}, nil
}

func downloadChecksum(ctx context.Context, config updateConfig, rawURL, archiveName string) ([]byte, error) {
	body, err := downloadBytes(ctx, config, rawURL, "text/plain", maxChecksumFile)
	if err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}
	checksum, err := checksumForAsset(body, archiveName)
	if err != nil {
		return nil, err
	}
	return checksum, nil
}

func downloadArchive(ctx context.Context, config updateConfig, rel release, expectedChecksum []byte) (string, error) {
	response, err := request(ctx, config, rel.ArchiveURL, "application/octet-stream")
	if err != nil {
		return "", fmt.Errorf("download release asset: %w", err)
	}
	defer response.Body.Close()
	if response.ContentLength > maxArchiveSize {
		return "", fmt.Errorf("release asset is too large: %d bytes", response.ContentLength)
	}

	archive, err := os.CreateTemp("", "server-agent-update-*.zip")
	if err != nil {
		return "", fmt.Errorf("create update archive: %w", err)
	}
	archivePath := archive.Name()
	keep := false
	defer func() {
		archive.Close()
		if !keep {
			os.Remove(archivePath)
		}
	}()

	digest := sha256.New()
	written, err := copyLimited(io.MultiWriter(archive, digest), response.Body, maxArchiveSize)
	if err != nil {
		return "", fmt.Errorf("save release asset: %w", err)
	}
	if rel.ArchiveSize > 0 && written != rel.ArchiveSize {
		return "", fmt.Errorf("release asset size mismatch: expected %d, got %d", rel.ArchiveSize, written)
	}
	if subtle.ConstantTimeCompare(digest.Sum(nil), expectedChecksum) != 1 {
		return "", errors.New("release asset checksum mismatch")
	}
	if err := archive.Sync(); err != nil {
		return "", fmt.Errorf("sync release asset: %w", err)
	}
	if err := archive.Close(); err != nil {
		return "", fmt.Errorf("close release asset: %w", err)
	}

	keep = true
	return archivePath, nil
}

func installArchive(archivePath, targetPath string, targetMode os.FileMode, goos string) error {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open release archive: %w", err)
	}
	defer archive.Close()

	binaryName := "server-agent"
	if goos == "windows" {
		binaryName += ".exe"
	}
	var binary *zip.File
	for _, file := range archive.File {
		if path.Base(file.Name) != binaryName || file.FileInfo().IsDir() {
			continue
		}
		if binary != nil {
			return fmt.Errorf("release archive contains duplicate executable %q", binaryName)
		}
		if !file.FileInfo().Mode().IsRegular() {
			return fmt.Errorf("release executable %q is not a regular file", binaryName)
		}
		if file.UncompressedSize64 > maxExecutableSize {
			return fmt.Errorf("release executable is too large: %d bytes", file.UncompressedSize64)
		}
		binary = file
	}
	if binary == nil {
		return fmt.Errorf("release executable %q was not found", binaryName)
	}

	reader, err := binary.Open()
	if err != nil {
		return fmt.Errorf("open release executable: %w", err)
	}
	defer reader.Close()
	if err := replaceExecutable(reader, targetPath, targetMode); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	return nil
}

func stageExecutable(source io.Reader, targetPath string, targetMode os.FileMode) (string, error) {
	directory := filepath.Dir(targetPath)
	prefix := "." + filepath.Base(targetPath) + ".new-"
	staged, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return "", err
	}
	stagedPath := staged.Name()
	keep := false
	defer func() {
		staged.Close()
		if !keep {
			os.Remove(stagedPath)
		}
	}()

	if targetMode.Perm() == 0 {
		targetMode = 0o755
	}
	if err := staged.Chmod(targetMode.Perm()); err != nil {
		return "", err
	}
	if _, err := copyLimited(staged, source, maxExecutableSize); err != nil {
		return "", err
	}
	if err := staged.Sync(); err != nil {
		return "", err
	}
	if err := staged.Close(); err != nil {
		return "", err
	}

	keep = true
	return stagedPath, nil
}

func resolveExecutable(executablePath string) (string, os.FileMode, error) {
	info, err := os.Lstat(executablePath)
	if err != nil {
		return "", 0, fmt.Errorf("stat current executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		executablePath, err = filepath.EvalSymlinks(executablePath)
		if err != nil {
			return "", 0, fmt.Errorf("resolve executable symlink: %w", err)
		}
		info, err = os.Stat(executablePath)
		if err != nil {
			return "", 0, fmt.Errorf("stat resolved executable: %w", err)
		}
	}
	if !info.Mode().IsRegular() {
		return "", 0, errors.New("current executable is not a regular file")
	}
	return executablePath, info.Mode(), nil
}

func downloadBytes(ctx context.Context, config updateConfig, rawURL, accept string, limit int64) ([]byte, error) {
	response, err := request(ctx, config, rawURL, accept)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength > limit {
		return nil, fmt.Errorf("response is too large: %d bytes", response.ContentLength)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, nil
}

func request(ctx context.Context, config updateConfig, rawURL, accept string) (*http.Response, error) {
	if err := validateURL(rawURL, config.allowHTTP); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "ServerAgent/"+config.Current.String())

	response, err := config.client.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return nil, fmt.Errorf("unexpected HTTP status %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	return response, nil
}

func checksumForAsset(data []byte, assetName string) ([]byte, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.TrimPrefix(fields[1], "*") != assetName {
			continue
		}
		checksum, err := hex.DecodeString(fields[0])
		if err != nil || len(checksum) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 checksum for %q", assetName)
		}
		return checksum, nil
	}
	return nil, fmt.Errorf("checksum for %q was not found", assetName)
}

func parseReleaseVersion(tag string) (semver.Version, error) {
	versionText := versionPattern.FindString(tag)
	if versionText == "" {
		return semver.Version{}, fmt.Errorf("release tag %q does not contain a semantic version", tag)
	}
	version, err := semver.Parse(versionText)
	if err != nil {
		return semver.Version{}, fmt.Errorf("parse release tag %q: %w", tag, err)
	}
	return version, nil
}

func releaseEndpoint(baseURL, repository string, allowHTTP bool) (string, error) {
	owner, name, ok := strings.Cut(repository, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("invalid repository %q; expected owner/name", repository)
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/latest", strings.TrimRight(baseURL, "/"), url.PathEscape(owner), url.PathEscape(name))
	if err := validateURL(endpoint, allowHTTP); err != nil {
		return "", err
	}
	return endpoint, nil
}

func validateURL(rawURL string, allowHTTP bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if parsed.Host == "" {
		return errors.New("URL has no host")
	}
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}
	return nil
}

func artifactName(goos, goarch string) string {
	return fmt.Sprintf("server-agent_%s_%s.zip", goos, goarch)
}

func providerAPIBaseURL(provider Provider) string {
	return githubAPIBaseURL
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many HTTP redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to %q", req.URL.Scheme)
			}
			return nil
		},
	}
}

func copyLimited(destination io.Writer, source io.Reader, limit int64) (int64, error) {
	written, err := io.Copy(destination, io.LimitReader(source, limit+1))
	if err != nil {
		return written, err
	}
	if written > limit {
		return written, fmt.Errorf("data exceeds %d bytes", limit)
	}
	return written, nil
}

func fetchLatestReleaseR2(ctx context.Context, config updateConfig) (release, error) {
	endpoint := strings.TrimRight(config.R2UpdateURL, "/") + "/index.json"
	body, err := downloadBytes(ctx, config, endpoint, "application/json", maxReleaseMetadata)
	if err != nil {
		return release{}, fmt.Errorf("fetch latest release: %w", err)
	}

	var payload releaseResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return release{}, fmt.Errorf("decode latest release: %w", err)
	}
	latestVersion, err := parseReleaseVersion(payload.TagName)
	if err != nil {
		return release{}, err
	}

	archiveName := artifactName(config.goos, config.goarch)
	archiveURL := strings.TrimRight(config.R2UpdateURL, "/") + "/" + payload.TagName + "/" + archiveName
	checksumURL := strings.TrimRight(config.R2UpdateURL, "/") + "/" + payload.TagName + "/checksums.txt"

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, archiveURL, nil)
	if err != nil {
		return release{}, err
	}
	resp, err := config.client.Do(req)
	if err != nil {
		return release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return release{}, fmt.Errorf("archive unavailable: %s", resp.Status)
	}

	return release{
		Version:     latestVersion,
		ArchiveName: archiveName,
		ArchiveURL:  archiveURL,
		ArchiveSize: resp.ContentLength,
		ChecksumURL: checksumURL,
	}, nil
}
