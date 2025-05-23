package util

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/nezhahq/service"
)

const (
	MacOSChromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
	// Buffer sizes
	DefaultBufferSize = 10240
	FileBufferSize    = 1048576
)

var (
	Json                  = jsoniter.ConfigCompatibleWithStandardLibrary
	Logger service.Logger = service.ConsoleLogger
	// Stream header for StreamID
	StreamIDHeader = []byte{0xff, 0x05, 0xff, 0x05}
)

func IsWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

func Println(enabled bool, v ...interface{}) {
	if enabled {
		Logger.Infof("NG@%s>> %v", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(v...))
	}
}

func Printf(enabled bool, format string, v ...interface{}) {
	if enabled {
		Logger.Infof("NG@%s>> "+format, append([]interface{}{time.Now().Format("2006-01-02 15:04:05")}, v...)...)
	}
}

func BrowserHeaders() http.Header {
	return http.Header{
		"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"},
		"Accept-Language": {"en,zh-CN;q=0.9,zh;q=0.8"},
		"User-Agent":      {MacOSChromeUA},
	}
}

func ContainsStr(slice []string, str string) bool {
	if str != "" {
		for _, item := range slice {
			if strings.Contains(str, item) {
				return true
			}
		}
	}
	return false
}

func RemoveDuplicate[T comparable](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// DebugLogger provides debug-aware logging functionality
type DebugLogger struct {
	enabled bool
}

func NewDebugLogger(enabled bool) *DebugLogger {
	return &DebugLogger{enabled: enabled}
}

func (d *DebugLogger) Printf(format string, v ...interface{}) {
	Printf(d.enabled, format, v...)
}

func (d *DebugLogger) Println(v ...interface{}) {
	Println(d.enabled, v...)
}

// CreateStreamIDData creates StreamID data for IOStream
func CreateStreamIDData(streamID string) []byte {
	return append(StreamIDHeader, []byte(streamID)...)
}
