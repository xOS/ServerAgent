package util

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
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

// BufferPool 全局缓冲池，用于复用 byte slice 减少内存分配
var BufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, DefaultBufferSize)
		return &buf
	},
}

// LargeBufferPool 大缓冲池，用于文件传输等场景
var LargeBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, FileBufferSize)
		return &buf
	},
}

// GetBuffer 从缓冲池获取缓冲区
func GetBuffer() *[]byte {
	return BufferPool.Get().(*[]byte)
}

// PutBuffer 将缓冲区放回缓冲池
func PutBuffer(buf *[]byte) {
	if buf != nil {
		BufferPool.Put(buf)
	}
}

// GetLargeBuffer 从大缓冲池获取缓冲区
func GetLargeBuffer() *[]byte {
	return LargeBufferPool.Get().(*[]byte)
}

// PutLargeBuffer 将大缓冲区放回缓冲池
func PutLargeBuffer(buf *[]byte) {
	if buf != nil {
		LargeBufferPool.Put(buf)
	}
}

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
