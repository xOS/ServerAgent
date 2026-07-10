//go:build !darwin && !windows && !plan9

package service

import (
	"log/syslog"
)

type Writer = syslog.Writer

var (
	NewSyslog = syslog.New
	NewSyslogLogger = syslog.NewLogger
)
