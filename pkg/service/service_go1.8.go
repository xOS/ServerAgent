//go:build go1.8
// +build go1.8

package service

import "os"

func (c *Config) execPath() (string, error) {
	if len(c.Executable) != 0 {
		return c.Executable, nil
	}
	return os.Executable()
}
