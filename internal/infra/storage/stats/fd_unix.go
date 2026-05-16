//go:build linux || darwin || freebsd || openbsd || netbsd

package stats

import (
	"os"
	"path/filepath"
)

func getFDCount() int {
	fdDir := "/proc/self/fd"
	entries, err := os.ReadDir(fdDir)
	if err == nil {
		return len(entries)
	}
	matches, err := filepath.Glob("/dev/fd/*")
	if err == nil {
		return len(matches)
	}
	return 0
}
