//go:build !windows

package proxy

import (
	"os"
	"syscall"
)

// statsSignal requests an interim session summary; reloadSignal requests a hot
// config reload. Both are Unix-only concepts (see signals_windows.go).
var (
	statsSignal  os.Signal = syscall.SIGUSR1
	reloadSignal os.Signal = syscall.SIGHUP
)
