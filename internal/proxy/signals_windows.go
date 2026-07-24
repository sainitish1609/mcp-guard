//go:build windows

package proxy

import "os"

// Windows defines neither SIGUSR1 nor SIGHUP, so the signal-driven summary
// snapshot and hot config reload are unavailable there. Nil entries are skipped
// at registration; every other protection behaves identically. The end-of-session
// summary still prints on exit.
var (
	statsSignal  os.Signal = nil
	reloadSignal os.Signal = nil
)
