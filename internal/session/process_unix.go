//go:build !windows

package session

import (
	"os"
	"syscall"
)

// ShutdownSignals are the signals that trigger a clean teardown in foreground sessions.
var ShutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// IsPIDAlive checks whether a process with the given PID is currently alive.
func IsPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// TerminateProcess asks the process to shut down cleanly via SIGTERM.
func TerminateProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}
