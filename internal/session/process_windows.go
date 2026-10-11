//go:build windows

package session

import (
	"fmt"
	"os"
	"syscall"
)

// ShutdownSignals are the signals that trigger a clean teardown in foreground sessions.
// Go maps Ctrl+C / Ctrl+Break to os.Interrupt and closing the console window,
// logoff and shutdown to SIGTERM; without the latter the proxy would stay set.
var ShutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

const stillActive = 259 // STILL_ACTIVE exit code

// IsPIDAlive checks whether a process with the given PID is currently alive.
func IsPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// TerminateProcess stops the foreground process. Windows has no
// SIGTERM for console processes, so the process is terminated; the caller
// unsets the system proxy itself afterwards.
func TerminateProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("поиск процесса %d: %w", pid, err)
	}
	if err := process.Kill(); err != nil {
		return fmt.Errorf("завершение процесса %d: %w", pid, err)
	}
	return nil
}
