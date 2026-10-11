package autostart

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	LaunchAgentLabel         = "io.github.losoph.gostpx"
	LaunchAgentFile          = "io.github.losoph.gostpx.plist"
	WindowsRunKey            = "gostpx"
	WarningNotInApplications = "⚠ автозапуск: переместите gostpx.app в /Applications"
)

var (
	ErrNotInApplications = errors.New("app is not in /Applications")
)

// CurrentExecutable returns the resolved absolute path to the current binary.
func CurrentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable: %w", err)
	}
	eval, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe, nil
	}
	return eval, nil
}
