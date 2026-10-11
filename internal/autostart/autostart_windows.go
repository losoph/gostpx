//go:build windows

package autostart

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const runRegistryKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// IsEnabled checks if HKCU\...\Run contains "gostpx".
func IsEnabled() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runRegistryKey, registry.QUERY_VALUE)
	if err != nil {
		return false, nil
	}
	defer k.Close()
	val, _, err := k.GetStringValue(WindowsRunKey)
	if err != nil {
		return false, nil
	}
	return val != "", nil
}

// Enable sets HKCU\...\Run "gostpx" = "<quoted path>".
func Enable(execPath string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runRegistryKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry run key: %w", err)
	}
	defer k.Close()

	// If gostpxw.exe exists in the same directory, prefer gostpxw.exe for GUI autostart
	targetPath := execPath
	dir := filepath.Dir(execPath)
	guiPath := filepath.Join(dir, "gostpxw.exe")
	if _, err := os.Stat(guiPath); err == nil {
		targetPath = guiPath
	}

	val := fmt.Sprintf("%q", targetPath)
	return k.SetStringValue(WindowsRunKey, val)
}

// Disable removes HKCU\...\Run "gostpx".
func Disable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runRegistryKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	_ = k.DeleteValue(WindowsRunKey)
	return nil
}

// Sync synchronizes Windows registry Run key with config.
func Sync(cfgAutostart bool, execPath string) (string, error) {
	if cfgAutostart {
		targetPath := execPath
		dir := filepath.Dir(execPath)
		guiPath := filepath.Join(dir, "gostpxw.exe")
		if _, err := os.Stat(guiPath); err == nil {
			targetPath = guiPath
		}
		expected := fmt.Sprintf("%q", targetPath)

		enabled, err := IsEnabled()
		if err != nil || !enabled {
			if err := Enable(execPath); err != nil {
				return "", err
			}
		} else {
			// Check if existing registry path needs update
			k, err := registry.OpenKey(registry.CURRENT_USER, runRegistryKey, registry.QUERY_VALUE)
			if err == nil {
				val, _, _ := k.GetStringValue(WindowsRunKey)
				k.Close()
				if val != expected {
					_ = Enable(execPath)
				}
			}
		}
		return "", nil
	}

	_ = Disable()
	return "", nil
}

// IsInApplications always returns true on Windows.
func IsInApplications(execPath string) bool {
	return true
}
