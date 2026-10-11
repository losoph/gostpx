//go:build !darwin && !windows

package autostart

// IsEnabled is a no-op on non-darwin/windows platforms.
func IsEnabled() (bool, error) {
	return false, nil
}

// Enable is a no-op on non-darwin/windows platforms.
func Enable(execPath string) error {
	return nil
}

// Disable is a no-op on non-darwin/windows platforms.
func Disable() error {
	return nil
}

// Sync is a no-op on non-darwin/windows platforms.
func Sync(cfgAutostart bool, execPath string) (string, error) {
	return "", nil
}

// IsInApplications always returns true on non-darwin platforms.
func IsInApplications(execPath string) bool {
	return true
}
