//go:build darwin

package autostart

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Program}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
</dict>
</plist>
`

type plistData struct {
	Label   string
	Program string
}

// GeneratePlist generates the XML bytes for LaunchAgent plist.
func GeneratePlist(execPath string) ([]byte, error) {
	tmpl, err := template.New("plist").Parse(plistTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	data := plistData{
		Label:   LaunchAgentLabel,
		Program: execPath,
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DefaultLaunchAgentsDir returns the default directory for user LaunchAgents (~/Library/LaunchAgents).
// Overridable via GOSTPX_LAUNCH_AGENTS_DIR for tests and dry runs.
func DefaultLaunchAgentsDir() string {
	if env := testLaunchAgentsDir(); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents")
	}
	return filepath.Join(home, "Library", "LaunchAgents")
}

// IsInApplications returns true if the executable path is located inside /Applications or ~/Applications.
func IsInApplications(execPath string) bool {
	if execPath == "" {
		return false
	}
	clean := filepath.Clean(execPath)
	if strings.HasPrefix(clean, "/Applications/") {
		return true
	}
	if strings.HasPrefix(clean, "/System/Applications/") {
		return true
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		userApps := filepath.Join(home, "Applications") + "/"
		if strings.HasPrefix(clean, userApps) {
			return true
		}
	}
	return false
}

// ExtractProgramArgument parses the binary path from existing plist bytes.
func ExtractProgramArgument(data []byte) string {
	s := string(data)
	idx := strings.Index(s, "<key>ProgramArguments</key>")
	if idx == -1 {
		return ""
	}
	sub := s[idx:]
	startTag := "<string>"
	endTag := "</string>"
	start := strings.Index(sub, startTag)
	if start == -1 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(sub[start:], endTag)
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(sub[start : start+end])
}

// IsEnabled checks if the LaunchAgent plist exists in the default directory.
func IsEnabled() (bool, error) {
	return IsEnabledWithDir(DefaultLaunchAgentsDir())
}

// IsEnabledWithDir checks if the plist exists in the specified directory.
func IsEnabledWithDir(dir string) (bool, error) {
	plistPath := filepath.Join(dir, LaunchAgentFile)
	_, err := os.Stat(plistPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Enable writes the LaunchAgent plist with current binary path without calling launchctl bootstrap.
func Enable(execPath string) error {
	return EnableWithDir(execPath, DefaultLaunchAgentsDir())
}

// EnableWithDir writes the plist in the specified directory.
func EnableWithDir(execPath, dir string) error {
	evalPath, err := filepath.EvalSymlinks(execPath)
	if err == nil {
		execPath = evalPath
	}
	if !IsInApplications(execPath) && !testAllowNonAppAutostart() {
		return ErrNotInApplications
	}

	content, err := GeneratePlist(execPath)
	if err != nil {
		return fmt.Errorf("generate plist: %w", err)
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create launch agents dir: %w", err)
	}

	plistPath := filepath.Join(dir, LaunchAgentFile)
	// Check if already exists with identical path
	if existing, err := os.ReadFile(plistPath); err == nil {
		if ExtractProgramArgument(existing) == execPath {
			return nil
		}
	}

	tmpFile := plistPath + ".tmp"
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		return fmt.Errorf("write temp plist: %w", err)
	}
	if err := os.Rename(tmpFile, plistPath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("rename plist: %w", err)
	}
	return nil
}

// Disable removes the LaunchAgent plist and unloads from launchd if loaded.
func Disable() error {
	return DisableWithDir(DefaultLaunchAgentsDir())
}

// DisableWithDir removes the plist from the specified dir.
func DisableWithDir(dir string) error {
	plistPath := filepath.Join(dir, LaunchAgentFile)
	_ = os.Remove(plistPath)

	// If using default system LaunchAgents dir, check if agent is loaded and bootout
	if testLaunchAgentsDir() == "" {
		uid := os.Getuid()
		target := fmt.Sprintf("gui/%d/%s", uid, LaunchAgentLabel)
		// Check launchctl print gui/$UID/<label>
		if err := exec.Command("launchctl", "print", target).Run(); err == nil {
			_ = exec.Command("launchctl", "bootout", target).Run()
		}
	}
	return nil
}

// Sync synchronizes the LaunchAgent state with config.
// Returns a warning string if app is not in /Applications.
func Sync(cfgAutostart bool, execPath string) (string, error) {
	return SyncWithDir(cfgAutostart, execPath, DefaultLaunchAgentsDir())
}

// SyncWithDir synchronizes LaunchAgent in the specified dir.
func SyncWithDir(cfgAutostart bool, execPath, dir string) (string, error) {
	evalPath, err := filepath.EvalSymlinks(execPath)
	if err == nil {
		execPath = evalPath
	}

	if cfgAutostart {
		if !IsInApplications(execPath) && !testAllowNonAppAutostart() {
			// Do not write translocation or Downloads path, return warning
			return WarningNotInApplications, nil
		}
		if err := EnableWithDir(execPath, dir); err != nil {
			return "", err
		}
		return "", nil
	}

	// cfgAutostart == false: clean up if exists
	if err := DisableWithDir(dir); err != nil {
		return "", err
	}
	return "", nil
}
