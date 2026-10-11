//go:build darwin

package autostart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePlist(t *testing.T) {
	execPath := "/Applications/gostpx.app/Contents/MacOS/gostpx"
	data, err := GeneratePlist(execPath)
	if err != nil {
		t.Fatalf("GeneratePlist failed: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "<key>Label</key>\n\t<string>io.github.losoph.gostpx</string>") {
		t.Errorf("Missing or incorrect Label in plist: %s", content)
	}
	if !strings.Contains(content, "<string>"+execPath+"</string>") {
		t.Errorf("Missing ProgramArguments in plist: %s", content)
	}
	if !strings.Contains(content, "<key>RunAtLoad</key>\n\t<true/>") {
		t.Errorf("Missing RunAtLoad in plist: %s", content)
	}
	if !strings.Contains(content, "<key>KeepAlive</key>\n\t<false/>") {
		t.Errorf("Missing KeepAlive in plist: %s", content)
	}

	extracted := ExtractProgramArgument(data)
	if extracted != execPath {
		t.Errorf("ExtractProgramArgument got %q, want %q", extracted, execPath)
	}
}

func TestIsInApplications(t *testing.T) {
	home, _ := os.UserHomeDir()
	tests := []struct {
		path string
		want bool
	}{
		{"/Applications/gostpx.app/Contents/MacOS/gostpx", true},
		{"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", true},
		{filepath.Join(home, "Applications", "gostpx.app", "Contents", "MacOS", "gostpx"), true},
		{filepath.Join(home, "Downloads", "gostpx.app", "Contents", "MacOS", "gostpx"), false},
		{"/Volumes/gostpx/gostpx.app/Contents/MacOS/gostpx", false},
		{"/private/var/folders/nz/abc/AppTranslocation/xyz/d/gostpx.app/Contents/MacOS/gostpx", false},
		{"/tmp/gostpx", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsInApplications(tt.path)
		if got != tt.want {
			t.Errorf("IsInApplications(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestSyncEnableDisablePairRollback(t *testing.T) {
	tmpDir := t.TempDir()
	appPath := "/Applications/gostpx.app/Contents/MacOS/gostpx"

	// 1. Enable via Sync
	warn, err := SyncWithDir(true, appPath, tmpDir)
	if err != nil {
		t.Fatalf("SyncWithDir(true) failed: %v", err)
	}
	if warn != "" {
		t.Fatalf("Unexpected warning: %s", warn)
	}

	enabled, err := IsEnabledWithDir(tmpDir)
	if err != nil {
		t.Fatalf("IsEnabledWithDir failed: %v", err)
	}
	if !enabled {
		t.Fatalf("Expected autostart to be enabled")
	}

	plistFile := filepath.Join(tmpDir, LaunchAgentFile)
	data, err := os.ReadFile(plistFile)
	if err != nil {
		t.Fatalf("Failed to read created plist: %v", err)
	}
	if ExtractProgramArgument(data) != appPath {
		t.Fatalf("ProgramArgument mismatch in plist: got %q, want %q", ExtractProgramArgument(data), appPath)
	}

	// 2. Binary moved -> Sync updates path
	newAppPath := "/Applications/gostpx-new.app/Contents/MacOS/gostpx"
	warn, err = SyncWithDir(true, newAppPath, tmpDir)
	if err != nil || warn != "" {
		t.Fatalf("Sync update failed: warn=%q, err=%v", warn, err)
	}
	data, _ = os.ReadFile(plistFile)
	if ExtractProgramArgument(data) != newAppPath {
		t.Fatalf("Expected path update to %q, got %q", newAppPath, ExtractProgramArgument(data))
	}

	// 3. Disable -> removes file (pair rollback)
	warn, err = SyncWithDir(false, newAppPath, tmpDir)
	if err != nil || warn != "" {
		t.Fatalf("SyncWithDir(false) failed: warn=%q, err=%v", warn, err)
	}

	enabled, _ = IsEnabledWithDir(tmpDir)
	if enabled {
		t.Fatalf("Expected autostart to be disabled after rollback")
	}
	if _, err := os.Stat(plistFile); !os.IsNotExist(err) {
		t.Fatalf("Expected plist file to be deleted, got err=%v", err)
	}
}

func TestSyncWarningOutsideApplications(t *testing.T) {
	tmpDir := t.TempDir()
	downloadsPath := "/Users/test/Downloads/gostpx.app/Contents/MacOS/gostpx"

	warn, err := SyncWithDir(true, downloadsPath, tmpDir)
	if err != nil {
		t.Fatalf("SyncWithDir failed: %v", err)
	}
	if warn != WarningNotInApplications {
		t.Errorf("Expected warning %q, got %q", WarningNotInApplications, warn)
	}

	plistFile := filepath.Join(tmpDir, LaunchAgentFile)
	if _, err := os.Stat(plistFile); !os.IsNotExist(err) {
		t.Fatalf("Plist file should not be created for path outside /Applications")
	}
}
