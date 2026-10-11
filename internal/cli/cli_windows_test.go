//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuiHint(t *testing.T) {
	tmpDir := t.TempDir()

	if hint := guiHint(tmpDir); hint != "" {
		t.Errorf("expected empty hint when gostpxw.exe is missing, got %q", hint)
	}

	guiPath := filepath.Join(tmpDir, "gostpxw.exe")
	if err := os.WriteFile(guiPath, []byte("fake"), 0755); err != nil {
		t.Fatalf("failed to create fake gostpxw.exe: %v", err)
	}

	if hint := guiHint(tmpDir); hint == "" {
		t.Errorf("expected hint when gostpxw.exe exists, got empty string")
	}
}
