package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestState_ZeroDates_OmittedInJSON(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	st := DefaultState()
	st.ActiveSession = false
	st.LastConnected = time.Time{}
	st.NextReconnect = time.Time{}

	if err := Save(statePath, st); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	content := string(data)

	if strings.Contains(content, "last_connected") {
		t.Errorf("expected last_connected to be omitted, got in JSON: %s", content)
	}
	if strings.Contains(content, "next_reconnect") {
		t.Errorf("expected next_reconnect to be omitted, got in JSON: %s", content)
	}
}

func TestState_OldZeroDate_BackwardCompatibility(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	oldJSON := `{
  "mode": "sysproxy",
  "active_session": false,
  "last_connected": "0001-01-01T00:00:00Z",
  "next_reconnect": "0001-01-01T00:00:00Z"
}`
	if err := os.WriteFile(statePath, []byte(oldJSON), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	loaded, err := Load(statePath)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if !loaded.LastConnected.IsZero() {
		t.Errorf("expected LastConnected.IsZero() == true, got %v", loaded.LastConnected)
	}
	if !loaded.NextReconnect.IsZero() {
		t.Errorf("expected NextReconnect.IsZero() == true, got %v", loaded.NextReconnect)
	}
}
