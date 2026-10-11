package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestState_ReconnectFields_Serialization(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	nextTime := time.Now().Add(30 * time.Second).Truncate(time.Millisecond)

	st := DefaultState()
	st.ActiveSession = false
	st.NetworkDown = false
	st.Reconnecting = true
	st.ReconnectAttempt = 3
	st.NextReconnect = nextTime
	st.LastDisconnectReason = "dial tcp 1.2.3.4:8080: connect: connection refused"

	if err := Save(statePath, st); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	loaded, err := Load(statePath)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if !loaded.Reconnecting {
		t.Errorf("expected Reconnecting=true, got false")
	}
	if loaded.ReconnectAttempt != 3 {
		t.Errorf("expected ReconnectAttempt=3, got %d", loaded.ReconnectAttempt)
	}
	if loaded.NextReconnect.Sub(nextTime).Abs() > time.Second {
		t.Errorf("expected NextReconnect approx %v, got %v", nextTime, loaded.NextReconnect)
	}
	if loaded.LastDisconnectReason != st.LastDisconnectReason {
		t.Errorf("expected LastDisconnectReason %q, got %q", st.LastDisconnectReason, loaded.LastDisconnectReason)
	}
	if loaded.NetworkDown {
		t.Errorf("expected NetworkDown=false, got true")
	}
}

func TestState_BackwardCompatibility_OldJSON(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	// Old JSON without network_down or reconnecting fields
	oldJSON := `{
  "schema_version": 1,
  "active_session": true,
  "pid": 12345,
  "mode": "sysproxy",
  "last_connected": "2026-09-29T10:00:00Z"
}`

	if err := os.WriteFile(statePath, []byte(oldJSON), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	loaded, err := Load(statePath)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if !loaded.ActiveSession {
		t.Errorf("expected ActiveSession=true")
	}
	if loaded.PID != 12345 {
		t.Errorf("expected PID=12345, got %d", loaded.PID)
	}
	if loaded.NetworkDown {
		t.Errorf("expected NetworkDown=false for legacy state")
	}
	if loaded.Reconnecting {
		t.Errorf("expected Reconnecting=false for legacy state")
	}
	if loaded.ReconnectAttempt != 0 {
		t.Errorf("expected ReconnectAttempt=0 for legacy state")
	}
	if !loaded.NextReconnect.IsZero() {
		t.Errorf("expected NextReconnect to be zero for legacy state")
	}
}
