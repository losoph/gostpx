package state

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStateLoadNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "state.json")

	st, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error on missing file: %v", err)
	}
	if st.ActiveSession {
		t.Errorf("expected ActiveSession to be false, got true")
	}
	if st.Mode != "sysproxy" {
		t.Errorf("expected Mode sysproxy, got %s", st.Mode)
	}
}

func TestStateSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "state.json")

	now := time.Now().Truncate(time.Second)
	st := &State{
		Mode:                 "tun",
		ActiveSession:        true,
		CachedExternalIP:     "198.51.100.1",
		CachedCountry:        "US",
		LastConnected:        now,
		LastDisconnectReason: "user requested",
	}

	if err := Save(path, st); err != nil {
		t.Fatalf("failed to save state: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}

	if loaded.Mode != "tun" || !loaded.ActiveSession || loaded.CachedExternalIP != "198.51.100.1" || loaded.CachedCountry != "US" {
		t.Errorf("state fields mismatch: %+v", loaded)
	}
	if !loaded.LastConnected.Equal(now) {
		t.Errorf("LastConnected mismatch: got %v, want %v", loaded.LastConnected, now)
	}
	if loaded.LastDisconnectReason != "user requested" {
		t.Errorf("LastDisconnectReason mismatch: %s", loaded.LastDisconnectReason)
	}
}
