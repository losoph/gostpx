//go:build gostpxtest

package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/state"
)

// TestSession_Restart_InactiveSession_ForeignProcessStateUntouched verifies that
// when Restart is called on an inactive session with mode = "off" in config,
// but state.json belongs to an active foreign process (live PID != os.Getpid()),
// state.json is NOT modified and remains completely intact.
func TestSession_Restart_InactiveSession_ForeignProcessStateUntouched(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeOff
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}

	// Write foreign process state with live parent PID
	parentPID := os.Getppid()
	foreignState := &state.State{
		Mode:                 config.ModeSysproxy,
		ActiveSession:        true,
		PID:                  parentPID,
		LastConnected:        time.Now().Truncate(time.Second),
		LastDisconnectReason: "",
		CachedExternalIP:     "198.51.100.22",
		CachedCountry:        "SE",
	}
	if err := state.Save(statePath, foreignState); err != nil {
		t.Fatal(err)
	}

	rawBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	if sess.IsActive() {
		t.Fatal("expected local session to be inactive")
	}

	// Call Restart on inactive session when config mode is "off"
	if err := sess.Restart(context.Background()); err != nil {
		t.Fatalf("expected Restart to return nil, got: %v", err)
	}

	rawAfter, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(rawBefore, rawAfter) {
		t.Errorf("state.json was modified! Before:\n%s\nAfter:\n%s", string(rawBefore), string(rawAfter))
	}

	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !st.ActiveSession || st.PID != parentPID || st.CachedExternalIP != "198.51.100.22" {
		t.Errorf("foreign state damaged: %+v", st)
	}
}
