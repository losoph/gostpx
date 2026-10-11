//go:build gostpxtest

package session

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/state"
)

// TestSession_ReconnectLoop_NilConfig verifies that if the reconnect loop runs with cfg == nil,
// it cleans up reconnect fields in memory (ReconnectInfo) and resets state.json
// (Reconnecting=false, ReconnectAttempt=0, NextReconnect zero, LastDisconnectReason="нет конфига", PID=0).
func TestSession_ReconnectLoop_NilConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	sess := New(configPath, statePath)
	sess.SetReconnectBackoffs([]time.Duration{10 * time.Millisecond})

	// Start reconnect loop directly with sess.cfg == nil
	sess.mu.Lock()
	sess.startReconnectLoopLocked("upstream down")
	sess.mu.Unlock()

	// Initial check: should show reconnecting
	initialInfo := sess.ReconnectInfo()
	if initialInfo.Attempt == 0 {
		t.Log("reconnect loop might have already executed")
	}

	// Wait for loop to detect cfg == nil and exit
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		info := sess.ReconnectInfo()
		st, _ := state.Load(statePath)
		if info.Attempt == 0 && st != nil && !st.Reconnecting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 1. ReconnectInfo in memory must not show reconnecting
	info := sess.ReconnectInfo()
	if info.Attempt != 0 {
		t.Errorf("expected ReconnectInfo.Attempt=0, got %d", info.Attempt)
	}
	if !info.Next.IsZero() {
		t.Errorf("expected ReconnectInfo.Next to be zero, got %v", info.Next)
	}

	// 2. state.json must not show reconnecting
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state.json: %v", err)
	}
	if st.Reconnecting {
		t.Errorf("expected state.Reconnecting=false, got true")
	}
	if st.ReconnectAttempt != 0 {
		t.Errorf("expected state.ReconnectAttempt=0, got %d", st.ReconnectAttempt)
	}
	if !st.NextReconnect.IsZero() {
		t.Errorf("expected state.NextReconnect to be zero, got %v", st.NextReconnect)
	}
	if st.LastDisconnectReason != "нет конфига" {
		t.Errorf("expected state.LastDisconnectReason 'нет конфига', got %q", st.LastDisconnectReason)
	}
	if st.PID != 0 {
		t.Errorf("expected state.PID=0, got %d", st.PID)
	}
}
