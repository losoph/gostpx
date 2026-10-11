//go:build gostpxtest

package session

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

// TestSession_ReconnectLoop_CancelDuringLongDelay verifies that when the context is cancelled
// during a long reconnect backoff delay (e.g. 10 minutes), the goroutine exits immediately
// without waiting for the delay timer to expire.
func TestSession_ReconnectLoop_CancelDuringLongDelay(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	sess := New(configPath, statePath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	longDelay := 10 * time.Minute
	done := make(chan struct{})

	go func() {
		sess.runReconnectLoop(ctx, config.DefaultConfig(), "", []time.Duration{longDelay})
		close(done)
	}()

	// Wait briefly to ensure the goroutine enters the timer select
	time.Sleep(25 * time.Millisecond)

	// Cancel context during long delay
	start := time.Now()
	cancel()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			t.Errorf("reconnect loop took too long to exit: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reconnect loop did not exit immediately upon context cancellation")
	}
}

// TestSession_ReconnectLoop_StopDuringLongDelay verifies that calling sess.Stop during
// a long reconnect delay cancels the loop and returns immediately under -race.
func TestSession_ReconnectLoop_StopDuringLongDelay(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	cfg := config.DefaultConfig()
	_ = config.Save(configPath, cfg)

	sess := New(configPath, statePath)
	sess.SetReconnectBackoffs([]time.Duration{10 * time.Minute})

	sess.mu.Lock()
	sess.cfg = cfg
	sess.startReconnectLoopLocked("upstream down")
	sess.mu.Unlock()

	time.Sleep(25 * time.Millisecond)

	stopDone := make(chan struct{})
	go func() {
		_ = sess.Stop("user disabled")
		close(stopDone)
	}()

	select {
	case <-stopDone:
		// Succeeded immediately
	case <-time.After(2 * time.Second):
		t.Fatal("sess.Stop timed out while cancelling long reconnect loop")
	}

	info := sess.ReconnectInfo()
	if info.Attempt != 0 {
		t.Errorf("expected Attempt=0 after Stop, got %d", info.Attempt)
	}
}
