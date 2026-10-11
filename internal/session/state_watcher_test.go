package session

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/state"
)

func TestStateWatcherAtomicOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	// 1. Initial state
	initialState := &state.State{
		ActiveSession: false,
		Mode:          "sysproxy",
	}
	if err := state.Save(statePath, initialState); err != nil {
		t.Fatalf("failed to save initial state: %v", err)
	}

	// 2. Start watcher
	callbackCh := make(chan *state.State, 10)
	watcher, err := WatchState(statePath, func() {
		st, _ := state.Load(statePath)
		callbackCh <- st
	})
	if err != nil {
		t.Fatalf("WatchState failed: %v", err)
	}
	defer func() { _ = watcher.Close() }()

	// Wait briefly for watcher loop to establish
	time.Sleep(50 * time.Millisecond)

	// 3. Atomically overwrite state file (state.Save uses tempfile + rename)
	updatedState := &state.State{
		ActiveSession: true,
		PID:           88888,
		Mode:          "sysproxy",
	}
	if err := state.Save(statePath, updatedState); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	// 4. Verify callback received updated state
	select {
	case received := <-callbackCh:
		if !received.ActiveSession {
			t.Errorf("expected ActiveSession=true, got false")
		}
		if received.PID != 88888 {
			t.Errorf("expected PID=88888, got %d", received.PID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for state watcher callback after atomic overwrite")
	}

	// 5. Overwrite again to ensure subsequent events are delivered
	finalState := &state.State{
		ActiveSession:        false,
		PID:                  0,
		Mode:                 "sysproxy",
		LastDisconnectReason: "CLI stopped",
	}
	if err := state.Save(statePath, finalState); err != nil {
		t.Fatalf("final state.Save failed: %v", err)
	}

	select {
	case received := <-callbackCh:
		if received.ActiveSession {
			t.Errorf("expected ActiveSession=false")
		}
		if received.LastDisconnectReason != "CLI stopped" {
			t.Errorf("expected LastDisconnectReason='CLI stopped', got %q", received.LastDisconnectReason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for second state watcher callback")
	}
}

func TestStateWatcherDebounceAndCoalesce(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	var triggerCount atomic.Int32
	watcher, err := WatchState(statePath, func() {
		triggerCount.Add(1)
	})
	if err != nil {
		t.Fatalf("WatchState error: %v", err)
	}
	defer func() { _ = watcher.Close() }()

	time.Sleep(50 * time.Millisecond)

	st := &state.State{
		ActiveSession: true,
		PID:           12345,
	}

	// Rapid succession of 5 saves should coalesce into exactly 1 trigger
	for i := 0; i < 5; i++ {
		st.PID = 20000 + i
		_ = state.Save(statePath, st)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait 250ms for debounce timer to fire
	time.Sleep(250 * time.Millisecond)
	if count := triggerCount.Load(); count != 1 {
		t.Fatalf("expected triggerCount=1 after debounced burst, got %d", count)
	}

	// After Close, no further triggers should fire
	_ = watcher.Close()
	_ = state.Save(statePath, st)
	time.Sleep(200 * time.Millisecond)
	if count := triggerCount.Load(); count != 1 {
		t.Fatalf("expected triggerCount=1 after Close, got %d", count)
	}
}

func TestStateWatcherCloseDuringPendingTimer(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	var triggerCount atomic.Int32
	watcher, err := WatchState(statePath, func() {
		triggerCount.Add(1)
	})
	if err != nil {
		t.Fatalf("WatchState error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	st := &state.State{
		ActiveSession: true,
		PID:           99999,
	}
	if err := state.Save(statePath, st); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	// Sleep 20ms: event is detected, debounce timer (100ms) is armed and pending
	time.Sleep(20 * time.Millisecond)

	// Close while timer is pending
	if err := watcher.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Wait 250ms past the 100ms debounce window
	time.Sleep(250 * time.Millisecond)

	if count := triggerCount.Load(); count != 0 {
		t.Fatalf("expected triggerCount=0 when closed during pending timer, got %d", count)
	}
}
