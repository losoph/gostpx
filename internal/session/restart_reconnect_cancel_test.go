//go:build gostpxtest

package session

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/testupstream"
)

// TestSession_Restart_CancelsReconnectLoopOnModeOff verifies that when a reconnect loop is
// running and upstream is reachable, calling Restart with mode = "off" cancels the reconnect
// loop so that over 3 backoff periods the session does NOT become active and state.json has no reconnecting.
func TestSession_Restart_CancelsReconnectLoopOnModeOff(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	dryFile := filepath.Join(tmpDir, "dry.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryFile)

	upstream, err := testupstream.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	getFreePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}

	httpPort := getFreePort()
	socksPort := getFreePort()

	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeSysproxy
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(config.CredentialsPath(configPath), ""); err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	backoff := 40 * time.Millisecond
	sess.SetReconnectBackoffs([]time.Duration{backoff, backoff, backoff})

	// Start reconnect loop while session is inactive
	sess.mu.Lock()
	sess.cfg = cfg
	sess.startReconnectLoopLocked("upstream unreachable")
	sess.mu.Unlock()

	// Verify reconnect loop is running
	info := sess.ReconnectInfo()
	if info.Attempt == 0 {
		t.Fatal("expected ReconnectInfo.Attempt > 0")
	}

	// Change config to mode = "off" and save
	cfg.Mode = config.ModeOff
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}

	// Call Restart while session is not active and mode is off
	if err := sess.Restart(context.Background()); err != nil {
		t.Fatalf("expected Restart to return nil, got: %v", err)
	}

	// Wait for 3 backoff periods (3 * 40ms = 120ms + buffer)
	time.Sleep(3*backoff + 50*time.Millisecond)

	// 1. Session must NOT have become active
	if sess.IsActive() {
		t.Errorf("expected session to NOT become active after Restart with mode=off")
	}

	// 2. state.json must not show reconnecting or active session
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("Load state error: %v", err)
	}
	if st.Reconnecting {
		t.Errorf("expected state.Reconnecting=false, got true")
	}
	if st.ReconnectAttempt != 0 {
		t.Errorf("expected state.ReconnectAttempt=0, got %d", st.ReconnectAttempt)
	}
	if st.ActiveSession {
		t.Errorf("expected state.ActiveSession=false, got true")
	}

	// 3. ReconnectInfo in memory must not show reconnecting
	infoAfter := sess.ReconnectInfo()
	if infoAfter.Attempt != 0 {
		t.Errorf("expected ReconnectInfo.Attempt=0, got %d", infoAfter.Attempt)
	}
}
