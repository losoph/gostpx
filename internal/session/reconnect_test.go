//go:build gostpxtest

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/engine"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/testupstream"
)

func TestSession_Phase_Transitions(t *testing.T) {
	sess := New("/tmp/cfg.toml", "/tmp/state.json")

	if p := sess.Phase(); p != PhaseOff {
		t.Fatalf("expected PhaseOff, got %v", p)
	}

	sess.active = true
	if p := sess.Phase(); p != PhaseConnected {
		t.Fatalf("expected PhaseConnected, got %v", p)
	}

	sess.networkDown = true
	if p := sess.Phase(); p != PhaseNetworkDown {
		t.Fatalf("expected PhaseNetworkDown, got %v", p)
	}

	sess.reconnectCancel = func() {}
	if p := sess.Phase(); p != PhaseReconnecting {
		t.Fatalf("expected PhaseReconnecting, got %v", p)
	}

	sess.reconnectCancel = nil
	sess.active = false
	sess.networkDown = false
	if p := sess.Phase(); p != PhaseOff {
		t.Fatalf("expected PhaseOff, got %v", p)
	}
}

func TestSession_ReconnectLoop_Success(t *testing.T) {
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

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", getFreePort())
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", getFreePort())
	cfg.Health.ProbeInterval = "10s"

	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(config.CredentialsPath(configPath), ""); err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	sess.SetReconnectBackoffs([]time.Duration{20 * time.Millisecond, 30 * time.Millisecond})

	ctx := context.Background()
	if err := sess.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !sess.IsActive() {
		t.Fatalf("expected session to be active")
	}

	var verifyAttempts atomic.Int32
	restoreVerify := SetVerifyUpstreamForTest(func(ctx context.Context, cfg config.ProxyConfig, plainSecret string, timeout time.Duration) (time.Duration, error) {
		att := verifyAttempts.Add(1)
		if att == 1 {
			// First reconnect verification fails
			return 0, errors.New("upstream unreachable probe failed")
		}
		// Second reconnect verification succeeds
		return 10 * time.Millisecond, nil
	})
	defer restoreVerify()

	// Drain any existing events
	time.Sleep(30 * time.Millisecond)

	// Simulate engine disconnect event
	eng := sess.engine
	if eng == nil {
		t.Fatalf("engine is nil")
	}

	// Trigger disconnect through engine event channel
	eng.EmitEventForTest(engine.Event{
		Type:      engine.EventDisconnected,
		Reason:    "upstream connection dropped",
		Timestamp: time.Now(),
	})

	// Wait for reconnect loop to trigger
	reconnected := false
	timer := time.After(2 * time.Second)
loop:
	for {
		select {
		case evt := <-sess.Events():
			if evt.Type == EventReconnected {
				reconnected = true
				break loop
			}
		case <-timer:
			break loop
		}
	}

	if !reconnected {
		t.Fatalf("expected EventReconnected was not received")
	}

	if !sess.IsActive() {
		t.Errorf("session should be active after reconnection")
	}
	if sess.Phase() != PhaseConnected {
		t.Errorf("session phase should be PhaseConnected, got %v", sess.Phase())
	}

	st, _ := state.Load(statePath)
	if st == nil || !st.ActiveSession {
		t.Errorf("state.json ActiveSession should be true after reconnection")
	}
	if st.Reconnecting {
		t.Errorf("state.json Reconnecting should be false after reconnection")
	}

	_ = sess.Stop("test finished")
}

func TestSession_ReconnectLoop_StopUserDisabled(t *testing.T) {
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

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", getFreePort())
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", getFreePort())
	cfg.Health.ProbeInterval = "10s"

	_ = config.Save(configPath, cfg)
	_ = config.SavePassword(config.CredentialsPath(configPath), "")

	sess := New(configPath, statePath)
	// Long backoff so it stays in reconnect loop
	sess.SetReconnectBackoffs([]time.Duration{500 * time.Millisecond})

	ctx := context.Background()
	if err := sess.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// Trigger disconnect
	sess.engine.EmitEventForTest(engine.Event{
		Type:      engine.EventDisconnected,
		Reason:    "connection timeout",
		Timestamp: time.Now(),
	})

	// Wait until in reconnect phase
	time.Sleep(50 * time.Millisecond)
	if sess.Phase() != PhaseReconnecting {
		t.Fatalf("expected PhaseReconnecting, got %v", sess.Phase())
	}

	info := sess.ReconnectInfo()
	if info.Attempt == 0 {
		t.Errorf("expected ReconnectInfo Attempt > 0, got %d", info.Attempt)
	}

	// User disables/cancels
	if err := sess.Stop("user disabled"); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	if sess.Phase() != PhaseOff {
		t.Errorf("expected PhaseOff after Stop, got %v", sess.Phase())
	}

	st, _ := state.Load(statePath)
	if st.Reconnecting {
		t.Errorf("expected state Reconnecting=false after Stop")
	}
}

func TestSession_ReconnectLoop_NoReconnectOnAuthFailed(t *testing.T) {
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

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", getFreePort())
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", getFreePort())
	cfg.Health.ProbeInterval = "10s"

	_ = config.Save(configPath, cfg)
	_ = config.SavePassword(config.CredentialsPath(configPath), "")

	sess := New(configPath, statePath)
	sess.SetReconnectBackoffs([]time.Duration{50 * time.Millisecond})

	ctx := context.Background()
	if err := sess.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// Trigger disconnect with auth rejection
	sess.engine.EmitEventForTest(engine.Event{
		Type:      engine.EventDisconnected,
		Reason:    "отказ в авторизации: invalid username or password",
		Timestamp: time.Now(),
	})

	time.Sleep(50 * time.Millisecond)

	if sess.Phase() == PhaseReconnecting {
		t.Errorf("session should NOT enter PhaseReconnecting on auth failure")
	}

	st, _ := state.Load(statePath)
	if st.Reconnecting {
		t.Errorf("state.json Reconnecting should NOT be true on auth failure")
	}

	_ = sess.Stop("test cleanup")
}
