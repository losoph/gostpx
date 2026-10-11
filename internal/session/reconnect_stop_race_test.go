//go:build gostpxtest

package session

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/engine"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
	"github.com/losoph/gostpx/internal/testupstream"
)

func TestSession_ReconnectStopRace(t *testing.T) {
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
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	cfg.Health.ProbeInterval = "10s"

	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(config.CredentialsPath(configPath), ""); err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	sess.SetReconnectBackoffs([]time.Duration{20 * time.Millisecond})

	ctx := context.Background()
	if err := sess.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !sess.IsActive() {
		t.Fatalf("expected session to be active")
	}

	// Drain initial events
	time.Sleep(30 * time.Millisecond)

	var hookCalled atomic.Bool
	var eventsAfterStop []Event
	var eventsMu sync.Mutex
	stopCalled := make(chan struct{})

	// Intercept right before VerifyUpstream executes in the Start called by reconnect loop
	resetHook := SetBeforeVerifyUpstreamHookForTest(func() {
		sess.mu.Lock()
		isRecStarting := sess.reconnectStarting
		sess.mu.Unlock()

		if isRecStarting && hookCalled.CompareAndSwap(false, true) {
			go func() {
				_ = sess.Stop("user disabled")
				close(stopCalled)
			}()
			time.Sleep(20 * time.Millisecond)
		}
	})
	defer resetHook()

	// Monitor events
	go func() {
		for evt := range sess.Events() {
			eventsMu.Lock()
			select {
			case <-stopCalled:
				eventsAfterStop = append(eventsAfterStop, evt)
			default:
			}
			eventsMu.Unlock()
		}
	}()

	// Simulate disconnect event from engine
	sess.engine.EmitEventForTest(engine.Event{
		Type:      engine.EventDisconnected,
		Reason:    "network dropped",
		Timestamp: time.Now(),
	})

	// Wait until Stop has been triggered
	select {
	case <-stopCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for hook / stopCalled")
	}

	// Wait for any concurrent reconnect/start logic to settle
	time.Sleep(200 * time.Millisecond)

	// Verification 1: IsActive() == false
	if sess.IsActive() {
		t.Errorf("expected session to be inactive (IsActive() == false), got active")
	}

	// Verification 2: Phase is PhaseOff
	if sess.Phase() != PhaseOff {
		t.Errorf("expected phase PhaseOff, got %v", sess.Phase())
	}

	// Verification 3: sysproxy (dry) does not point to our ports
	cur, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("failed to read current sysproxy: %v", err)
	}
	if cur != nil && cur.Enabled {
		if cur.HTTPPort == httpPort || cur.SOCKSPort == socksPort {
			t.Errorf("sysproxy still points to our ports: HTTP %d, SOCKS %d", cur.HTTPPort, cur.SOCKSPort)
		}
	}

	// Verification 4: state.json ActiveSession=false, Reconnecting=false
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state.json: %v", err)
	}
	if st.ActiveSession {
		t.Errorf("expected state.ActiveSession=false, got true")
	}
	if st.Reconnecting {
		t.Errorf("expected state.Reconnecting=false, got true")
	}
	if st.PID != 0 {
		t.Errorf("expected state.PID=0, got %d", st.PID)
	}

	// Verification 5: No EventReconnected or EventConnected after Stop
	eventsMu.Lock()
	for _, evt := range eventsAfterStop {
		if evt.Type == EventReconnected {
			t.Errorf("unexpected EventReconnected received after Stop")
		}
		if evt.Type == EventConnected {
			t.Errorf("unexpected EventConnected received after Stop")
		}
	}
	eventsMu.Unlock()
}

func TestSession_ReconnectClosingRace(t *testing.T) {
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
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	cfg.Health.ProbeInterval = "10s"

	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(config.CredentialsPath(configPath), ""); err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	sess.SetReconnectBackoffs([]time.Duration{20 * time.Millisecond})

	ctx := context.Background()
	if err := sess.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	var hookCalled atomic.Bool
	closingCalled := make(chan struct{})

	resetHook := SetBeforeVerifyUpstreamHookForTest(func() {
		sess.mu.Lock()
		isRecStarting := sess.reconnectStarting
		sess.mu.Unlock()

		if isRecStarting && hookCalled.CompareAndSwap(false, true) {
			go func() {
				sess.SetClosing()
				close(closingCalled)
			}()
			time.Sleep(20 * time.Millisecond)
		}
	})
	defer resetHook()

	// Trigger disconnect
	sess.engine.EmitEventForTest(engine.Event{
		Type:      engine.EventDisconnected,
		Reason:    "connection dropped",
		Timestamp: time.Now(),
	})

	select {
	case <-closingCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SetClosing")
	}

	time.Sleep(200 * time.Millisecond)

	if sess.IsActive() {
		t.Errorf("expected session to be inactive, got active")
	}

	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state.json: %v", err)
	}
	if st.ActiveSession {
		t.Errorf("expected state.ActiveSession=false, got true")
	}
	if st.Reconnecting {
		t.Errorf("expected state.Reconnecting=false, got true")
	}
}
