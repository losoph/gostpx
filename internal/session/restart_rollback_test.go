//go:build gostpxtest

package session

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
	"github.com/losoph/gostpx/internal/testupstream"
)

// TestSession_Restart_EngineStartFailureRollback verifies that when Restart fails
// at the engine.Start step (e.g. http_listen port is occupied), state.json is rolled back
// to ActiveSession=false, PID=0, sysproxy is rolled back to the pre-session snapshot,
// and EventDisconnected is emitted.
func TestSession_Restart_EngineStartFailureRollback(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	dryFile := filepath.Join(tmpDir, "dry.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryFile)

	// Pre-populate dryFile with user's original proxy settings before session
	initialDryState := `{"enabled":true,"http_host":"192.168.1.50","http_port":3128}`
	if err := os.WriteFile(dryFile, []byte(initialDryState), 0644); err != nil {
		t.Fatal(err)
	}

	upstream, err := testupstream.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	httpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := httpL.Addr().(*net.TCPAddr).Port
	httpL.Close()

	socksL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksPort := socksL.Addr().(*net.TCPAddr).Port
	socksL.Close()

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	_ = config.Save(configPath, cfg)
	_ = config.SavePassword(config.CredentialsPath(configPath), "")

	sess := New(configPath, statePath)
	if err := sess.Start(context.Background()); err != nil {
		t.Fatalf("sess.Start failed: %v", err)
	}
	if !sess.IsActive() {
		t.Fatal("expected session to be active")
	}

	// Drain initial events
	time.Sleep(20 * time.Millisecond)

	// Set hook to occupy httpPort right after old engine stops during Restart
	var blocker net.Listener
	resetHook := SetRestartHookForTest(func() {
		var err error
		blocker, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
		if err != nil {
			t.Errorf("failed to occupy http port in test hook: %v", err)
		}
	})
	defer resetHook()
	defer func() {
		if blocker != nil {
			_ = blocker.Close()
		}
	}()

	// Perform Restart - should fail during engine.Start because port is occupied
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	restartErr := sess.Restart(ctx)
	if restartErr == nil {
		t.Fatal("expected Restart to fail due to occupied http port, got nil")
	}
	if !strings.Contains(restartErr.Error(), "запуск движка") && !strings.Contains(restartErr.Error(), "listen http") {
		t.Errorf("expected error containing 'запуск движка' / 'listen http', got: %v", restartErr)
	}

	// 1. Session must be inactive
	if sess.IsActive() {
		t.Errorf("expected session to be inactive after failed restart")
	}

	// 2. state.json must have ActiveSession=false, PID=0, and disconnect reason
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state.json: %v", err)
	}
	if st.ActiveSession {
		t.Errorf("expected state.ActiveSession=false, got true")
	}
	if st.PID != 0 {
		t.Errorf("expected state.PID=0, got %d", st.PID)
	}
	if st.LastDisconnectReason == "" {
		t.Errorf("expected non-empty LastDisconnectReason in state.json")
	}
	// SysproxySnapshot must be nil after successful Unset
	if st.SysproxySnapshot != nil {
		t.Errorf("expected state.SysproxySnapshot=nil after successful rollback, got %+v", st.SysproxySnapshot)
	}

	// 3. Sysproxy must be restored to original snapshot (192.168.1.50:3128)
	cur, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("failed to read current sysproxy: %v", err)
	}
	if cur == nil || !cur.Enabled || cur.HTTPHost != "192.168.1.50" || cur.HTTPPort != 3128 {
		t.Errorf("expected sysproxy restored to 192.168.1.50:3128, got: %+v", cur)
	}

	// 4. EventDisconnected must have been emitted
	disconnectedReceived := false
	for {
		select {
		case ev := <-sess.Events():
			if ev.Type == EventDisconnected {
				disconnectedReceived = true
			}
		default:
			goto eventsChecked
		}
	}
eventsChecked:
	if !disconnectedReceived {
		t.Errorf("expected EventDisconnected to be emitted on restart failure")
	}
}

// TestSession_Restart_StopConcurrent verifies that a concurrent Stop("user disabled")
// during Restart properly cancels the restart, unsets proxy, and leaves state inactive.
func TestSession_Restart_StopConcurrent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	dryFile := filepath.Join(tmpDir, "dry.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryFile)

	// Pre-populate dryFile with user's original proxy settings before session
	initialDryState := `{"enabled":true,"http_host":"192.168.1.50","http_port":3128}`
	if err := os.WriteFile(dryFile, []byte(initialDryState), 0644); err != nil {
		t.Fatal(err)
	}

	upstream, err := testupstream.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	httpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := httpL.Addr().(*net.TCPAddr).Port
	httpL.Close()

	socksL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksPort := socksL.Addr().(*net.TCPAddr).Port
	socksL.Close()

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	_ = config.Save(configPath, cfg)
	_ = config.SavePassword(config.CredentialsPath(configPath), "")

	sess := New(configPath, statePath)
	if err := sess.Start(context.Background()); err != nil {
		t.Fatalf("sess.Start failed: %v", err)
	}
	if !sess.IsActive() {
		t.Fatal("expected session to be active")
	}

	// Drain start events
	time.Sleep(20 * time.Millisecond)

	// When restart reaches hook (between stopping old engine and startWithSnapshot),
	// invoke Stop concurrently from another goroutine
	stopDone := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	resetHook := SetRestartHookForTest(func() {
		go func() {
			defer wg.Done()
			stopDone <- sess.Stop("user disabled")
		}()
		// Wait slightly to let Stop acquire lock and set stopRequested
		time.Sleep(20 * time.Millisecond)
	})
	defer resetHook()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	restartErr := sess.Restart(ctx)
	wg.Wait()

	stopErr := <-stopDone
	if stopErr != nil {
		t.Errorf("unexpected error from sess.Stop: %v", stopErr)
	}
	if restartErr == nil {
		t.Fatal("expected Restart to return error when stopped concurrently, got nil")
	}
	if !strings.Contains(restartErr.Error(), "user disabled") {
		t.Errorf("expected restartErr to mention 'user disabled', got: %v", restartErr)
	}

	// Invariants after both completed:
	// 1. Session is inactive
	if sess.IsActive() {
		t.Errorf("expected session to be inactive, got active")
	}

	// 2. state.json has ActiveSession=false, PID=0, LastDisconnectReason="user disabled"
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state.json: %v", err)
	}
	if st.ActiveSession {
		t.Errorf("expected state.ActiveSession=false, got true")
	}
	if st.PID != 0 {
		t.Errorf("expected state.PID=0, got %d", st.PID)
	}
	if st.LastDisconnectReason != "user disabled" {
		t.Errorf("expected LastDisconnectReason='user disabled', got %q", st.LastDisconnectReason)
	}

	// 3. Sysproxy is restored to original snapshot (192.168.1.50:3128)
	cur, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("failed to read current sysproxy: %v", err)
	}
	if cur == nil || !cur.Enabled || cur.HTTPHost != "192.168.1.50" || cur.HTTPPort != 3128 {
		t.Errorf("expected sysproxy restored to 192.168.1.50:3128, got: %+v", cur)
	}

	// 4. EventDisconnected was emitted with reason "user disabled"
	disconnectedReceived := false
	for {
		select {
		case ev := <-sess.Events():
			if ev.Type == EventDisconnected && ev.Reason == "user disabled" {
				disconnectedReceived = true
			}
		default:
			goto eventsChecked
		}
	}
eventsChecked:
	if !disconnectedReceived {
		t.Errorf("expected EventDisconnected with reason 'user disabled'")
	}
}

// TestSession_Restart_StopConcurrent_DuringVerify verifies that Stop called while
// VerifyUpstream is in flight (s.mu unlocked) cleanly cancels Restart and rolls back.
func TestSession_Restart_StopConcurrent_DuringVerify(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	dryFile := filepath.Join(tmpDir, "dry.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryFile)

	initialDryState := `{"enabled":true,"http_host":"192.168.1.50","http_port":3128}`
	if err := os.WriteFile(dryFile, []byte(initialDryState), 0644); err != nil {
		t.Fatal(err)
	}

	upstream, err := testupstream.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	httpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := httpL.Addr().(*net.TCPAddr).Port
	httpL.Close()

	socksL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksPort := socksL.Addr().(*net.TCPAddr).Port
	socksL.Close()

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	_ = config.Save(configPath, cfg)
	_ = config.SavePassword(config.CredentialsPath(configPath), "")

	sess := New(configPath, statePath)
	if err := sess.Start(context.Background()); err != nil {
		t.Fatalf("sess.Start failed: %v", err)
	}
	if !sess.IsActive() {
		t.Fatal("expected session to be active")
	}

	time.Sleep(20 * time.Millisecond)

	stopDone := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	// Intercept right before VerifyUpstream executes with s.mu unlocked
	resetHook := SetBeforeVerifyUpstreamHookForTest(func() {
		go func() {
			defer wg.Done()
			stopDone <- sess.Stop("user disabled")
		}()
		time.Sleep(20 * time.Millisecond)
	})
	defer resetHook()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	restartErr := sess.Restart(ctx)
	wg.Wait()

	stopErr := <-stopDone
	if stopErr != nil {
		t.Errorf("unexpected error from sess.Stop: %v", stopErr)
	}
	if restartErr == nil {
		t.Fatal("expected Restart to fail due to concurrent stop, got nil")
	}
	if !strings.Contains(restartErr.Error(), "user disabled") {
		t.Errorf("expected restartErr to mention 'user disabled', got: %v", restartErr)
	}

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
	if st.PID != 0 {
		t.Errorf("expected state.PID=0, got %d", st.PID)
	}
	if st.LastDisconnectReason != "user disabled" {
		t.Errorf("expected LastDisconnectReason='user disabled', got %q", st.LastDisconnectReason)
	}

	cur, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("failed to read current sysproxy: %v", err)
	}
	if cur == nil || !cur.Enabled || cur.HTTPHost != "192.168.1.50" || cur.HTTPPort != 3128 {
		t.Errorf("expected sysproxy restored to 192.168.1.50:3128, got: %+v", cur)
	}
}
