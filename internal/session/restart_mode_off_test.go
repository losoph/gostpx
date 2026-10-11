//go:build gostpxtest

package session

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
	"github.com/losoph/gostpx/internal/testupstream"
)

// TestSession_Restart_ModeOff verifies that calling Restart when config has mode = "off"
// leaves the session inactive, restores sysproxy from the pre-session snapshot,
// updates state.json to active_session=false with reason "user disabled",
// and emits an EventDisconnected event with reason "user disabled".
func TestSession_Restart_ModeOff(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	dryFile := filepath.Join(tmpDir, "dry.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryFile)

	// Pre-populate dryFile with initial system proxy settings
	initialDryState := `{"enabled":true,"http_host":"192.168.1.50","http_port":3128}`
	if err := os.WriteFile(dryFile, []byte(initialDryState), 0644); err != nil {
		t.Fatal(err)
	}

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
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(config.CredentialsPath(configPath), ""); err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	if err := sess.Start(context.Background()); err != nil {
		t.Fatalf("sess.Start failed: %v", err)
	}
	if !sess.IsActive() {
		t.Fatal("expected session to be active")
	}

	// Drain initial events
	time.Sleep(20 * time.Millisecond)

	// Now change config to mode = "off"
	cfg.Mode = config.ModeOff
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("config.Save failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	restartErr := sess.Restart(ctx)
	if restartErr != nil {
		t.Fatalf("expected Restart with mode=off to succeed without error, got: %v", restartErr)
	}

	// 1. Session must be inactive
	if sess.IsActive() {
		t.Errorf("expected session to be inactive after Restart with mode=off")
	}

	// 2. state.json must have active_session=false, pid=0, last_disconnect_reason="user disabled"
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
		t.Errorf("expected LastDisconnectReason 'user disabled', got %q", st.LastDisconnectReason)
	}
	if st.SysproxySnapshot != nil {
		t.Errorf("expected SysproxySnapshot=nil, got %+v", st.SysproxySnapshot)
	}

	// 3. Sysproxy must be restored to initial snapshot (192.168.1.50:3128)
	cur, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("failed to read current sysproxy: %v", err)
	}
	if cur == nil || !cur.Enabled || cur.HTTPHost != "192.168.1.50" || cur.HTTPPort != 3128 {
		t.Errorf("expected sysproxy restored to 192.168.1.50:3128, got: %+v", cur)
	}

	// 4. Disconnect event with reason "user disabled" must have been emitted
	disconnectedReceived := false
	for {
		select {
		case ev := <-sess.Events():
			if ev.Type == EventDisconnected {
				disconnectedReceived = true
				if ev.Reason != "user disabled" {
					t.Errorf("expected EventDisconnected reason 'user disabled', got %q", ev.Reason)
				}
				break
			}
		default:
			goto done
		}
	}
done:
	if !disconnectedReceived {
		t.Errorf("expected EventDisconnected to be received on event channel")
	}
}

// TestSession_Start_ModeOffWorks verifies that explicit Start succeeds even when config mode is "off".
func TestSession_Start_ModeOffWorks(t *testing.T) {
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
	cfg.Mode = config.ModeOff
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = upstream.Port()
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(config.CredentialsPath(configPath), ""); err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	if err := sess.Start(context.Background()); err != nil {
		t.Fatalf("sess.Start failed: %v", err)
	}
	defer func() {
		_ = sess.Stop("test cleanup")
	}()

	if !sess.IsActive() {
		t.Errorf("expected session to be active after Start even with mode=off")
	}
}
