//go:build gostpxtest

package session

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
	"github.com/losoph/gostpx/internal/testupstream"
)

// TestSession_Restart_MissingSnapshot_Sanitized verifies that if state.json lost its
// sysproxy_snapshot during an active session, a subsequent Restart takes a new snapshot
// but sanitizes any entries matching the proxy listen addresses so that when Stop is
// subsequently called, dry-sysproxy is disabled (Enabled=false) and does not point to http_listen.
func TestSession_Restart_MissingSnapshot_Sanitized(t *testing.T) {
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
	if err := sess.Start(context.Background()); err != nil {
		t.Fatalf("sess.Start error: %v", err)
	}
	if !sess.IsActive() {
		t.Fatal("expected session to be active")
	}

	// Verify dry proxy is currently pointing to our httpPort
	cur, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("sysproxy.Current error: %v", err)
	}
	if !cur.Enabled || cur.HTTPPort != httpPort {
		t.Fatalf("expected sysproxy pointing to httpPort %d, got %+v", httpPort, cur)
	}

	// Manually delete snapshot from state.json
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("Load state error: %v", err)
	}
	st.SysproxySnapshot = nil
	if err := state.Save(statePath, st); err != nil {
		t.Fatalf("Save state error: %v", err)
	}

	// Perform Restart - origSnap will be nil, TakeSnapshot will see current proxy pointing to httpPort,
	// but SanitizeSnapshot must sanitize it to Enabled=false.
	if err := sess.Restart(context.Background()); err != nil {
		t.Fatalf("Restart error: %v", err)
	}
	if !sess.IsActive() {
		t.Fatal("expected session to remain active after Restart")
	}

	// Now Stop the session
	if err := sess.Stop("user disabled"); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	// dry-sysproxy must be disabled and NOT pointing to httpPort
	curAfter, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("sysproxy.Current after Stop error: %v", err)
	}
	if curAfter.Enabled {
		t.Errorf("expected sysproxy to be disabled (Enabled=false) after Stop, got: %+v", curAfter)
	}
	if curAfter.HTTPPort == httpPort {
		t.Errorf("sysproxy still points to dead http_listen port %d: %+v", httpPort, curAfter)
	}
}
