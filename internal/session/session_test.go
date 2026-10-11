//go:build gostpxtest

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestSessionLifecycleBasic(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", filepath.Join(tmpDir, "sysproxy.json"))

	// 1. Session with no proxy configured returns error
	cfg := config.DefaultConfig()
	cfg.Proxy.Host = ""
	_ = config.Save(configPath, cfg)

	sess := New(configPath, statePath)
	err := sess.Start(context.Background())
	if err == nil {
		t.Fatalf("expected error starting session with empty proxy host")
	}

	// 2. IsPIDAlive on current process
	if !IsPIDAlive(os.Getpid()) {
		t.Errorf("expected current process PID %d to be alive", os.Getpid())
	}
	if IsPIDAlive(-1) {
		t.Errorf("expected PID -1 to not be alive")
	}

	// 3. RecoverDanglingProxy with no proxy
	rec, err := RecoverDanglingProxy(configPath, statePath)
	if err != nil {
		t.Fatalf("unexpected error in RecoverDanglingProxy: %v", err)
	}
	if rec.Recovered || rec.Occupied {
		t.Errorf("expected recovered=false and occupied=false when no proxy set")
	}

	// 4. Stop when inactive does not fail
	if err := sess.Stop("test stop"); err != nil {
		t.Fatalf("unexpected error stopping inactive session: %v", err)
	}

	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if st.ActiveSession {
		t.Errorf("expected ActiveSession=false in state")
	}
	if st.LastDisconnectReason != "test stop" {
		t.Errorf("expected reason 'test stop', got: %s", st.LastDisconnectReason)
	}
}

func TestSessionExternalIPCache(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	sess := New(configPath, statePath)
	sess.cachedIP = "1.2.3.4"
	sess.cachedCountry = "US"
	sess.cachedIPTime = time.Now()
	sess.cachedIPWasProxy = false

	ip, country, err := sess.GetExternalIP(context.Background(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "1.2.3.4" || country != "US" {
		t.Errorf("expected cached IP '1.2.3.4' and country 'US', got %q, %q", ip, country)
	}
}

func TestStopActiveSessionPreservesState(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", filepath.Join(tmpDir, "sysproxy.json"))

	now := time.Now().Truncate(time.Second)
	initialState := &state.State{
		ActiveSession:        true,
		Mode:                 config.ModeSysproxy,
		PID:                  999999, // inactive PID
		LastConnected:        now,
		LastDisconnectReason: "",
		CachedExternalIP:     "5.6.7.8",
	}
	if err := state.Save(statePath, initialState); err != nil {
		t.Fatalf("failed to save initial state: %v", err)
	}

	if err := StopActiveSession(statePath, "test disabled"); err != nil {
		t.Fatalf("unexpected error in StopActiveSession: %v", err)
	}

	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if st.ActiveSession {
		t.Errorf("expected ActiveSession=false")
	}
	if st.PID != 0 {
		t.Errorf("expected PID=0, got %d", st.PID)
	}
	if st.Mode != config.ModeSysproxy {
		t.Errorf("expected Mode=%q to be preserved, got %q", config.ModeSysproxy, st.Mode)
	}
	if st.CachedExternalIP != "" {
		t.Errorf("expected CachedExternalIP to be cleared upon StopActiveSession, got %q", st.CachedExternalIP)
	}
	if !st.LastConnected.Equal(now) {
		t.Errorf("expected LastConnected to be preserved, got %v, want %v", st.LastConnected, now)
	}
	if st.LastDisconnectReason != "test disabled" {
		t.Errorf("expected LastDisconnectReason='test disabled', got %q", st.LastDisconnectReason)
	}
}

func TestSessionStopUpdatesStateAndEmitsEvent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", filepath.Join(tmpDir, "sysproxy.json"))

	sess := New(configPath, statePath)
	sess.active = true

	events := sess.Events()

	err := sess.Stop("test-signal")
	if err != nil {
		t.Fatalf("unexpected error in Stop: %v", err)
	}

	select {
	case evt := <-events:
		if evt.Type != EventDisconnected {
			t.Errorf("expected EventDisconnected, got %v", evt.Type)
		}
		if evt.Reason != "test-signal" {
			t.Errorf("expected reason 'test-signal', got %q", evt.Reason)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for EventDisconnected")
	}

	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if st.ActiveSession {
		t.Errorf("expected ActiveSession=false")
	}
	if st.LastDisconnectReason != "test-signal" {
		t.Errorf("expected LastDisconnectReason='test-signal', got %q", st.LastDisconnectReason)
	}
}

func TestSessionIPCacheResetOnStopAndStart(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", filepath.Join(tmpDir, "sysproxy.json"))

	// 1. Setup session with cached IP
	sess := New(configPath, statePath)
	sess.active = true
	sess.cachedIP = "203.0.113.30"
	sess.cachedCountry = "KZ"
	sess.cachedIPTime = time.Now()
	sess.cachedIPWasProxy = true

	_ = state.Save(statePath, &state.State{
		ActiveSession:    true,
		CachedExternalIP: "203.0.113.30",
		CachedCountry:    "KZ",
	})

	ip, country := sess.CachedIP()
	if ip != "203.0.113.30" || country != "KZ" {
		t.Fatalf("expected CachedIP to return cached value, got %q, %q", ip, country)
	}

	// 2. Stop resets cache in memory and in state.json
	if err := sess.Stop("user disabled"); err != nil {
		t.Fatalf("unexpected error in Stop: %v", err)
	}

	ip, country = sess.CachedIP()
	if ip != "" || country != "" {
		t.Errorf("expected in-memory CachedIP to be empty after Stop, got %q, %q", ip, country)
	}
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if st.CachedExternalIP != "" || st.CachedCountry != "" {
		t.Errorf("expected state cache to be empty after Stop, got IP=%q Country=%q", st.CachedExternalIP, st.CachedCountry)
	}

	// 3. ResetIPCache helper
	sess.cachedIP = "1.2.3.4"
	sess.cachedCountry = "US"
	sess.cachedIPTime = time.Now()
	st.CachedExternalIP = "1.2.3.4"
	st.CachedCountry = "US"
	_ = state.Save(statePath, st)

	sess.ResetIPCache()
	ip, country = sess.CachedIP()
	if ip != "" || country != "" {
		t.Errorf("expected in-memory CachedIP to be empty after ResetIPCache, got %q, %q", ip, country)
	}
	st, _ = state.Load(statePath)
	if st.CachedExternalIP != "" || st.CachedCountry != "" {
		t.Errorf("expected state cache to be empty after ResetIPCache, got IP=%q Country=%q", st.CachedExternalIP, st.CachedCountry)
	}
}

func TestFetchExternalIPParsing(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		statusCode  int
		wantIP      string
		wantCountry string
		wantErr     bool
	}{
		{
			name:        "Standard json with IP and country",
			body:        `{"ip":"198.51.100.20","country":"US","city":"Huntington"}`,
			statusCode:  http.StatusOK,
			wantIP:      "198.51.100.20",
			wantCountry: "US",
		},
		{
			name:        "JSON without country",
			body:        `{"ip":"1.2.3.4"}`,
			statusCode:  http.StatusOK,
			wantIP:      "1.2.3.4",
			wantCountry: "",
		},
		{
			name:        "JSON with empty country",
			body:        `{"ip":"5.6.7.8","country":""}`,
			statusCode:  http.StatusOK,
			wantIP:      "5.6.7.8",
			wantCountry: "",
		},
		{
			name:        "Plain text IP",
			body:        "9.10.11.12\n",
			statusCode:  http.StatusOK,
			wantIP:      "9.10.11.12",
			wantCountry: "",
		},
		{
			name:       "500 Internal Server Error",
			body:       "Internal Server Error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			ip, country, err := fetchExternalIPFromURL(context.Background(), server.URL, "")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ip != tt.wantIP {
				t.Errorf("IP mismatch: got %q, want %q", ip, tt.wantIP)
			}
			if country != tt.wantCountry {
				t.Errorf("Country mismatch: got %q, want %q", country, tt.wantCountry)
			}
		})
	}
}

func TestSessionStartClosingRace(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	// 1. Direct SetClosing before Start returns ErrSessionClosing
	sessPre := New(configPath, statePath)
	sessPre.SetClosing()
	if err := sessPre.Start(context.Background()); !errors.Is(err, ErrSessionClosing) {
		t.Fatalf("expected ErrSessionClosing, got: %v", err)
	}

	// 2. Start with dummy listener for upstream
	probeL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer probeL.Close()

	probePort := probeL.Addr().(*net.TCPAddr).Port

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = probePort
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	// Run concurrent Start and Stop/SetClosing
	for i := 0; i < 5; i++ {
		sess := New(configPath, statePath)
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = sess.Start(context.Background())
		}()

		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i*3) * time.Millisecond)
			sess.SetClosing()
			_ = sess.Stop("shutdown")
		}()

		wg.Wait()

		// Verify invariant: sysproxy MUST NOT remain enabled!
		cur, err := sysproxy.Current()
		if err != nil {
			t.Fatalf("sysproxy.Current failed: %v", err)
		}
		if cur.Enabled {
			t.Errorf("iteration %d: sysproxy left enabled after concurrent Start/Stop!", i)
		}
		if sess.IsActive() {
			t.Errorf("iteration %d: sess.IsActive() == true after Stop!", i)
		}
	}
}

func TestRecoverDanglingProxy_OccupiedVsDeadPort(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	// Case 1: Port has an active listener (e.g. SwiftBar proxy).
	// Must NOT unset sysproxy!
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()
	livePort := l.Addr().(*net.TCPAddr).Port

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", livePort)
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	// Set sysproxy to point to livePort
	if err := sysproxy.Set(cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen); err != nil {
		t.Fatalf("sysproxy.Set failed: %v", err)
	}

	res, err := RecoverDanglingProxy(configPath, statePath)
	if err != nil {
		t.Fatalf("RecoverDanglingProxy error: %v", err)
	}
	if !res.Occupied {
		t.Errorf("expected res.Occupied=true for live listener")
	}
	if res.Recovered {
		t.Errorf("expected res.Recovered=false for live listener")
	}

	cur, err := sysproxy.Current()
	if err != nil || cur == nil || !cur.Enabled {
		t.Fatalf("expected sysproxy to remain enabled when port is occupied!")
	}

	// Case 2: Port is dead. Safe to unset!
	_ = l.Close()
	time.Sleep(50 * time.Millisecond)

	resDead, err := RecoverDanglingProxy(configPath, statePath)
	if err != nil {
		t.Fatalf("RecoverDanglingProxy error on dead port: %v", err)
	}
	if resDead.Occupied {
		t.Errorf("expected resDead.Occupied=false on dead port")
	}
	if !resDead.Recovered {
		t.Errorf("expected resDead.Recovered=true on dead port")
	}

	curDead, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("sysproxy.Current failed: %v", err)
	}
	if curDead != nil && curDead.Enabled {
		t.Errorf("expected sysproxy to be unset when port is dead!")
	}
}

func TestSessionStart_StateSaveFailureRollback(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	blockFile := filepath.Join(tmpDir, "not_a_dir")
	if err := os.WriteFile(blockFile, []byte("block"), 0600); err != nil {
		t.Fatalf("failed to create block file: %v", err)
	}
	statePath := filepath.Join(blockFile, "state.json")

	probeL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer probeL.Close()

	probePort := probeL.Addr().(*net.TCPAddr).Port

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = probePort
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	sess := New(configPath, statePath)
	startErr := sess.Start(context.Background())
	if startErr == nil {
		t.Fatalf("expected error from sess.Start when state.Save fails, got nil")
	}

	if sess.IsActive() {
		t.Errorf("expected sess.IsActive() to be false after rollback")
	}

	cur, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("sysproxy.Current failed: %v", err)
	}
	if cur != nil && cur.Enabled {
		t.Errorf("expected sysproxy to be rolled back (disabled), got enabled")
	}
}

func TestSessionStop_StateSaveFailureReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	blockFile := filepath.Join(tmpDir, "not_a_dir")
	if err := os.WriteFile(blockFile, []byte("block"), 0600); err != nil {
		t.Fatalf("failed to create block file: %v", err)
	}
	statePath := filepath.Join(blockFile, "state.json")

	sess := New(configPath, statePath)
	sess.active = true

	stopErr := sess.Stop("user shutdown")
	if stopErr == nil {
		t.Fatalf("expected error from sess.Stop when state.Save fails, got nil")
	}
}

func TestStopActiveSessionProcessNotTerminated(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	if err := sysproxy.Set("127.0.0.1:8080", "127.0.0.1:8081"); err != nil {
		t.Fatalf("sysproxy.Set failed: %v", err)
	}

	st := &state.State{
		ActiveSession: true,
		PID:           88888,
		Mode:          config.ModeSysproxy,
	}
	if err := state.Save(statePath, st); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	reset := SetProcessHooksForTest(
		func(pid int) bool { return pid == 88888 },
		func(pid int) error { return nil },
	)
	defer reset()

	err := StopActiveSession(statePath, "test off")
	if err == nil {
		t.Fatalf("expected error from StopActiveSession when process does not terminate, got nil")
	}
	if !strings.Contains(err.Error(), "процесс PID 88888 не завершился") {
		t.Errorf("expected error containing 'процесс PID 88888 не завершился', got: %v", err)
	}

	// Invariant: state must NOT be marked inactive
	savedSt, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	if !savedSt.ActiveSession {
		t.Errorf("expected ActiveSession to remain true when process did not terminate")
	}
	if savedSt.PID != 88888 {
		t.Errorf("expected PID to remain 88888, got: %d", savedSt.PID)
	}

	// Invariant: sysproxy must NOT be unset
	cur, err := sysproxy.Current()
	if err != nil {
		t.Fatalf("sysproxy.Current failed: %v", err)
	}
	if cur == nil || !cur.Enabled {
		t.Errorf("expected sysproxy to remain enabled when process did not terminate")
	}
}

func TestSessionStart_TakeSnapshotFailureAborts(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	// Set GOSTPX_SYSPROXY_DRY to a directory so TakeSnapshot fails
	t.Setenv("GOSTPX_SYSPROXY_DRY", tmpDir)

	probeSrv, err := testupstream.Start()
	if err != nil {
		t.Fatalf("testupstream error: %v", err)
	}
	defer probeSrv.Close()

	probePort := probeSrv.Port()

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = probePort
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("config.Save failed: %v", err)
	}

	sess := New(configPath, statePath)
	err = sess.Start(context.Background())
	if err == nil {
		sess.Stop("cleanup")
		t.Fatalf("expected sess.Start to fail when TakeSnapshot fails, got nil")
	}
	if !strings.Contains(err.Error(), "take system proxy snapshot") {
		t.Errorf("expected error mentioning 'take system proxy snapshot', got: %v", err)
	}
	if sess.IsActive() {
		t.Errorf("expected session to remain inactive after snapshot failure")
	}
}

func TestStopActiveSession_PreservesStateOnUnsetFailure(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	snap := &sysproxy.Snapshot{
		Dry: &sysproxy.Status{
			Enabled:  true,
			HTTPHost: "1.2.3.4",
			HTTPPort: 8888,
		},
	}
	st := &state.State{
		ActiveSession:    true,
		PID:              999999,
		SysproxySnapshot: snap,
	}
	if err := state.Save(statePath, st); err != nil {
		t.Fatal(err)
	}

	// Make sysproxy.Unset fail by pointing dry path to a directory
	t.Setenv("GOSTPX_SYSPROXY_DRY", tmpDir)

	err := StopActiveSession(statePath, "test reason")
	if err == nil {
		t.Fatalf("expected StopActiveSession to fail when sysproxy.Unset fails")
	}

	// Invariant: state must NOT be wiped; SysproxySnapshot must remain intact
	savedSt, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !savedSt.ActiveSession {
		t.Errorf("expected ActiveSession to remain true when Unset fails")
	}
	if savedSt.SysproxySnapshot == nil {
		t.Errorf("expected SysproxySnapshot to be preserved when Unset fails")
	}
}

func TestMonitorEngineEvents_PreservesSnapshotOnUnsetFailure(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	dryFile := filepath.Join(tmpDir, "dry.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryFile)

	probeSrv, err := testupstream.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer probeSrv.Close()
	probePort := probeSrv.Port()

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
	cfg.Proxy.Port = probePort
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	cfg.Health.ProbeInterval = "20ms"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	if err := sess.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Make dry file unwriteable (directory) before disconnect triggers
	_ = os.Remove(dryFile)
	_ = os.Mkdir(dryFile, 0755)

	// Close probe server so engine encounters disconnect event
	_ = probeSrv.Close()

	// Wait for disconnect event
	evCh := sess.Events()
	var recEv Event
	for ev := range evCh {
		if ev.Type == EventDisconnected {
			recEv = ev
			break
		}
	}
	if recEv.Type != EventDisconnected {
		t.Fatalf("expected EventDisconnected")
	}

	// State must preserve snapshot and record error in LastDisconnectReason
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.SysproxySnapshot == nil {
		t.Errorf("expected SysproxySnapshot to be preserved when Unset failed on disconnect")
	}
	if !strings.Contains(st.LastDisconnectReason, "ошибка снятия прокси") {
		t.Errorf("expected LastDisconnectReason to record unset error, got: %s", st.LastDisconnectReason)
	}
}

func TestSession_RestartPending(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	initialCfg := config.DefaultConfig()
	initialCfg.Proxy.Host = "1.2.3.4"
	initialCfg.Proxy.Port = 1080
	initialCfg.Health.ProbeInterval = "30s"
	_ = config.Save(configPath, initialCfg)
	_ = config.SavePassword(config.CredentialsPath(configPath), "pass1")

	sess := New(configPath, statePath)
	sess.active = true
	sess.cfg = initialCfg
	sess.plainSecret = "pass1"

	// 1. Changing [health] does not require restart -> RestartPending remains false
	healthCfg := *initialCfg
	healthCfg.Health.ProbeInterval = "10s"
	sess.handleConfigReload(&healthCfg, false)

	if sess.RestartPending() {
		t.Errorf("expected RestartPending=false after [health] change, got true")
	}
	if sess.Config().Health.ProbeInterval != "10s" {
		t.Errorf("expected active config to be updated for [health], got: %v", sess.Config().Health.ProbeInterval)
	}

	// 2. Changing [proxy] requires restart -> RestartPending becomes true
	proxyCfg := healthCfg
	proxyCfg.Proxy.Host = "5.6.7.8"
	sess.handleConfigReload(&proxyCfg, true)

	if !sess.RestartPending() {
		t.Errorf("expected RestartPending=true after [proxy] change, got false")
	}
	// Active config must remain the old one
	if sess.Config().Proxy.Host != "1.2.3.4" {
		t.Errorf("expected active config to retain old proxy host 1.2.3.4, got: %s", sess.Config().Proxy.Host)
	}
	if sess.PendingConfig().Proxy.Host != "5.6.7.8" {
		t.Errorf("expected pending config to have new proxy host 5.6.7.8, got: %s", sess.PendingConfig().Proxy.Host)
	}
}

func TestSession_RestartPreservesSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")
	dryFile := filepath.Join(tmpDir, "dry.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryFile)

	srv1, err := testupstream.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer srv1.Close()

	srv2, err := testupstream.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()

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

	// Initial config with srv1
	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = srv1.Port()
	cfg.Proxy.Type = config.ProxyTypeSOCKS5
	cfg.Sysproxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg.Sysproxy.SOCKSListen = fmt.Sprintf("127.0.0.1:%d", socksPort)
	_ = config.Save(configPath, cfg)

	// Save pre-existing system proxy settings in dryFile representing user's original network settings
	initialDryState := `{"enabled":true,"http_host":"192.168.1.50","http_port":3128}`
	if err := os.WriteFile(dryFile, []byte(initialDryState), 0644); err != nil {
		t.Fatal(err)
	}

	sess := New(configPath, statePath)
	if err := sess.Start(context.Background()); err != nil {
		t.Fatalf("sess.Start failed: %v", err)
	}
	defer sess.Stop("cleanup")

	// Change config to srv2
	cfg.Proxy.Port = srv2.Port()
	_ = config.Save(configPath, cfg)
	sess.handleConfigReload(cfg, true)

	if !sess.RestartPending() {
		t.Fatalf("expected RestartPending=true")
	}

	// Perform Restart
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sess.Restart(ctx); err != nil {
		t.Fatalf("sess.Restart failed: %v", err)
	}

	if sess.RestartPending() {
		t.Errorf("expected RestartPending=false after Restart")
	}
	if sess.Config().Proxy.Port != srv2.Port() {
		t.Errorf("expected active config to point to srv2 port %d, got: %d", srv2.Port(), sess.Config().Proxy.Port)
	}

	// Verify state.json still preserves the original preSnapshot (ADR-015)
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.SysproxySnapshot == nil || st.SysproxySnapshot.Dry == nil || st.SysproxySnapshot.Dry.HTTPHost != "192.168.1.50" {
		t.Errorf("original snapshot lost or corrupted after Restart: %+v", st.SysproxySnapshot)
	}
}
