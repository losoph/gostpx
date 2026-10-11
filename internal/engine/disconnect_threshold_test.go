package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

// TestEngine_ProbeLoop_RetriesBeforeDisconnect verifies that a single failed probe
// while the upstream is alive does not cause EventDisconnected, but 3 consecutive
// failed probes trigger EventDisconnected with the human-readable Russian reason.
func TestEngine_ProbeLoop_RetriesBeforeDisconnect(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999
	cfg.Health.ProbeInterval = "20ms"

	eng, err := New(cfg, "")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	eng.dialer = &mockDialer{}
	eng.SetProbeParams(3, 15*time.Millisecond, 50*time.Millisecond)

	// Step 1: Initial start probe succeeds
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	// Drain initial EventConnected
	select {
	case evt := <-eng.Events():
		if evt.Type != EventConnected {
			t.Fatalf("expected EventConnected, got: %+v", evt)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial EventConnected")
	}

	// Step 2: One probe failure followed by successful probes -> NO disconnect event
	attempts := &atomic.Int32{}
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		n := attempts.Add(1)
		if n == 1 {
			return 0, errors.New("temporary glitch 1")
		}
		return 5 * time.Millisecond, nil
	})

	time.Sleep(100 * time.Millisecond)

	// Invariant: Status must remain Connected=true, no EventDisconnected
	if !eng.Status().Connected {
		t.Errorf("expected engine to remain Connected after 1 probe failure, got disconnected: %s", eng.Status().LastDisconnectReason)
	}
	select {
	case evt := <-eng.Events():
		t.Fatalf("unexpected event after single probe failure: %+v", evt)
	default:
	}

	// Step 3: Three consecutive probe failures -> EventDisconnected MUST be emitted
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("upstream unreachable network down")
	})

	var disconnEvt Event
	select {
	case evt := <-eng.Events():
		if evt.Type == EventDisconnected {
			disconnEvt = evt
		} else {
			t.Fatalf("expected EventDisconnected, got: %+v", evt)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for EventDisconnected after 3 failed probes")
	}

	if !strings.Contains(disconnEvt.Reason, "прокси не отвечает (3 проверки подряд):") {
		t.Errorf("expected reason to contain 'прокси не отвечает (3 проверки подряд):', got: %q", disconnEvt.Reason)
	}
	if !strings.Contains(disconnEvt.Reason, "upstream unreachable network down") {
		t.Errorf("expected reason to contain 'upstream unreachable network down', got: %q", disconnEvt.Reason)
	}

	if eng.Status().Connected {
		t.Errorf("expected engine status Connected=false after 3 failed probes")
	}
}

// TestEngine_RecordDialFailure_IgnoresTargetUnreachable verifies that ErrTargetUnreachable
// and ErrAuthFailed without ErrCredentialsRejected (e.g. SOCKS5 0x02 or HTTP 403 on a specific target)
// do not increment consecutiveErrors or cause disconnect, while ErrCredentialsRejected disconnects immediately.
func TestEngine_RecordDialFailure_IgnoresTargetUnreachable(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19998
	cfg.Health.ProbeInterval = "10s" // long probe interval so probeLoop doesn't interfere

	eng, err := New(cfg, "")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	eng.SetProbeParams(3, 10*time.Millisecond, 50*time.Millisecond)

	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})

	var dialErr atomic.Pointer[error]
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			if ptr := dialErr.Load(); ptr != nil {
				return nil, *ptr
			}
			return nil, errors.New("default dial error")
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	// Drain initial EventConnected
	select {
	case <-eng.Events():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial EventConnected")
	}

	// 1. ErrTargetUnreachable: send 5 requests through HTTP proxy
	targetErr := fmt.Errorf("%w: узел недоступен (0x04)", ErrTargetUnreachable)
	dialErr.Store(&targetErr)

	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", eng.httpListener.Addr().String())
		if err != nil {
			t.Fatalf("dial http listener failed: %v", err)
		}
		reqStr := "CONNECT target.example.com:443 HTTP/1.1\r\nHost: target.example.com:443\r\n\r\n"
		_, _ = conn.Write([]byte(reqStr))
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}

	// Invariant: consecutiveErrors must remain 0, no disconnect
	if count := eng.consecutiveErrors.Load(); count != 0 {
		t.Errorf("expected consecutiveErrors=0 for ErrTargetUnreachable, got: %d", count)
	}
	if !eng.Status().Connected {
		t.Errorf("expected engine to remain Connected for ErrTargetUnreachable")
	}
	select {
	case evt := <-eng.Events():
		t.Fatalf("unexpected event for ErrTargetUnreachable: %+v", evt)
	default:
	}

	// 2. SOCKS5 0x02 and HTTP 403 (ErrAuthFailed without ErrCredentialsRejected):
	// Must NOT disconnect and must NOT increment consecutiveErrors (Task E)
	ruleErr := fmt.Errorf("%w: соединение запрещено правилами прокси (0x02) — проверьте логин и пароль", ErrAuthFailed)
	dialErr.Store(&ruleErr)

	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", eng.httpListener.Addr().String())
		if err != nil {
			t.Fatalf("dial http listener failed: %v", err)
		}
		reqStr := "CONNECT rule.example.com:443 HTTP/1.1\r\nHost: rule.example.com:443\r\n\r\n"
		_, _ = conn.Write([]byte(reqStr))
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}

	if count := eng.consecutiveErrors.Load(); count != 0 {
		t.Errorf("expected consecutiveErrors=0 for 0x02 rule error, got: %d", count)
	}
	if !eng.Status().Connected {
		t.Errorf("expected engine to remain Connected for 0x02 rule error")
	}
	select {
	case evt := <-eng.Events():
		t.Fatalf("unexpected event for 0x02 rule error: %+v", evt)
	default:
	}

	http403Err := fmt.Errorf("%w: HTTP 403 Forbidden (доступ к прокси запрещён)", ErrAuthFailed)
	dialErr.Store(&http403Err)

	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", eng.httpListener.Addr().String())
		if err != nil {
			t.Fatalf("dial http listener failed: %v", err)
		}
		reqStr := "CONNECT forbidden.example.com:443 HTTP/1.1\r\nHost: forbidden.example.com:443\r\n\r\n"
		_, _ = conn.Write([]byte(reqStr))
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}

	if count := eng.consecutiveErrors.Load(); count != 0 {
		t.Errorf("expected consecutiveErrors=0 for HTTP 403, got: %d", count)
	}
	if !eng.Status().Connected {
		t.Errorf("expected engine to remain Connected for HTTP 403")
	}
	select {
	case evt := <-eng.Events():
		t.Fatalf("unexpected event for HTTP 403: %+v", evt)
	default:
	}

	// 3. SOCKS5 subnegotiation auth rejection (ErrCredentialsRejected):
	// 1 request causes immediate disconnect with reason "отказ в авторизации"
	credErr := fmt.Errorf("%w: %w: неверный логин или пароль (код отказа 0x01)", ErrAuthFailed, ErrCredentialsRejected)
	dialErr.Store(&credErr)

	conn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial http listener failed: %v", err)
	}
	reqStr := "CONNECT auth.example.com:443 HTTP/1.1\r\nHost: auth.example.com:443\r\n\r\n"
	_, _ = conn.Write([]byte(reqStr))
	buf := make([]byte, 128)
	_, _ = conn.Read(buf)
	_ = conn.Close()

	var authEvt Event
	select {
	case evt := <-eng.Events():
		if evt.Type == EventDisconnected {
			authEvt = evt
		} else {
			t.Fatalf("expected EventDisconnected, got: %+v", evt)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for EventDisconnected on ErrCredentialsRejected")
	}

	if !strings.Contains(authEvt.Reason, "отказ в авторизации") {
		t.Errorf("expected reason to contain 'отказ в авторизации', got: %q", authEvt.Reason)
	}
	if !strings.Contains(authEvt.Reason, "неверный логин или пароль") {
		t.Errorf("expected reason to mention 'неверный логин или пароль', got: %q", authEvt.Reason)
	}
}

// TestEngine_RecordDialFailure_HTTP407_Disconnects verifies that HTTP 407 (ErrCredentialsRejected)
// triggers an immediate disconnect.
func TestEngine_RecordDialFailure_HTTP407_Disconnects(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19997
	cfg.Health.ProbeInterval = "10s"

	eng, err := New(cfg, "")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})

	var dialErr atomic.Pointer[error]
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			if ptr := dialErr.Load(); ptr != nil {
				return nil, *ptr
			}
			return nil, errors.New("default dial error")
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	// Drain initial EventConnected
	select {
	case <-eng.Events():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial EventConnected")
	}

	http407Err := fmt.Errorf("%w: %w: HTTP 407 Proxy Authentication Required (требуется авторизация или неверный логин/пароль)", ErrAuthFailed, ErrCredentialsRejected)
	dialErr.Store(&http407Err)

	conn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial http listener failed: %v", err)
	}
	reqStr := "CONNECT http407.example.com:443 HTTP/1.1\r\nHost: http407.example.com:443\r\n\r\n"
	_, _ = conn.Write([]byte(reqStr))
	buf := make([]byte, 128)
	_, _ = conn.Read(buf)
	_ = conn.Close()

	var authEvt Event
	select {
	case evt := <-eng.Events():
		if evt.Type == EventDisconnected {
			authEvt = evt
		} else {
			t.Fatalf("expected EventDisconnected, got: %+v", evt)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for EventDisconnected on HTTP 407 ErrCredentialsRejected")
	}

	if !strings.Contains(authEvt.Reason, "отказ в авторизации") {
		t.Errorf("expected reason to contain 'отказ в авторизации', got: %q", authEvt.Reason)
	}
	if !strings.Contains(authEvt.Reason, "HTTP 407") {
		t.Errorf("expected reason to mention 'HTTP 407', got: %q", authEvt.Reason)
	}
}
