package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

// Test 1: 50 iterations of concurrent Start() and Stop() on the same Engine
// (on test ports 127.0.0.1:0) under -race:
// - no panic
// - no deadlock (overall test watchdog 20s)
// - no goroutine leak
// - after final Stop(), listeners are closed.
func TestLifecycle_ConcurrentStartStop_50Iterations(t *testing.T) {
	done := make(chan struct{})
	timer := time.AfterFunc(20*time.Second, func() {
		panic("TestLifecycle_ConcurrentStartStop_50Iterations exceeded 20s watchdog (deadlock detected)")
	})
	defer timer.Stop()

	baselineGoroutines := runtime.NumGoroutine()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return nil, errors.New("no upstream")
		},
	}

	var lastHTTPListener net.Listener
	var lastSOCKSListener net.Listener

	for i := 0; i < 50; i++ {
		var wg sync.WaitGroup
		barrier := make(chan struct{})
		wg.Add(2)

		go func() {
			defer wg.Done()
			<-barrier
			_ = eng.Start()
		}()

		go func() {
			defer wg.Done()
			<-barrier
			_ = eng.Stop()
		}()

		close(barrier)
		wg.Wait()

		eng.mu.RLock()
		if eng.httpListener != nil {
			lastHTTPListener = eng.httpListener
		}
		if eng.socksListener != nil {
			lastSOCKSListener = eng.socksListener
		}
		eng.mu.RUnlock()
	}

	// Ensure engine was started at least once and we captured its listeners.
	if lastHTTPListener == nil || lastSOCKSListener == nil {
		if err := eng.Start(); err != nil && err.Error() != "engine is already running" {
			t.Fatalf("Start error: %v", err)
		}
		eng.mu.RLock()
		lastHTTPListener = eng.httpListener
		lastSOCKSListener = eng.socksListener
		eng.mu.RUnlock()
	}

	// Final Stop() to ensure engine is cleanly stopped.
	if err := eng.Stop(); err != nil {
		t.Fatalf("final Stop error: %v", err)
	}

	// Internal state assertions
	eng.mu.RLock()
	running := eng.running
	httpL := eng.httpListener
	socksL := eng.socksListener
	eng.mu.RUnlock()

	if running {
		t.Fatal("expected eng.running == false after final Stop()")
	}
	if httpL != nil {
		t.Fatal("expected eng.httpListener == nil after final Stop()")
	}
	if socksL != nil {
		t.Fatal("expected eng.socksListener == nil after final Stop()")
	}

	// Assert that recorded listeners are truly closed
	if lastHTTPListener != nil {
		_, err := lastHTTPListener.Accept()
		if err == nil {
			t.Fatal("expected lastHTTPListener.Accept() to fail, got nil")
		}
		if !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "closed") {
			t.Fatalf("expected ErrClosed for lastHTTPListener, got %v", err)
		}
	}
	if lastSOCKSListener != nil {
		_, err := lastSOCKSListener.Accept()
		if err == nil {
			t.Fatal("expected lastSOCKSListener.Accept() to fail, got nil")
		}
		if !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "closed") {
			t.Fatalf("expected ErrClosed for lastSOCKSListener, got %v", err)
		}
	}

	// Goroutine leak check: wait up to 2 seconds for goroutines to settle
	deadline := time.Now().Add(2 * time.Second)
	var finalGoroutines int
	for time.Now().Before(deadline) {
		finalGoroutines = runtime.NumGoroutine()
		if finalGoroutines <= baselineGoroutines+4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if finalGoroutines > baselineGoroutines+4 {
		t.Fatalf("goroutine leak detected: baseline %d, final %d", baselineGoroutines, finalGoroutines)
	}

	close(done)
}

// Test 2: Stop() -> Start() -> CONNECT-туннель нового запуска живёт после завершения прежнего Stop()
// (то есть tunnelsClosed не остался true).
func TestLifecycle_StopStart_TunnelSurvives(t *testing.T) {
	echoL, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.DialTimeout("tcp", echoL.Addr().String(), 2*time.Second)
		},
	}

	// 1. Generation 1 starts
	if err := eng.Start(); err != nil {
		t.Fatalf("gen 1 Start error: %v", err)
	}

	c1, r1 := connectHTTP(t, eng.httpListener.Addr().String(), "target.upstream:443")
	if _, err := c1.Write([]byte("gen1-hello\n")); err != nil {
		t.Fatalf("write c1: %v", err)
	}
	buf1 := make([]byte, len("gen1-hello\n"))
	if _, err := io.ReadFull(r1, buf1); err != nil {
		t.Fatalf("read c1: %v", err)
	}
	if string(buf1) != "gen1-hello\n" {
		t.Fatalf("unexpected echo gen1: %s", string(buf1))
	}
	if active := eng.ActiveTunnels(); active != 1 {
		t.Fatalf("expected 1 active tunnel in gen 1, got %d", active)
	}

	// 2. Generation 1 stops
	if err := eng.Stop(); err != nil {
		t.Fatalf("gen 1 Stop error: %v", err)
	}
	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active tunnels after gen 1 Stop, got %d", active)
	}

	// 3. Generation 2 starts
	if err := eng.Start(); err != nil {
		t.Fatalf("gen 2 Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	eng.tunnelsMu.Lock()
	tunnelsClosed := eng.tunnelsClosed
	eng.tunnelsMu.Unlock()
	if tunnelsClosed {
		t.Fatal("expected tunnelsClosed == false after Start(), but was true")
	}

	// 4. Generation 2 CONNECT tunnel connects and stays alive
	c2, r2 := connectHTTP(t, eng.httpListener.Addr().String(), "target.upstream:443")
	defer c2.Close()

	if _, err := c2.Write([]byte("gen2-first\n")); err != nil {
		t.Fatalf("write c2 first: %v", err)
	}
	buf2 := make([]byte, len("gen2-first\n"))
	if _, err := io.ReadFull(r2, buf2); err != nil {
		t.Fatalf("read c2 first: %v", err)
	}
	if string(buf2) != "gen2-first\n" {
		t.Fatalf("unexpected echo gen2 first: %s", string(buf2))
	}

	if active := eng.ActiveTunnels(); active != 1 {
		t.Fatalf("expected 1 active tunnel in gen 2, got %d", active)
	}

	// Wait and send another packet to verify the tunnel didn't get killed
	time.Sleep(100 * time.Millisecond)

	if _, err := c2.Write([]byte("gen2-second\n")); err != nil {
		t.Fatalf("write c2 second: %v", err)
	}
	buf3 := make([]byte, len("gen2-second\n"))
	if _, err := io.ReadFull(r2, buf3); err != nil {
		t.Fatalf("read c2 second (tunnel died unexpectedly): %v", err)
	}
	if string(buf3) != "gen2-second\n" {
		t.Fatalf("unexpected echo gen2 second: %s", string(buf3))
	}

	if active := eng.ActiveTunnels(); active != 1 {
		t.Fatalf("expected 1 active tunnel in gen 2 after second packet, got %d", active)
	}
}

// Test 3: Concurrent Stop() and Start() where Start() competes with Stop() on the same Engine
// while a tunnel is being stopped. The tunnel on the new generation survives.
func TestLifecycle_ConcurrentStopStart_TunnelSurvives(t *testing.T) {
	echoL, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.DialTimeout("tcp", echoL.Addr().String(), 2*time.Second)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("initial Start: %v", err)
	}

	c1, r1 := connectHTTP(t, eng.httpListener.Addr().String(), "target.upstream:443")
	defer c1.Close()
	if _, err := c1.Write([]byte("init\n")); err != nil {
		t.Fatalf("write init: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(r1, buf); err != nil {
		t.Fatalf("read init: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	barrier := make(chan struct{})

	go func() {
		defer wg.Done()
		<-barrier
		_ = eng.Stop()
	}()

	var startErr error
	go func() {
		defer wg.Done()
		<-barrier
		// Retry Start() until it starts (since it may encounter "engine is already running" if scheduled before Stop)
		for {
			err := eng.Start()
			if err == nil {
				startErr = nil
				return
			}
			if err.Error() == "engine is already running" {
				time.Sleep(1 * time.Millisecond)
				continue
			}
			startErr = err
			return
		}
	}()

	close(barrier)
	wg.Wait()

	if startErr != nil {
		t.Fatalf("Start failed: %v", startErr)
	}
	defer func() { _ = eng.Stop() }()

	eng.tunnelsMu.Lock()
	tunnelsClosed := eng.tunnelsClosed
	eng.tunnelsMu.Unlock()
	if tunnelsClosed {
		t.Fatal("tunnelsClosed is true on new generation")
	}

	// Tunnel on new generation must work and survive
	c2, r2 := connectHTTP(t, eng.httpListener.Addr().String(), "target.upstream:443")
	defer c2.Close()

	if _, err := c2.Write([]byte("survivor\n")); err != nil {
		t.Fatalf("write survivor: %v", err)
	}
	survBuf := make([]byte, len("survivor\n"))
	if _, err := io.ReadFull(r2, survBuf); err != nil {
		t.Fatalf("read survivor: %v", err)
	}
	if string(survBuf) != "survivor\n" {
		t.Fatalf("unexpected echo: %s", string(survBuf))
	}

	time.Sleep(100 * time.Millisecond)
	if active := eng.ActiveTunnels(); active != 1 {
		t.Fatalf("expected 1 active tunnel, got %d", active)
	}
}
