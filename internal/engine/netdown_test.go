package engine

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

func TestLocalNetworkDown_ErrorMatching(t *testing.T) {
	if !isNetworkDownError(syscall.ENETUNREACH) {
		t.Errorf("expected ENETUNREACH to be network down error")
	}
	if !isNetworkDownError(syscall.EHOSTUNREACH) {
		t.Errorf("expected EHOSTUNREACH to be network down error")
	}
	if !isNetworkDownError(syscall.ENETDOWN) {
		t.Errorf("expected ENETDOWN to be network down error")
	}

	wrapped := errors.Join(errors.New("dial failed"), syscall.ENETUNREACH)
	if !isNetworkDownError(wrapped) {
		t.Errorf("expected wrapped ENETUNREACH to be network down error")
	}

	if isNetworkDownError(errors.New("i/o timeout")) {
		t.Errorf("i/o timeout alone must NOT be treated as network down error")
	}
	if isNetworkDownError(context.DeadlineExceeded) {
		t.Errorf("DeadlineExceeded must NOT be treated as network down error")
	}
	if isNetworkDownError(nil) {
		t.Errorf("nil must NOT be treated as network down error")
	}
}

func TestEngine_NetworkDown_ProbeBehavior(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999
	cfg.Health.ProbeInterval = "25ms"

	eng, err := New(cfg, "")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	eng.dialer = &mockDialer{}
	eng.SetProbeParams(3, 10*time.Millisecond, 30*time.Millisecond)

	// Step 1: Initial checkProxy succeeds
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer eng.Stop()

	// Drain initial events
	time.Sleep(50 * time.Millisecond)

	// Step 2: Simulate local network down
	netDownErr := syscall.ENETUNREACH
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return 0, netDownErr
	})
	eng.SetLocalNetworkDown(func(err error) bool {
		return true
	})

	// Wait and monitor events: should see EventNetworkDown, but NOT EventDisconnected
	receivedNetDown := false
	timer := time.After(200 * time.Millisecond)
loop1:
	for {
		select {
		case evt := <-eng.Events():
			if evt.Type == EventNetworkDown {
				receivedNetDown = true
			}
			if evt.Type == EventDisconnected {
				t.Fatalf("unexpected EventDisconnected when network is down!")
			}
		case <-timer:
			break loop1
		}
	}

	if !receivedNetDown {
		t.Fatalf("expected EventNetworkDown event was not received")
	}

	// Engine should still be running and not disconnected
	if !eng.Status().Connected {
		t.Errorf("engine status Connected should remain true while waiting for network")
	}

	// Step 3: Network comes back up, probe succeeds
	eng.SetLocalNetworkDown(func(err error) bool {
		return false
	})
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return 8 * time.Millisecond, nil
	})

	receivedNetUp := false
	timer2 := time.After(200 * time.Millisecond)
loop2:
	for {
		select {
		case evt := <-eng.Events():
			if evt.Type == EventNetworkUp {
				receivedNetUp = true
			}
			if evt.Type == EventDisconnected {
				t.Fatalf("unexpected EventDisconnected on recovery")
			}
		case <-timer2:
			break loop2
		}
	}

	if !receivedNetUp {
		t.Fatalf("expected EventNetworkUp event was not received")
	}

	// Step 4: Upstream dies while network is up -> should disconnect after retries
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("upstream connection refused")
	})

	receivedDisconnect := false
	timer3 := time.After(300 * time.Millisecond)
loop3:
	for {
		select {
		case evt := <-eng.Events():
			if evt.Type == EventDisconnected {
				receivedDisconnect = true
				break loop3
			}
		case <-timer3:
			break loop3
		}
	}

	if !receivedDisconnect {
		t.Fatalf("expected EventDisconnected when network is up and upstream is dead")
	}
}
