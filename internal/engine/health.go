package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

const (
	// ProbeTargetHost is the destination host used to verify upstream CONNECT tunneling.
	ProbeTargetHost = "1.1.1.1"
	// ProbeTargetPort is the destination port used to verify upstream CONNECT tunneling.
	ProbeTargetPort = 443
)

// VerifyUpstream performs a full proxy connection and handshake to the control target
// (ProbeTargetHost:ProbeTargetPort) to verify upstream reachability, protocol validity,
// authentication, and external tunneling capability.
// Returned errors wrap ErrUpstreamUnreachable, ErrAuthFailed, ErrInvalidProtocol, or ErrTargetUnreachable,
// with all credentials masked via SanitizeError.
func VerifyUpstream(ctx context.Context, cfg config.ProxyConfig, plainSecret string, timeout time.Duration) (time.Duration, error) {
	if cfg.Host == "" || cfg.Port <= 0 {
		return 0, errors.New("хост или порт прокси не указаны")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer, err := NewDirectDialer(cfg, plainSecret)
	if err != nil {
		return 0, SanitizeError(err, plainSecret)
	}
	dialer.timeout = timeout
	defer dialer.Close()

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialTarget(probeCtx, ProbeTargetHost, ProbeTargetPort)
	rtt := time.Since(start)

	if err != nil {
		return 0, SanitizeError(err, plainSecret)
	}
	_ = conn.Close()

	return rtt, nil
}

// CheckProxy performs a cheap in-process TCP dial to the proxy server
// to measure round-trip time (RTT) without spawning external processes (ARCHITECTURE.md §8).
func CheckProxy(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{
		Timeout: timeout,
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("probe %s: %w", addr, err)
	}
	defer conn.Close()

	rtt := time.Since(start)
	return rtt, nil
}
