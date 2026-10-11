package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

const (
	// ProbeTargetHost is the destination host used to verify upstream CONNECT tunneling.
	ProbeTargetHost = "1.1.1.1"
	// ProbeTargetPort is the destination port used to verify upstream CONNECT tunneling.
	ProbeTargetPort = 443
)

var (
	protocolProbeTimeout   = 3 * time.Second
	sshBannerDetectTimeout = 300 * time.Millisecond
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
		if shouldProbeProtocolMismatch(err) {
			if mismatchErr := probeProtocolMismatch(ctx, cfg); mismatchErr != nil {
				return 0, SanitizeError(mismatchErr, plainSecret)
			}
		}
		return 0, SanitizeError(err, plainSecret)
	}
	_ = conn.Close()

	return rtt, nil
}

func shouldProbeProtocolMismatch(err error) bool {
	if errors.Is(err, ErrUpstreamUnreachable) || errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrTargetUnreachable) {
		return false
	}
	if errors.Is(err, ErrInvalidProtocol) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

func formatProtocolMismatchMessage(addr string, detected, chosen string) string {
	var detectedDesc string
	var detectedType string
	switch strings.ToLower(detected) {
	case config.ProxyTypeHTTP:
		detectedDesc = "HTTP-прокси"
		detectedType = "HTTP"
	case config.ProxyTypeSOCKS5:
		detectedDesc = "SOCKS5-прокси"
		detectedType = "SOCKS5"
	case config.ProxyTypeSSH:
		detectedDesc = "SSH-сервер"
		detectedType = "SSH"
	default:
		detectedDesc = strings.ToUpper(detected)
		detectedType = strings.ToUpper(detected)
	}

	var chosenName string
	switch strings.ToLower(chosen) {
	case config.ProxyTypeHTTP:
		chosenName = "HTTP"
	case config.ProxyTypeSOCKS5:
		chosenName = "SOCKS5"
	case config.ProxyTypeSSH:
		chosenName = "SSH"
	default:
		chosenName = strings.ToUpper(chosen)
	}

	return fmt.Sprintf("сервер %s отвечает как %s, а выбран %s — выберите тип «%s» или узнайте у провайдера порт %s",
		addr, detectedDesc, chosenName, detectedType, chosenName)
}

func probeProtocolMismatch(ctx context.Context, cfg config.ProxyConfig) error {
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	probeCtx, cancel := context.WithTimeout(context.Background(), protocolProbeTimeout)
	defer cancel()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(protocolProbeTimeout))

	// Step 1: Check for unsolicited SSH banner in the first ~300ms before sending anything.
	_ = conn.SetReadDeadline(time.Now().Add(sshBannerDetectTimeout))
	bannerBuf := make([]byte, 64)
	n, readErr := conn.Read(bannerBuf)
	if n > 0 && strings.HasPrefix(string(bannerBuf[:n]), "SSH-") {
		if cfg.Type != config.ProxyTypeSSH {
			return &protocolMismatchErr{msg: formatProtocolMismatchMessage(addr, config.ProxyTypeSSH, cfg.Type)}
		}
		return nil
	}
	if readErr != nil {
		var netErr net.Error
		if !(errors.As(readErr, &netErr) && netErr.Timeout()) && !errors.Is(readErr, os.ErrDeadlineExceeded) {
			// Connection was closed or reset by server before any data
			return nil
		}
	}

	// Reset deadline for protocol-specific probe
	_ = conn.SetDeadline(time.Now().Add(protocolProbeTimeout))

	switch cfg.Type {
	case config.ProxyTypeSOCKS5:
		// Chosen socks5: send CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n, read up to 16 bytes.
		// Starts with HTTP/1. -> HTTP proxy.
		req := "CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return nil
		}
		buf := make([]byte, 16)
		var total int
		for total < len(buf) {
			nr, err := conn.Read(buf[total:])
			if nr > 0 {
				total += nr
				if total >= 7 && strings.HasPrefix(string(buf[:total]), "HTTP/1.") {
					return &protocolMismatchErr{msg: formatProtocolMismatchMessage(addr, config.ProxyTypeHTTP, cfg.Type)}
				}
			}
			if err != nil {
				break
			}
		}
		if total >= 7 && strings.HasPrefix(string(buf[:total]), "HTTP/1.") {
			return &protocolMismatchErr{msg: formatProtocolMismatchMessage(addr, config.ProxyTypeHTTP, cfg.Type)}
		}

	case config.ProxyTypeHTTP:
		// Chosen http: send SOCKS5 greeting 05 01 00, read 2 bytes; first byte 0x05 -> SOCKS5 proxy.
		greeting := []byte{0x05, 0x01, 0x00}
		if _, err := conn.Write(greeting); err != nil {
			return nil
		}
		buf := make([]byte, 2)
		nr, _ := io.ReadFull(conn, buf)
		// A SOCKS5 method reply is VER=0x05 plus a method: no auth, GSSAPI,
		// user/password, or "no acceptable" — anything else is not SOCKS5.
		if nr == 2 && buf[0] == 0x05 && (buf[1] <= 0x02 || buf[1] == 0xFF) {
			return &protocolMismatchErr{msg: formatProtocolMismatchMessage(addr, config.ProxyTypeSOCKS5, cfg.Type)}
		}

	case config.ProxyTypeSSH:
		// Chosen ssh, but server did not send SSH banner in 300ms.
		// Test if it responds as HTTP:
		req := "CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return nil
		}
		buf := make([]byte, 16)
		var total int
		for total < len(buf) {
			nr, err := conn.Read(buf[total:])
			if nr > 0 {
				total += nr
				if total >= 7 && strings.HasPrefix(string(buf[:total]), "HTTP/1.") {
					return &protocolMismatchErr{msg: formatProtocolMismatchMessage(addr, config.ProxyTypeHTTP, cfg.Type)}
				}
			}
			if err != nil {
				break
			}
		}
		if total >= 7 && strings.HasPrefix(string(buf[:total]), "HTTP/1.") {
			return &protocolMismatchErr{msg: formatProtocolMismatchMessage(addr, config.ProxyTypeHTTP, cfg.Type)}
		}
	}

	return nil
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
