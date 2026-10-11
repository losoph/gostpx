package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/testupstream"
)

func TestVerifyUpstream_SOCKS5_Success(t *testing.T) {
	srv, err := testupstream.StartWithOptions(testupstream.Options{
		Type:     "socks5",
		Username: "testuser",
		Password: "secretpassword",
	})
	if err != nil {
		t.Fatalf("failed to start testupstream: %v", err)
	}
	defer srv.Close()

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: srv.Port(),
		User: "testuser",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rtt, err := VerifyUpstream(ctx, cfg, "secretpassword", 2*time.Second)
	if err != nil {
		t.Fatalf("expected VerifyUpstream success, got error: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("expected positive RTT, got %v", rtt)
	}
}

func TestVerifyUpstream_SOCKS5_WrongPassword(t *testing.T) {
	srv, err := testupstream.StartWithOptions(testupstream.Options{
		Type:     "socks5",
		Username: "testuser",
		Password: "secretpassword",
	})
	if err != nil {
		t.Fatalf("failed to start testupstream: %v", err)
	}
	defer srv.Close()

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: srv.Port(),
		User: "testuser",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "wrongpassword", 2*time.Second)
	if err == nil {
		t.Fatalf("expected error on wrong password, got nil")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected error to wrap ErrAuthFailed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "отказ в авторизации") && !strings.Contains(err.Error(), "неверный логин или пароль") {
		t.Errorf("expected Russian auth failure message, got: %v", err)
	}
	// Verify password is not leaked in error message
	if strings.Contains(err.Error(), "wrongpassword") {
		t.Errorf("password leaked in error message: %v", err)
	}
}

func TestVerifyUpstream_HTTP_Success(t *testing.T) {
	srv, err := testupstream.StartWithOptions(testupstream.Options{
		Type:     "http",
		Username: "httpuser",
		Password: "httppassword",
	})
	if err != nil {
		t.Fatalf("failed to start testupstream: %v", err)
	}
	defer srv.Close()

	cfg := config.ProxyConfig{
		Type: "http",
		Host: "127.0.0.1",
		Port: srv.Port(),
		User: "httpuser",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rtt, err := VerifyUpstream(ctx, cfg, "httppassword", 2*time.Second)
	if err != nil {
		t.Fatalf("expected VerifyUpstream success, got error: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("expected positive RTT, got %v", rtt)
	}
}

func TestVerifyUpstream_HTTP_WrongPassword(t *testing.T) {
	srv, err := testupstream.StartWithOptions(testupstream.Options{
		Type:     "http",
		Username: "httpuser",
		Password: "httppassword",
	})
	if err != nil {
		t.Fatalf("failed to start testupstream: %v", err)
	}
	defer srv.Close()

	cfg := config.ProxyConfig{
		Type: "http",
		Host: "127.0.0.1",
		Port: srv.Port(),
		User: "httpuser",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "wronghttppassword", 2*time.Second)
	if err == nil {
		t.Fatalf("expected error on wrong password, got nil")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected error to wrap ErrAuthFailed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "407") && !strings.Contains(err.Error(), "авторизац") {
		t.Errorf("expected Russian auth failure message or 407, got: %v", err)
	}
	if strings.Contains(err.Error(), "wronghttppassword") {
		t.Errorf("password leaked in error message: %v", err)
	}
}

func TestVerifyUpstream_InvalidProtocol(t *testing.T) {
	// Start HTTP server, but configure client as SOCKS5
	srv, err := testupstream.StartWithOptions(testupstream.Options{
		Type: "http",
	})
	if err != nil {
		t.Fatalf("failed to start testupstream: %v", err)
	}
	defer srv.Close()

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: srv.Port(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "", 2*time.Second)
	if err == nil {
		t.Fatalf("expected error on mismatched protocol, got nil")
	}
	if !errors.Is(err, ErrInvalidProtocol) {
		t.Errorf("expected error to wrap ErrInvalidProtocol, got: %v", err)
	}
	if !strings.Contains(err.Error(), "отвечает как HTTP-прокси") && !strings.Contains(err.Error(), "протокол") && !strings.Contains(err.Error(), "верси") {
		t.Errorf("expected protocol error message, got: %v", err)
	}
}

func TestVerifyUpstream_UnreachablePort(t *testing.T) {
	// Find a free closed port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close() // immediately close to make it unreachable

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "", 2*time.Second)
	if err == nil {
		t.Fatalf("expected error on unreachable port, got nil")
	}
	if !errors.Is(err, ErrUpstreamUnreachable) {
		t.Errorf("expected error to wrap ErrUpstreamUnreachable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "недоступен") {
		t.Errorf("expected unreachable message, got: %v", err)
	}
}

func TestVerifyUpstream_SOCKS5_RuleForbidden0x02(t *testing.T) {
	// Mock SOCKS5 server that succeeds greeting & auth, but returns 0x02 on CONNECT
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer server.Close()

	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// 1. Read greeting
		buf := make([]byte, 128)
		if _, err := io.ReadAtLeast(conn, buf, 3); err != nil {
			return
		}
		// Method 0x00 (No auth)
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		// 2. Read CONNECT request
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			return
		}

		// 3. Respond with 0x02 (connection not allowed by ruleset)
		resp := []byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		_, _ = conn.Write(resp)
	}()

	serverPort := server.Addr().(*net.TCPAddr).Port
	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: serverPort,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "", 2*time.Second)
	if err == nil {
		t.Fatalf("expected error from VerifyUpstream on 0x02, got nil")
	}

	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected error to wrap ErrAuthFailed, got: %v", err)
	}
	if errors.Is(err, ErrCredentialsRejected) {
		t.Errorf("expected error NOT to be ErrCredentialsRejected, got: %v", err)
	}
	if !strings.Contains(err.Error(), "0x02") {
		t.Errorf("expected error text to mention '0x02', got: %v", err)
	}
	if !strings.Contains(err.Error(), "проверьте логин и пароль") {
		t.Errorf("expected error text to mention 'проверьте логин и пароль', got: %v", err)
	}
}
