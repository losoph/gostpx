package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/testupstream"
)

// 1. HTTP-сервер, молча ждущий конца запроса (как настоящий), выбран socks5 → текст про HTTP-прокси, errors.Is(..., ErrInvalidProtocol).
func TestVerifyUpstream_ProtocolMismatch_HTTP_SelectedSOCKS5(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				var total []byte
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					total = append(total, buf[:n]...)
					if strings.Contains(string(total), "\r\n\r\n") {
						// HTTP CONNECT probe received
						_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
						return
					}
					// If request does not contain \r\n\r\n (e.g. SOCKS5 greeting 05 01 00),
					// HTTP server silently waits for more data until client deadline.
				}
			}(conn)
		}
	}()

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: port,
	}

	// Short timeout so initial SOCKS5 handshake read times out quickly
	timeout := 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "", timeout)
	if err == nil {
		t.Fatalf("expected error on protocol mismatch, got nil")
	}

	if !errors.Is(err, ErrInvalidProtocol) {
		t.Errorf("expected errors.Is(err, ErrInvalidProtocol) == true, got false; err = %v", err)
	}
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Errorf("expected errors.Is(err, ErrProtocolMismatch) == true, got false; err = %v", err)
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "отвечает как HTTP-прокси") {
		t.Errorf("expected error to contain 'отвечает как HTTP-прокси', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "выбран SOCKS5") {
		t.Errorf("expected error to contain 'выбран SOCKS5', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "выберите тип «HTTP»") {
		t.Errorf("expected error to contain 'выберите тип «HTTP»', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "порт SOCKS5") {
		t.Errorf("expected error to contain 'порт SOCKS5', got: %q", errMsg)
	}
}

// 2. SOCKS5-сервер (на любой не-SOCKS5 первый байт закрывает, на 05 01 00 отвечает 05 00), выбран http → текст про SOCKS5.
func TestVerifyUpstream_ProtocolMismatch_SOCKS5_SelectedHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 16)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}
				if buf[0] != 0x05 {
					// Non-SOCKS5 byte (e.g. 'C' from HTTP CONNECT): close immediately
					return
				}
				// SOCKS5 greeting 05 01 00: reply 05 00 (NO_AUTH)
				_, _ = c.Write([]byte{0x05, 0x00})
			}(conn)
		}
	}()

	cfg := config.ProxyConfig{
		Type: "http",
		Host: "127.0.0.1",
		Port: port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "", 500*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error on protocol mismatch, got nil")
	}

	if !errors.Is(err, ErrInvalidProtocol) {
		t.Errorf("expected errors.Is(err, ErrInvalidProtocol) == true, got false; err = %v", err)
	}
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Errorf("expected errors.Is(err, ErrProtocolMismatch) == true, got false; err = %v", err)
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "отвечает как SOCKS5-прокси") {
		t.Errorf("expected error to contain 'отвечает как SOCKS5-прокси', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "выбран HTTP") {
		t.Errorf("expected error to contain 'выбран HTTP', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "выберите тип «SOCKS5»") {
		t.Errorf("expected error to contain 'выберите тип «SOCKS5»', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "порт HTTP") {
		t.Errorf("expected error to contain 'порт HTTP', got: %q", errMsg)
	}
}

// 3. Сервер, шлющий SSH-2.0-OpenSSH_9.0\r\n сразу после подключения, выбран socks5 → текст про SSH.
func TestVerifyUpstream_ProtocolMismatch_SSH_SelectedSOCKS5(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "", 500*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error on protocol mismatch, got nil")
	}

	if !errors.Is(err, ErrInvalidProtocol) {
		t.Errorf("expected errors.Is(err, ErrInvalidProtocol) == true, got false; err = %v", err)
	}
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Errorf("expected errors.Is(err, ErrProtocolMismatch) == true, got false; err = %v", err)
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "отвечает как SSH-сервер") {
		t.Errorf("expected error to contain 'отвечает как SSH-сервер', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "выбран SOCKS5") {
		t.Errorf("expected error to contain 'выбран SOCKS5', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "выберите тип «SSH»") {
		t.Errorf("expected error to contain 'выберите тип «SSH»', got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "порт SOCKS5") {
		t.Errorf("expected error to contain 'порт SOCKS5', got: %q", errMsg)
	}
}

// 4. Сервер, молча закрывающий соединение на всё, выбран socks5 → исходная ошибка, без «отвечает как».
func TestVerifyUpstream_SilentClose_NoMismatch(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = VerifyUpstream(ctx, cfg, "", 500*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error on closed connection, got nil")
	}

	if !errors.Is(err, ErrInvalidProtocol) {
		t.Errorf("expected errors.Is(err, ErrInvalidProtocol) == true, got false; err = %v", err)
	}
	if errors.Is(err, ErrProtocolMismatch) {
		t.Errorf("expected errors.Is(err, ErrProtocolMismatch) == false, got true; err = %v", err)
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, "отвечает как") {
		t.Errorf("did not expect 'отвечает как' in error message for closed connection, got: %q", errMsg)
	}
}

// 5. Нормальный SOCKS5 с выбранным socks5 → VerifyUpstream успешен, лишней пробы нет.
func TestVerifyUpstream_NormalSOCKS5_NoProbe(t *testing.T) {
	var connCount atomic.Int32

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			connCount.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				// SOCKS5 handshake
				buf := make([]byte, 256)
				if _, err := io.ReadFull(c, buf[:3]); err != nil {
					return
				}
				// Reply NO_AUTH
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				// SOCKS5 CONNECT request
				// Read VER(1), CMD(1), RSV(1), ATYP(1)
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				// IPv4: 4 bytes addr + 2 bytes port = 6 bytes
				if _, err := io.ReadFull(c, buf[:6]); err != nil {
					return
				}
				// Reply CONNECT success: VER 5, REP 0, RSV 0, ATYP 1 (0.0.0.0:0)
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			}(conn)
		}
	}()

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rtt, err := VerifyUpstream(ctx, cfg, "", 1*time.Second)
	if err != nil {
		t.Fatalf("expected VerifyUpstream success, got error: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("expected positive RTT, got %v", rtt)
	}

	if count := connCount.Load(); count != 1 {
		t.Errorf("expected exactly 1 connection to proxy (no extra probe), got %d", count)
	}
}

// Also verify with testupstream directly
func TestVerifyUpstream_NormalSOCKS5_Testupstream(t *testing.T) {
	srv, err := testupstream.StartWithOptions(testupstream.Options{
		Type: "socks5",
	})
	if err != nil {
		t.Fatalf("start testupstream: %v", err)
	}
	defer srv.Close()

	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: srv.Port(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rtt, err := VerifyUpstream(ctx, cfg, "", 1*time.Second)
	if err != nil {
		t.Fatalf("expected VerifyUpstream success, got error: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("expected positive RTT, got %v", rtt)
	}
}
