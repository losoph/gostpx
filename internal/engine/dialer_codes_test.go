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
)

// TestDirectDialer_SOCKS5ConnectCodes verifies RFC 1928 reply codes decoding:
// specifically code 0x02 wraps ErrAuthFailed with "0x02" in text, and other codes
// wrap ErrTargetUnreachable with their respective descriptions.
func TestDirectDialer_SOCKS5ConnectCodes(t *testing.T) {
	testCases := []struct {
		name       string
		replyCode  byte
		wantErr    error
		wantSubstr string
	}{
		{
			name:       "0x01 general failure",
			replyCode:  0x01,
			wantErr:    ErrTargetUnreachable,
			wantSubstr: "общий сбой сервера (0x01)",
		},
		{
			name:       "0x02 connection not allowed by ruleset (auth failed)",
			replyCode:  0x02,
			wantErr:    ErrAuthFailed,
			wantSubstr: "0x02",
		},
		{
			name:       "0x03 network unreachable",
			replyCode:  0x03,
			wantErr:    ErrTargetUnreachable,
			wantSubstr: "сеть недоступна (0x03)",
		},
		{
			name:       "0x04 host unreachable",
			replyCode:  0x04,
			wantErr:    ErrTargetUnreachable,
			wantSubstr: "узел недоступен (0x04)",
		},
		{
			name:       "0x05 connection refused",
			replyCode:  0x05,
			wantErr:    ErrTargetUnreachable,
			wantSubstr: "соединение отклонено (0x05)",
		},
		{
			name:       "0x06 TTL expired",
			replyCode:  0x06,
			wantErr:    ErrTargetUnreachable,
			wantSubstr: "истёк TTL (0x06)",
		},
		{
			name:       "0x07 command not supported",
			replyCode:  0x07,
			wantErr:    ErrTargetUnreachable,
			wantSubstr: "команда не поддерживается (0x07)",
		},
		{
			name:       "0x08 address type not supported",
			replyCode:  0x08,
			wantErr:    ErrTargetUnreachable,
			wantSubstr: "тип адреса не поддерживается (0x08)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Start a mock SOCKS5 server that returns tc.replyCode on CONNECT
			server, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to start mock SOCKS5 server: %v", err)
			}
			defer server.Close()

			go func() {
				conn, err := server.Accept()
				if err != nil {
					return
				}
				defer conn.Close()

				// 1. Read greeting (VER 5, NMETHODS, METHODS)
				buf := make([]byte, 128)
				if _, err := io.ReadAtLeast(conn, buf, 3); err != nil {
					return
				}
				// Reply: VER 5, METHOD 0x00 (No auth)
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return
				}

				// 2. Read CONNECT request (VER 5, CMD 1, RSV 0, ATYP ...)
				if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
					return
				}

				// 3. Send response with tc.replyCode
				// VER 5, REP tc.replyCode, RSV 0, ATYP 1 (IPv4), BND.ADDR 0.0.0.0, BND.PORT 0
				resp := []byte{0x05, tc.replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
				_, _ = conn.Write(resp)
			}()

			serverPort := server.Addr().(*net.TCPAddr).Port
			dialer, err := NewDirectDialer(config.ProxyConfig{
				Host: "127.0.0.1",
				Port: serverPort,
				Type: "socks5",
			}, "")
			if err != nil {
				t.Fatalf("NewDirectDialer error: %v", err)
			}
			defer dialer.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, dialErr := dialer.DialTarget(ctx, "example.com", 80)
			if dialErr == nil {
				t.Fatalf("expected error from DialTarget for reply code 0x%02x, got nil", tc.replyCode)
			}

			// Verify error wrapping
			if !errors.Is(dialErr, tc.wantErr) {
				t.Errorf("expected errors.Is(err, %v), got: %v", tc.wantErr, dialErr)
			}

			// For 0x02 specifically: must NOT be ErrTargetUnreachable, and must NOT be ErrCredentialsRejected (Task E)
			if tc.replyCode == 0x02 {
				if errors.Is(dialErr, ErrTargetUnreachable) {
					t.Errorf("for code 0x02, expected NOT to be ErrTargetUnreachable, but it was")
				}
				if errors.Is(dialErr, ErrCredentialsRejected) {
					t.Errorf("for code 0x02, expected NOT to be ErrCredentialsRejected, but it was")
				}
				if !strings.Contains(dialErr.Error(), "проверьте логин и пароль") {
					t.Errorf("expected text to contain 'проверьте логин и пароль', got: %v", dialErr)
				}
			}

			if !strings.Contains(dialErr.Error(), tc.wantSubstr) {
				t.Errorf("expected error message to contain %q, got: %q", tc.wantSubstr, dialErr.Error())
			}
		})
	}
}
