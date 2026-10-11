package engine

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/losoph/gostpx/internal/config"
)

func TestMaskURL(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"socks5://user:secretpass@example.com:1080", "socks5://user:***@example.com:1080"},
		{"http://alice:supersecret@127.0.0.1:8080", "http://alice:***@127.0.0.1:8080"},
		{"socks5://example.com:1080", "socks5://example.com:1080"},
		{"socks5://user@example.com:1080", "socks5://user@example.com:1080"},
	}

	for _, tt := range tests {
		u, err := url.Parse(tt.raw)
		if err != nil {
			t.Fatalf("failed to parse url %q: %v", tt.raw, err)
		}
		got := MaskURL(u)
		if got != tt.want {
			t.Errorf("MaskURL(%q) = %q, want %q", tt.raw, got, tt.want)
		}
		gotStr := MaskURLString(tt.raw)
		if gotStr != tt.want {
			t.Errorf("MaskURLString(%q) = %q, want %q", tt.raw, gotStr, tt.want)
		}
	}
}

type customSanitizeTestError struct {
	code int
}

func (c *customSanitizeTestError) Error() string {
	return fmt.Sprintf("custom code %d", c.code)
}

func TestSanitizeError(t *testing.T) {
	secret := "TopSecretPassword123"
	baseErr := &customSanitizeTestError{code: 42}
	err := fmt.Errorf("dial socks5://bob:TopSecretPassword123@proxy.org:8000: %w", baseErr)

	sanitized := SanitizeError(err, secret)
	if strings.Contains(sanitized.Error(), secret) {
		t.Errorf("sanitized error still contains secret: %s", sanitized.Error())
	}
	if !strings.Contains(sanitized.Error(), "***") {
		t.Errorf("sanitized error does not contain *** mask: %s", sanitized.Error())
	}

	// Verify error chain is preserved (errors.Is)
	if !errors.Is(sanitized, baseErr) {
		t.Errorf("expected errors.Is(sanitized, baseErr) to be true")
	}

	// Verify error chain is preserved (errors.As)
	var extracted *customSanitizeTestError
	if !errors.As(sanitized, &extracted) || extracted.code != 42 {
		t.Errorf("expected errors.As(sanitized, &extracted) to succeed, got %+v", extracted)
	}
}

func TestBuildProxyURL(t *testing.T) {
	cfg := config.ProxyConfig{
		Type: "socks5",
		Host: "proxy.test",
		Port: 8080,
		User: "john",
	}
	u, err := BuildProxyURL(cfg, "mypass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	masked := MaskURL(u)
	if masked != "socks5://john:***@proxy.test:8080" {
		t.Errorf("unexpected masked URL: %s", masked)
	}

	pass, _ := u.User.Password()
	if pass != "mypass" {
		t.Errorf("password in built URL mismatch: %s", pass)
	}
}

func TestParseProxyURL(t *testing.T) {
	raw := "socks5://myuser:secret123@myproxy.net:9000"
	pCfg, plainPass, err := ParseProxyURL(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pCfg.Type != "socks5" || pCfg.Host != "myproxy.net" || pCfg.Port != 9000 || pCfg.User != "myuser" {
		t.Errorf("parsed config mismatch: %+v", pCfg)
	}
	if plainPass != "secret123" {
		t.Errorf("parsed password mismatch: %s", plainPass)
	}

	// Test ssh scheme and default port 22
	sshRaw := "ssh://sshuser:sshpass@ssh.example.com"
	sshCfg, sshPass, err := ParseProxyURL(sshRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sshCfg.Type != "ssh" || sshCfg.Host != "ssh.example.com" || sshCfg.Port != 22 || sshCfg.User != "sshuser" {
		t.Errorf("ssh parsed config mismatch: %+v", sshCfg)
	}
	if sshPass != "sshpass" {
		t.Errorf("ssh parsed password mismatch: %s", sshPass)
	}

	// Test missing scheme error
	_, _, err = ParseProxyURL("no-scheme.com:8080")
	if err == nil {
		t.Error("expected error for URL without scheme, got nil")
	}

	// Test removed protocols rejected as unsupported
	for _, raw := range []string{
		"ss://host.net:8388",
		"shadowsocks://host.net:8388",
		"wireguard://wg.example.com:51820",
	} {
		_, _, err := ParseProxyURL(raw)
		if err == nil {
			t.Errorf("expected error for %q, got nil", raw)
		}
		if !strings.Contains(err.Error(), "unsupported protocol scheme") {
			t.Errorf("expected unsupported protocol scheme error for %q, got: %v", raw, err)
		}
	}
}
