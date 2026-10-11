package settings

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveSettings_EmptyDNSDoH_PreservesConfigAndComments(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialTOML := `# Main configuration header
version = 1
mode = "sysproxy"
autostart = false

# Upstream proxy configuration
[proxy]
type = "socks5"
host = "192.168.1.1" # Proxy host comment
port = 1080
user = "testuser"

# DNS section comment - must be preserved
[dns]
doh = "https://1.1.1.1/dns-query" # Quad1 DoH endpoint

[sysproxy]
http_listen = "127.0.0.1:8080"
socks_listen = "127.0.0.1:1080"

[ui]
config_writable = true
`
	if err := os.WriteFile(configPath, []byte(initialTOML), 0600); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")

	// 1. Save with empty DNSDoH
	reqPayload := SaveSettingsRequest{
		Mode:      "sysproxy",
		Autostart: true,
		ProxyType: "socks5",
		ProxyHost: "192.168.1.2",
		ProxyPort: 1081,
		ProxyUser: "testuser",
		DNSDoH:    "", // Empty DoH string must NOT overwrite dns.doh
	}

	body, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	updatedBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(updatedBytes)

	// Verify comments are preserved
	if !strings.Contains(content, "# Main configuration header") {
		t.Errorf("lost header comment")
	}
	if !strings.Contains(content, "# Upstream proxy configuration") {
		t.Errorf("lost proxy comment")
	}
	if !strings.Contains(content, "# Proxy host comment") {
		t.Errorf("lost inline proxy host comment")
	}
	if !strings.Contains(content, "# DNS section comment - must be preserved") {
		t.Errorf("lost DNS section comment")
	}
	if !strings.Contains(content, "# Quad1 DoH endpoint") {
		t.Errorf("lost inline DoH endpoint comment")
	}

	// Verify dns.doh was preserved intact
	if !strings.Contains(content, `doh = "https://1.1.1.1/dns-query"`) {
		t.Errorf("expected dns.doh to be preserved as 'https://1.1.1.1/dns-query', got: %s", content)
	}

	// Verify other fields were updated
	if !strings.Contains(content, `host = "192.168.1.2"`) {
		t.Errorf("expected host to be updated to 192.168.1.2, got: %s", content)
	}
	if !strings.Contains(content, `port = 1081`) {
		t.Errorf("expected port to be updated to 1081, got: %s", content)
	}
	if !strings.Contains(content, `autostart = true`) {
		t.Errorf("expected autostart to be true, got: %s", content)
	}

	// 2. Save with whitespace-only DNSDoH
	reqPayloadWhitespace := SaveSettingsRequest{
		Mode:      "sysproxy",
		Autostart: true,
		ProxyType: "socks5",
		ProxyHost: "192.168.1.3",
		ProxyPort: 1082,
		ProxyUser: "testuser",
		DNSDoH:    "   ", // Whitespace-only must also NOT overwrite dns.doh
	}

	bodyWs, err := json.Marshal(reqPayloadWhitespace)
	if err != nil {
		t.Fatal(err)
	}

	reqWs := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(bodyWs))
	rrWs := httptest.NewRecorder()
	handler.ServeHTTP(rrWs, reqWs)

	if rrWs.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rrWs.Code, rrWs.Body.String())
	}

	updatedBytesWs, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	contentWs := string(updatedBytesWs)

	if !strings.Contains(contentWs, `doh = "https://1.1.1.1/dns-query"`) {
		t.Errorf("whitespace DNSDoH modified dns.doh: %s", contentWs)
	}
	if !strings.Contains(contentWs, "# DNS section comment - must be preserved") {
		t.Errorf("lost DNS section comment after whitespace save")
	}
}

func TestSaveSettings_NonEmptyDNSDoH_UpdatesConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialTOML := `# Header comment
version = 1
mode = "sysproxy"

[proxy]
type = "socks5"
host = "127.0.0.1"
port = 1080

# DNS section comment
[dns]
doh = "https://1.1.1.1/dns-query" # Original DoH comment

[sysproxy]
http_listen = "127.0.0.1:8080"
socks_listen = "127.0.0.1:1080"

[ui]
config_writable = true
`
	if err := os.WriteFile(configPath, []byte(initialTOML), 0600); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")

	reqPayload := SaveSettingsRequest{
		Mode:      "sysproxy",
		ProxyType: "socks5",
		ProxyHost: "127.0.0.1",
		ProxyPort: 1080,
		DNSDoH:    "https://dns.google/dns-query", // Non-empty DoH string updates dns.doh
	}

	body, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	updatedBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(updatedBytes)

	// Verify dns.doh was updated
	if !strings.Contains(content, `doh = "https://dns.google/dns-query"`) {
		t.Errorf("expected dns.doh to be updated to 'https://dns.google/dns-query', got: %s", content)
	}

	// Verify comments are preserved
	if !strings.Contains(content, "# Header comment") {
		t.Errorf("lost header comment")
	}
	if !strings.Contains(content, "# DNS section comment") {
		t.Errorf("lost DNS section comment")
	}
	if !strings.Contains(content, "# Original DoH comment") {
		t.Errorf("lost inline DoH comment")
	}
}
