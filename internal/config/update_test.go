package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdatePreservesCommentsByteForByte(t *testing.T) {
	orig := `# Top level document comment
version = 1 # version comment

# Mode comment
mode = "tun"

autostart = true # autostart comment

# Proxy configuration section
[proxy] # Table comment
type = "socks5" # inline type comment
host = "old.example.com"
port = 1080 # default socks port

# System proxy section
[sysproxy]
http_listen = "127.0.0.1:8080" # listen http
`

	updates := map[string]any{
		"mode":       "sysproxy",
		"proxy.host": "new.example.org",
		"proxy.port": 9050,
		"proxy.type": "http",
		"autostart":  false,
	}

	updated, err := UpdateBytes([]byte(orig), updates)
	if err != nil {
		t.Fatalf("UpdateBytes failed: %v", err)
	}

	str := string(updated)

	// Verify values updated
	if !strings.Contains(str, `mode = "sysproxy"`) {
		t.Errorf("mode not updated: %s", str)
	}
	if !strings.Contains(str, `host = "new.example.org"`) {
		t.Errorf("proxy.host not updated: %s", str)
	}
	if !strings.Contains(str, `port = 9050 # default socks port`) {
		t.Errorf("proxy.port not updated or inline comment lost: %s", str)
	}
	if !strings.Contains(str, `type = "http" # inline type comment`) {
		t.Errorf("proxy.type not updated or inline comment lost: %s", str)
	}
	if !strings.Contains(str, `autostart = false # autostart comment`) {
		t.Errorf("autostart not updated or inline comment lost: %s", str)
	}

	// Verify comments preserved
	expectedComments := []string{
		"# Top level document comment",
		"# version comment",
		"# Mode comment",
		"# Proxy configuration section",
		"[proxy] # Table comment",
		"# System proxy section",
		"# listen http",
	}
	for _, c := range expectedComments {
		if !strings.Contains(str, c) {
			t.Errorf("Missing expected comment: %q", c)
		}
	}
}

func TestUpdateSameKeyInDifferentSections(t *testing.T) {
	orig := `version = 1
mode = "sysproxy"

[proxy]
port = 1080 # proxy port

[custom]
port = 8888 # custom port
`

	updates := map[string]any{
		"proxy.port": 9999,
	}

	updated, err := UpdateBytes([]byte(orig), updates)
	if err != nil {
		t.Fatalf("UpdateBytes failed: %v", err)
	}

	str := string(updated)
	if !strings.Contains(str, "port = 9999 # proxy port") {
		t.Errorf("proxy.port was not updated: %s", str)
	}
	if !strings.Contains(str, "port = 8888 # custom port") {
		t.Errorf("custom.port was accidentally changed: %s", str)
	}
}

func TestUpdateStringWithHash(t *testing.T) {
	orig := `version = 1
mode = "sysproxy"

[proxy]
type = "socks5"
host = "old#host.com" # comment with # inside
port = 1080
`

	updates := map[string]any{
		"proxy.host": "new#special#host.net",
	}

	updated, err := UpdateBytes([]byte(orig), updates)
	if err != nil {
		t.Fatalf("UpdateBytes failed: %v", err)
	}

	str := string(updated)
	if !strings.Contains(str, `host = "new#special#host.net" # comment with # inside`) {
		t.Errorf("host with hash not updated properly: %s", str)
	}
}

func TestUpdateBOMAndCRLF(t *testing.T) {
	orig := "\xef\xbb\xbf# Windows CRLF\r\nversion = 1\r\nmode = \"tun\"\r\n[proxy]\r\ntype = \"socks5\"\r\nhost = \"example.com\"\r\nport = 1080\r\n"

	updates := map[string]any{
		"mode":       "sysproxy",
		"proxy.port": 8080,
	}

	updated, err := UpdateBytes([]byte(orig), updates)
	if err != nil {
		t.Fatalf("UpdateBytes failed: %v", err)
	}

	// Verify BOM is preserved
	if !bytes.HasPrefix(updated, []byte("\xef\xbb\xbf")) {
		t.Errorf("UTF-8 BOM was lost")
	}

	// Verify CRLF line endings are preserved
	if !bytes.Contains(updated, []byte("\r\n")) {
		t.Errorf("CRLF line endings were lost")
	}

	str := string(updated)
	if !strings.Contains(str, `mode = "sysproxy"`) {
		t.Errorf("mode not updated in BOM doc")
	}
	if !strings.Contains(str, `port = 8080`) {
		t.Errorf("port not updated in BOM doc")
	}
}

func TestUpdateReadOnlyProtection(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")

	content := `version = 1
mode = "sysproxy"

[proxy]
type = "socks5"
host = "example.com"
port = 1080

[ui]
config_writable = false
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err := UpdateFile(cfgPath, map[string]any{"mode": "tun"})
	if !errors.Is(err, ErrConfigReadOnly) {
		t.Fatalf("Expected ErrConfigReadOnly, got %v", err)
	}

	// Verify file was NOT modified
	data, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(data), `mode = "sysproxy"`) {
		t.Errorf("File was unexpectedly modified despite read-only mode")
	}
}

func TestUpdateMultipleMissingKeysInTable(t *testing.T) {
	orig := `# Initial config comment
version = 1
mode = "sysproxy"

# Proxy section comment
[proxy]
host = "1.2.3.4"
port = 1080

# DNS section comment
[dns]
doh = "https://dns.quad9.net/dns-query"
`

	// Insert two missing keys into [proxy], with [dns] and its comment following it
	updates := map[string]any{
		"proxy.type": "socks5",
		"proxy.user": "alice",
	}

	updated, err := UpdateBytes([]byte(orig), updates)
	if err != nil {
		t.Fatalf("UpdateBytes failed: %v", err)
	}

	str := string(updated)

	// Verify both keys are present
	if !strings.Contains(str, `type = "socks5"`) {
		t.Errorf("proxy.type not found: %s", str)
	}
	if !strings.Contains(str, `user = "alice"`) {
		t.Errorf("proxy.user not found: %s", str)
	}

	// Verify comments are preserved
	if !strings.Contains(str, "# Initial config comment") {
		t.Errorf("Initial comment lost: %s", str)
	}
	if !strings.Contains(str, "# Proxy section comment") {
		t.Errorf("Proxy section comment lost: %s", str)
	}
	if !strings.Contains(str, "# DNS section comment") {
		t.Errorf("DNS section comment lost: %s", str)
	}

	// Verify structure: keys are inside [proxy], before [dns]
	proxyIdx := strings.Index(str, "[proxy]")
	dnsIdx := strings.Index(str, "[dns]")
	typeIdx := strings.Index(str, `type = "socks5"`)
	userIdx := strings.Index(str, `user = "alice"`)
	dnsCommentIdx := strings.Index(str, "# DNS section comment")

	if proxyIdx == -1 || dnsIdx == -1 || typeIdx == -1 || userIdx == -1 || dnsCommentIdx == -1 {
		t.Fatalf("Malformed output: %s", str)
	}

	if !(proxyIdx < typeIdx && typeIdx < dnsCommentIdx && dnsCommentIdx < dnsIdx) {
		t.Errorf("type was not inserted inside [proxy] before [dns] comment: %s", str)
	}
	if !(proxyIdx < userIdx && userIdx < dnsCommentIdx && dnsCommentIdx < dnsIdx) {
		t.Errorf("user was not inserted inside [proxy] before [dns] comment: %s", str)
	}

	// Verify the result parses and validates cleanly via config.Load/Parse
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgPath, updated, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, issues, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed on updated config: %v", err)
	}
	for _, issue := range issues {
		if !issue.IsWarning {
			t.Errorf("Validation error on updated config: %s", issue)
		}
	}
	if cfg.Proxy.Type != "socks5" || cfg.Proxy.User != "alice" {
		t.Errorf("Parsed config does not match expected values: %+v", cfg.Proxy)
	}
}

func TestUpdateFile_BackupFailure(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	initialContent := []byte("version = 1\nmode = \"off\"\n")
	if err := os.WriteFile(cfgPath, initialContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Create a directory where the .bak file should be written to force WriteFile error
	bakPath := cfgPath + ".bak"
	if err := os.Mkdir(bakPath, 0755); err != nil {
		t.Fatal(err)
	}

	err := UpdateFile(cfgPath, map[string]any{"autostart": true})
	if err == nil || !strings.Contains(err.Error(), "backup config") {
		t.Fatalf("expected backup config error, got: %v", err)
	}

	// Verify original file is unchanged
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, initialContent) {
		t.Errorf("config was modified despite backup failure: %s", string(after))
	}
}
