package settings

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/testupstream"
)

const baseConfigTOML = `version = 1
mode = "sysproxy"
autostart = false
autoconnect = false

[proxy]
type = "socks5"
host = "192.168.1.50"
port = 1080
user = "olduser"

[dns]
doh = "https://1.1.1.1/dns-query"

[sysproxy]
http_listen = "127.0.0.1:8080"
socks_listen = "127.0.0.1:1080"

[ui]
config_writable = true
`

// TestSaveSettings_ChangeHostWithoutPassword verifies that changing proxy host without
// re-entering a password clears credentials.toml and returns password_cleared: true.
func TestSaveSettings_ChangeHostWithoutPassword(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)

	if err := os.WriteFile(configPath, []byte(baseConfigTOML), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(credPath, "secret123"); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "new.proxy.host",
		ProxyPort:       1080,
		ProxyUser:       "olduser",
		DNSDoH:          "https://1.1.1.1/dns-query",
		PasswordChanged: false,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["password_cleared"] != true {
		t.Errorf("expected password_cleared: true, got %v", resp["password_cleared"])
	}

	pwd, err := config.LoadPassword(credPath)
	if err != nil {
		t.Fatalf("unexpected error reading credentials: %v", err)
	}
	if pwd != "" {
		t.Errorf("expected empty password after carryover reset, got %q", pwd)
	}

	cfg, _, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Host != "new.proxy.host" {
		t.Errorf("expected host 'new.proxy.host', got %q", cfg.Proxy.Host)
	}
}

// TestSaveSettings_ChangeUserWithoutPassword verifies that changing proxy user without
// re-entering a password clears credentials.toml and returns password_cleared: true.
func TestSaveSettings_ChangeUserWithoutPassword(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)

	if err := os.WriteFile(configPath, []byte(baseConfigTOML), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(credPath, "secret123"); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "192.168.1.50",
		ProxyPort:       1080,
		ProxyUser:       "newuser",
		DNSDoH:          "https://1.1.1.1/dns-query",
		PasswordChanged: false,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["password_cleared"] != true {
		t.Errorf("expected password_cleared: true, got %v", resp["password_cleared"])
	}

	pwd, err := config.LoadPassword(credPath)
	if err != nil {
		t.Fatalf("unexpected error reading credentials: %v", err)
	}
	if pwd != "" {
		t.Errorf("expected empty password after carryover reset, got %q", pwd)
	}
}

// TestSaveSettings_ChangePortOrTypeWithoutPassword verifies that changing port or type
// without re-entering password also clears credentials.toml.
func TestSaveSettings_ChangePortOrTypeWithoutPassword(t *testing.T) {
	// 1. Port change
	{
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.toml")
		credPath := config.CredentialsPath(configPath)
		_ = os.WriteFile(configPath, []byte(baseConfigTOML), 0600)
		_ = config.SavePassword(credPath, "secret123")

		handler := APIHandler(configPath, "")
		body, _ := json.Marshal(SaveSettingsRequest{
			Mode:            "sysproxy",
			ProxyType:       "socks5",
			ProxyHost:       "192.168.1.50",
			ProxyPort:       1088,
			ProxyUser:       "olduser",
			DNSDoH:          "https://1.1.1.1/dns-query",
			PasswordChanged: false,
		})

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["password_cleared"] != true {
			t.Errorf("expected password_cleared: true on port change, got %v", resp["password_cleared"])
		}
		pwd, _ := config.LoadPassword(credPath)
		if pwd != "" {
			t.Errorf("expected empty password, got %q", pwd)
		}
	}

	// 2. Type change
	{
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.toml")
		credPath := config.CredentialsPath(configPath)
		_ = os.WriteFile(configPath, []byte(baseConfigTOML), 0600)
		_ = config.SavePassword(credPath, "secret123")

		handler := APIHandler(configPath, "")
		body, _ := json.Marshal(SaveSettingsRequest{
			Mode:            "sysproxy",
			ProxyType:       "http",
			ProxyHost:       "192.168.1.50",
			ProxyPort:       1080,
			ProxyUser:       "olduser",
			DNSDoH:          "https://1.1.1.1/dns-query",
			PasswordChanged: false,
		})

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["password_cleared"] != true {
			t.Errorf("expected password_cleared: true on type change, got %v", resp["password_cleared"])
		}
		pwd, _ := config.LoadPassword(credPath)
		if pwd != "" {
			t.Errorf("expected empty password, got %q", pwd)
		}
	}
}

// TestSaveSettings_ChangeHostWithNewPassword verifies that entering a new password
// saves the new password properly and does not return password_cleared: true.
func TestSaveSettings_ChangeHostWithNewPassword(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)

	if err := os.WriteFile(configPath, []byte(baseConfigTOML), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(credPath, "oldsecret"); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "new.proxy.host",
		ProxyPort:       1080,
		ProxyUser:       "olduser",
		DNSDoH:          "https://1.1.1.1/dns-query",
		Password:        "newsecret456",
		PasswordChanged: true,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["password_cleared"] == true {
		t.Errorf("expected password_cleared to NOT be true when new password is provided")
	}

	pwd, err := config.LoadPassword(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if pwd != "newsecret456" {
		t.Errorf("expected password 'newsecret456', got %q", pwd)
	}

	cfg, _, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Host != "new.proxy.host" {
		t.Errorf("expected host 'new.proxy.host', got %q", cfg.Proxy.Host)
	}
}

// TestSaveSettings_ChangeModeOnly_PreservesPassword verifies that changing only
// mode, autostart, or dns does not touch the existing password.
func TestSaveSettings_ChangeModeOnly_PreservesPassword(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)

	if err := os.WriteFile(configPath, []byte(baseConfigTOML), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(credPath, "keep_this_secret"); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")

	// 1. Change mode only
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "off",
		ProxyType:       "socks5",
		ProxyHost:       "192.168.1.50",
		ProxyPort:       1080,
		ProxyUser:       "olduser",
		DNSDoH:          "https://1.1.1.1/dns-query",
		PasswordChanged: false,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["password_cleared"] == true {
		t.Errorf("password_cleared must not be true when only mode changed")
	}

	pwd, err := config.LoadPassword(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if pwd != "keep_this_secret" {
		t.Errorf("expected password 'keep_this_secret' preserved, got %q", pwd)
	}

	// 2. Change autostart and DNS only
	body, _ = json.Marshal(SaveSettingsRequest{
		Mode:            "off",
		Autostart:       true,
		ProxyType:       "socks5",
		ProxyHost:       "192.168.1.50",
		ProxyPort:       1080,
		ProxyUser:       "olduser",
		DNSDoH:          "https://dns.google/dns-query",
		PasswordChanged: false,
	})

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	pwd, err = config.LoadPassword(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if pwd != "keep_this_secret" {
		t.Errorf("expected password 'keep_this_secret' preserved after DNS/autostart change, got %q", pwd)
	}
}

// TestSaveSettings_ConfigWriteFailureRollback_PreservesPassword verifies that if writing
// config fails after credentials were cleared in the transaction, rollback restores the old password.
func TestSaveSettings_ConfigWriteFailureRollback_PreservesPassword(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)

	if err := os.WriteFile(configPath, []byte(baseConfigTOML), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(credPath, "original_secret"); err != nil {
		t.Fatal(err)
	}

	// Create config.toml.bak as a directory so UpdateFile fails when creating the backup
	bakPath := configPath + ".bak"
	if err := os.Mkdir(bakPath, 0755); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "changed.proxy.host",
		ProxyPort:       1080,
		ProxyUser:       "olduser",
		PasswordChanged: false,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	// Should fail with an error because config write failed
	if rr.Code == http.StatusOK {
		t.Fatalf("expected error response when config write fails, got 200 OK")
	}

	// Rollback check: password in credentials.toml must be restored to original_secret
	pwd, err := config.LoadPassword(credPath)
	if err != nil {
		t.Fatalf("failed to read credentials after rollback: %v", err)
	}
	if pwd != "original_secret" {
		t.Errorf("expected password rolled back to 'original_secret', got %q", pwd)
	}

	// Config check: config.toml must still contain old host
	cfg, _, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Host != "192.168.1.50" {
		t.Errorf("expected host to remain '192.168.1.50', got %q", cfg.Proxy.Host)
	}
}

// TestCheckConnection_ChangedHostSendsEmptyPassword verifies that handleCheckConnection
// sends an empty password when host is changed relative to current config and !PasswordChanged.
func TestCheckConnection_ChangedHostSendsEmptyPassword(t *testing.T) {
	// Start test SOCKS5 upstream that requires user "alice" and an EMPTY password ""
	srvEmpty, err := testupstream.StartWithOptions(testupstream.Options{
		Type:     "socks5",
		Username: "alice",
		Password: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srvEmpty.Close()

	emptyHost, emptyPortStr, _ := net.SplitHostPort(srvEmpty.Addr())
	emptyPort, _ := strconv.Atoi(emptyPortStr)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)

	// Current config has a different host and a non-empty password saved
	cfgContent := `version = 1
mode = "sysproxy"
[proxy]
type = "socks5"
host = "old.saved.host"
port = 1080
user = "alice"
`
	if err := os.WriteFile(configPath, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(credPath, "old_saved_secret"); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")

	// 1. Check with changed host and PasswordChanged: false.
	// Since host changed, handler must check with empty password.
	// Because srvEmpty expects an empty password, this MUST succeed.
	bodyChanged, _ := json.Marshal(CheckRequest{
		Type:            "socks5",
		Host:            emptyHost,
		Port:            emptyPort,
		User:            "alice",
		PasswordChanged: false,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/check", bytes.NewReader(bodyChanged)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp CheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("expected OK: true for empty password check against upstream expecting empty password, got error: %s", resp.Error)
	}

	// 2. Counter-check: check upstream that expects the OLD secret.
	// When host is changed, empty password is sent -> auth MUST fail.
	srvOldSecret, err := testupstream.StartWithOptions(testupstream.Options{
		Type:     "socks5",
		Username: "alice",
		Password: "old_saved_secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srvOldSecret.Close()

	oldSecHost, oldSecPortStr, _ := net.SplitHostPort(srvOldSecret.Addr())
	oldSecPort, _ := strconv.Atoi(oldSecPortStr)

	bodyCounter, _ := json.Marshal(CheckRequest{
		Type:            "socks5",
		Host:            oldSecHost,
		Port:            oldSecPort,
		User:            "alice",
		PasswordChanged: false,
	})

	rrCounter := httptest.NewRecorder()
	handler.ServeHTTP(rrCounter, httptest.NewRequest(http.MethodPost, "/api/check", bytes.NewReader(bodyCounter)))

	var respCounter CheckResponse
	if err := json.Unmarshal(rrCounter.Body.Bytes(), &respCounter); err != nil {
		t.Fatal(err)
	}
	if respCounter.OK {
		t.Errorf("expected OK: false because empty password was sent to upstream expecting 'old_saved_secret'")
	}
	if !strings.Contains(respCounter.Error, "авториз") {
		t.Errorf("expected authorization error, got: %q", respCounter.Error)
	}

	// 3. Check with unchanged host and PasswordChanged: false.
	// Since host matches config.toml ("old.saved.host"), the saved password "old_saved_secret" is used.
	// When checked against srvOldSecret, auth succeeds.
	cfgMatchContent := `version = 1
mode = "sysproxy"
[proxy]
type = "socks5"
host = "` + oldSecHost + `"
port = ` + strconv.Itoa(oldSecPort) + `
user = "alice"
`
	if err := os.WriteFile(configPath, []byte(cfgMatchContent), 0600); err != nil {
		t.Fatal(err)
	}

	bodyMatch, _ := json.Marshal(CheckRequest{
		Type:            "socks5",
		Host:            oldSecHost,
		Port:            oldSecPort,
		User:            "alice",
		PasswordChanged: false,
	})

	rrMatch := httptest.NewRecorder()
	handler.ServeHTTP(rrMatch, httptest.NewRequest(http.MethodPost, "/api/check", bytes.NewReader(bodyMatch)))

	var respMatch CheckResponse
	if err := json.Unmarshal(rrMatch.Body.Bytes(), &respMatch); err != nil {
		t.Fatal(err)
	}
	if !respMatch.OK {
		t.Errorf("expected OK: true when proxy matches config and saved secret is valid, got: %s", respMatch.Error)
	}
}

// TestSaveSettings_EmptiedFieldSameProxyKeepsPassword: an emptied password field
// on the same proxy is not a request to clear it (that is ClearPassword).
func TestSaveSettings_EmptiedFieldSameProxyKeepsPassword(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)
	if err := os.WriteFile(configPath, []byte(baseConfigTOML), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePassword(credPath, "secret123"); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "192.168.1.50",
		ProxyPort:       1080,
		ProxyUser:       "olduser",
		DNSDoH:          "https://1.1.1.1/dns-query",
		PasswordChanged: true,
		Password:        "",
	})
	rr := httptest.NewRecorder()
	APIHandler(configPath, "").ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "password_cleared") {
		t.Errorf("password must not be reported cleared: %s", rr.Body.String())
	}
	if pwd, _ := config.LoadPassword(credPath); pwd != "secret123" {
		t.Errorf("password changed to %q, want it kept", pwd)
	}
}
