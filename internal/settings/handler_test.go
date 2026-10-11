package settings

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func TestGetSettingsDefault(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	handler := APIHandler(configPath, "")
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var data SettingsData
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if data.ConfigWritable != true {
		t.Errorf("expected config_writable true, got %v", data.ConfigWritable)
	}
	if data.HasPassword {
		t.Errorf("expected has_password false, got true")
	}
}

func TestGetSettingsWithCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	cfgContent := `version = 1
mode = "sysproxy"
autostart = false
autoconnect = false

[proxy]
type = "socks5"
host = "192.168.1.100"
port = 1080
user = "alice"

[dns]
doh = "https://1.1.1.1/dns-query"

[sysproxy]
http_listen = "127.0.0.1:8080"
socks_listen = "127.0.0.1:1080"

[ui]
config_writable = true
`
	if err := os.WriteFile(configPath, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}

	credPath := config.CredentialsPath(configPath)
	if err := config.SavePassword(credPath, "secret123"); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var data SettingsData
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if data.ProxyHost != "192.168.1.100" || data.ProxyPort != 1080 || data.ProxyUser != "alice" {
		t.Errorf("unexpected proxy data: %+v", data)
	}
	if !data.HasPassword {
		t.Errorf("expected has_password true")
	}
	if strings.Contains(rr.Body.String(), "secret123") {
		t.Errorf("SECURITY LEAK: response body contains actual password!")
	}
}

func TestSaveSettingsSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialTOML := `# Header comment that MUST be preserved
version = 1
mode = "off"
autostart = false

[proxy]
# Host comment that MUST be preserved
type = "http"
host = "old.host.com"
port = 8080
user = "olduser"

[dns]
doh = "https://old.doh/query"

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
	payload := SaveSettingsRequest{
		Mode:            "sysproxy",
		Autostart:       true,
		ProxyType:       "socks5",
		ProxyHost:       "new.host.org",
		ProxyPort:       1088,
		ProxyUser:       "newuser",
		Password:        "newpassword",
		PasswordChanged: true,
		DNSDoH:          "https://new.doh/dns-query",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify file was updated surgically
	updatedBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(updatedBytes)

	if !strings.Contains(content, "# Header comment that MUST be preserved") {
		t.Errorf("lost header comment!")
	}
	if !strings.Contains(content, "# Host comment that MUST be preserved") {
		t.Errorf("lost proxy host comment!")
	}
	if !strings.Contains(content, `host = "new.host.org"`) {
		t.Errorf("host was not updated: %s", content)
	}
	if !strings.Contains(content, `port = 1088`) {
		t.Errorf("port was not updated: %s", content)
	}
	if strings.Contains(content, "newpassword") {
		t.Errorf("SECURITY LEAK: password leaked into config.toml!")
	}

	// Verify credentials.toml
	credPath := config.CredentialsPath(configPath)
	pwd, err := config.LoadPassword(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if pwd != "newpassword" {
		t.Errorf("expected password 'newpassword', got %q", pwd)
	}

	// Test clear password
	clearPayload := SaveSettingsRequest{
		Mode:          "sysproxy",
		ProxyType:     "socks5",
		ProxyHost:     "new.host.org",
		ProxyPort:     1088,
		ClearPassword: true,
	}
	clearBody, _ := json.Marshal(clearPayload)
	reqClear := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(clearBody))
	rrClear := httptest.NewRecorder()
	handler.ServeHTTP(rrClear, reqClear)

	if rrClear.Code != http.StatusOK {
		t.Fatalf("clear failed with %d: %s", rrClear.Code, rrClear.Body.String())
	}

	pwdAfterClear, _ := config.LoadPassword(credPath)
	if pwdAfterClear != "" {
		t.Errorf("expected empty password after clear, got %q", pwdAfterClear)
	}
}

func TestSaveSettingsReadOnlyProtection(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialTOML := `version = 1
mode = "off"
autostart = false

[proxy]
type = "http"
host = "locked.host.com"
port = 8080

[sysproxy]
http_listen = "127.0.0.1:8080"
socks_listen = "127.0.0.1:1080"

[ui]
config_writable = false
`
	if err := os.WriteFile(configPath, []byte(initialTOML), 0600); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	payload := SaveSettingsRequest{
		Mode:      "sysproxy",
		ProxyType: "socks5",
		ProxyHost: "hacker.host.com",
		ProxyPort: 1080,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"], "ui.config_writable = false") {
		t.Errorf("unexpected error message: %v", resp)
	}

	// Verify file was NOT modified
	content, _ := os.ReadFile(configPath)
	if strings.Contains(string(content), "hacker.host.com") {
		t.Errorf("file was modified despite read-only protection!")
	}
}

func TestSaveSettingsValidationError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialTOML := `version = 1
mode = "sysproxy"

[proxy]
type = "socks5"
host = "valid.host.com"
port = 1080

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
	payload := SaveSettingsRequest{
		Mode:      "sysproxy",
		ProxyType: "socks5",
		ProxyHost: "valid.host.com",
		ProxyPort: 99999, // Invalid port > 65535
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCheckConnection(t *testing.T) {
	srv, err := testupstream.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	handler := APIHandler(configPath, "")

	// 1. Successful check
	body, _ := json.Marshal(CheckRequest{Type: "socks5", Host: host, Port: port})
	req := httptest.NewRequest(http.MethodPost, "/api/check", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp CheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Errorf("expected OK true, got error: %s", resp.Error)
	}

	// 2. Closed port check (e.g. port 1)
	bodyFail, _ := json.Marshal(CheckRequest{Type: "socks5", Host: "127.0.0.1", Port: 1})
	reqFail := httptest.NewRequest(http.MethodPost, "/api/check", bytes.NewReader(bodyFail))
	rrFail := httptest.NewRecorder()
	handler.ServeHTTP(rrFail, reqFail)

	var respFail CheckResponse
	_ = json.Unmarshal(rrFail.Body.Bytes(), &respFail)
	if respFail.OK {
		t.Errorf("expected OK false for closed port")
	}

	// 3. Empty host check
	bodyEmpty, _ := json.Marshal(CheckRequest{Host: "", Port: 0})
	reqEmpty := httptest.NewRequest(http.MethodPost, "/api/check", bytes.NewReader(bodyEmpty))
	rrEmpty := httptest.NewRecorder()
	handler.ServeHTTP(rrEmpty, reqEmpty)

	var respEmpty CheckResponse
	_ = json.Unmarshal(rrEmpty.Body.Bytes(), &respEmpty)
	if respEmpty.OK || respEmpty.Error == "" {
		t.Errorf("expected error for empty host/port, got: %+v", respEmpty)
	}
}

func TestCheckConnection_AuthFailure(t *testing.T) {
	srv, err := testupstream.StartWithOptions(testupstream.Options{
		Type:     "socks5",
		Username: "alice",
		Password: "correctpassword",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Addr())
	port, _ := strconv.Atoi(portStr)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	handler := APIHandler(configPath, "")

	// 1. Password passed directly in request with wrong password
	body, _ := json.Marshal(CheckRequest{
		Type:            "socks5",
		Host:            host,
		Port:            port,
		User:            "alice",
		Password:        "wrongpassword",
		PasswordChanged: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/check", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp CheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Errorf("expected OK=false for wrong password")
	}
	if !strings.Contains(resp.Error, "авториз") {
		t.Errorf("expected error message to mention authorization, got: %q", resp.Error)
	}

	// 2. Password read from credentials.toml with wrong password
	credPath := config.CredentialsPath(configPath)
	if err := config.SavePassword(credPath, "wrong_saved_password"); err != nil {
		t.Fatal(err)
	}
	bodySaved, _ := json.Marshal(CheckRequest{
		Type:            "socks5",
		Host:            host,
		Port:            port,
		User:            "alice",
		PasswordChanged: false,
	})
	reqSaved := httptest.NewRequest(http.MethodPost, "/api/check", bytes.NewReader(bodySaved))
	rrSaved := httptest.NewRecorder()
	handler.ServeHTTP(rrSaved, reqSaved)

	var respSaved CheckResponse
	if err := json.Unmarshal(rrSaved.Body.Bytes(), &respSaved); err != nil {
		t.Fatal(err)
	}
	if respSaved.OK {
		t.Errorf("expected OK=false for wrong saved password")
	}
	if !strings.Contains(respSaved.Error, "авториз") {
		t.Errorf("expected error message to mention authorization, got: %q", respSaved.Error)
	}
}

func TestStaticAssetsServing(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	handler, err := Handler(configPath, "")
	if err != nil {
		t.Fatalf("Handler failed: %v", err)
	}

	tests := []struct {
		path         string
		expectedCode int
		contains     string
	}{
		{"/", http.StatusOK, "Настройки gostpx"},
		{"/index.html", http.StatusMovedPermanently, ""},
		{"/style.css", http.StatusOK, "--primary-color"},
		{"/app.js", http.StatusOK, "loadSettings"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != tt.expectedCode {
			t.Errorf("expected %d for %s, got %d", tt.expectedCode, tt.path, rr.Code)
		}
		if tt.contains != "" && !strings.Contains(rr.Body.String(), tt.contains) {
			t.Errorf("path %s response missing %q", tt.path, tt.contains)
		}
	}
}

func TestSaveSettingsPasswordWithBulletAndUnchanged(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)

	def := config.DefaultConfig()
	def.Proxy.Host = "1.2.3.4"
	def.Proxy.Port = 1080
	def.Proxy.User = "myuser"
	if err := config.Save(configPath, def); err != nil {
		t.Fatal(err)
	}
	_ = config.SavePassword(credPath, "secret123")

	handler := APIHandler(configPath, "")

	// 1. PasswordChanged = false: password is NOT changed even if placeholder string is sent
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "1.2.3.4",
		ProxyPort:       1080,
		ProxyUser:       "myuser",
		DNSDoH:          def.DNS.DoH,
		Password:        "••••••••",
		PasswordChanged: false,
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	pwd, _ := config.LoadPassword(credPath)
	if pwd != "secret123" {
		t.Fatalf("expected password to remain 'secret123', got %q", pwd)
	}

	// 2. PasswordChanged = true and password actually contains '•': should be saved without false rejection!
	bulletPwd := "my•bullet•pass123"
	body, _ = json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "1.2.3.4",
		ProxyPort:       1080,
		ProxyUser:       "myuser",
		DNSDoH:          def.DNS.DoH,
		Password:        bulletPwd,
		PasswordChanged: true,
	})
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	pwd, _ = config.LoadPassword(credPath)
	if pwd != bulletPwd {
		t.Fatalf("expected password with bullet to be saved: want %q, got %q", bulletPwd, pwd)
	}
}

func TestSaveSettings_PasswordSaveFailureRollback(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialTOML := `version = 1
mode = "sysproxy"
autostart = false

[proxy]
type = "socks5"
host = "old.proxy.com"
port = 1080

[sysproxy]
http_listen = "127.0.0.1:8080"
socks_listen = "127.0.0.1:1080"

[ui]
config_writable = true
`
	if err := os.WriteFile(configPath, []byte(initialTOML), 0600); err != nil {
		t.Fatal(err)
	}

	// Make credentials path a non-empty directory so SavePassword fails
	credPath := config.CredentialsPath(configPath)
	if err := os.Mkdir(credPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credPath, "subfile"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "new.proxy.com",
		ProxyPort:       1080,
		Password:        "newpass",
		PasswordChanged: true,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 on password save failure, got %d: %s", rr.Code, rr.Body.String())
	}

	// Invariant: config.toml must be rolled back to old.proxy.com
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `host = "old.proxy.com"`) {
		t.Errorf("config.toml was not rolled back: %s", string(content))
	}
}

func TestSaveSettings_ClearPasswordFailureRollback(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialTOML := `version = 1
mode = "sysproxy"
autostart = false

[proxy]
type = "socks5"
host = "old.proxy.com"
port = 1080

[sysproxy]
http_listen = "127.0.0.1:8080"
socks_listen = "127.0.0.1:1080"

[ui]
config_writable = true
`
	if err := os.WriteFile(configPath, []byte(initialTOML), 0600); err != nil {
		t.Fatal(err)
	}

	// Make credentials path a non-empty directory so os.Remove in SavePassword fails
	credPath := config.CredentialsPath(configPath)
	if err := os.Mkdir(credPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credPath, "subfile"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:          "sysproxy",
		ProxyType:     "socks5",
		ProxyHost:     "new.proxy.com",
		ProxyPort:     1080,
		ClearPassword: true,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 on clear password failure, got %d: %s", rr.Code, rr.Body.String())
	}

	// Invariant: config.toml must be rolled back to old.proxy.com
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `host = "old.proxy.com"`) {
		t.Errorf("config.toml was not rolled back: %s", string(content))
	}
}

func TestSaveSettings_AutostartFailureRollback(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialTOML := `version = 1
mode = "sysproxy"
autostart = false

[proxy]
type = "socks5"
host = "old.proxy.com"
port = 1080

[sysproxy]
http_listen = "127.0.0.1:8080"
socks_listen = "127.0.0.1:1080"

[ui]
config_writable = true
`
	if err := os.WriteFile(configPath, []byte(initialTOML), 0600); err != nil {
		t.Fatal(err)
	}

	credPath := config.CredentialsPath(configPath)
	if err := config.SavePassword(credPath, "oldsecret"); err != nil {
		t.Fatal(err)
	}

	// Mock autostartSyncFn to fail
	origSync := autostartSyncFn
	autostartSyncFn = func(cfgAutostart bool, execPath string) (string, error) {
		return "", fmt.Errorf("simulated autostart failure")
	}
	defer func() { autostartSyncFn = origSync }()

	handler := APIHandler(configPath, "/fake/exec/path")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:            "sysproxy",
		ProxyType:       "socks5",
		ProxyHost:       "new.proxy.com",
		ProxyPort:       1080,
		Autostart:       true,
		Password:        "newsecret",
		PasswordChanged: true,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body)))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 on autostart failure, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "синхронизация автозапуска") {
		t.Errorf("expected error message to contain 'синхронизация автозапуска', got: %s", rr.Body.String())
	}

	// Invariant: config.toml must be rolled back
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `host = "old.proxy.com"`) {
		t.Errorf("config.toml was not rolled back: %s", string(content))
	}

	// Invariant: credentials.toml must be rolled back
	pwd, err := config.LoadPassword(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if pwd != "oldsecret" {
		t.Errorf("credentials.toml was not rolled back, expected 'oldsecret', got %q", pwd)
	}
}

func TestGetSettings_CredentialsMissingVsCorrupted(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	credPath := config.CredentialsPath(configPath)

	initialTOML := `version = 1
mode = "off"
[proxy]
type = "socks5"
host = "example.com"
port = 1080
`
	if err := os.WriteFile(configPath, []byte(initialTOML), 0600); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")

	// Case 1: Missing credentials file -> has_password: false, credentials_error: ""
	{
		req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var data SettingsData
		if err := json.NewDecoder(rr.Body).Decode(&data); err != nil {
			t.Fatal(err)
		}
		if data.HasPassword {
			t.Errorf("expected has_password false for missing credentials file")
		}
		if data.CredentialsError != "" {
			t.Errorf("expected empty credentials_error for missing credentials file, got: %q", data.CredentialsError)
		}
	}

	// Case 2: Corrupted credentials file -> has_password: false, credentials_error: nonempty
	{
		if err := os.WriteFile(credPath, []byte("password = unterminated string"), 0600); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var data SettingsData
		if err := json.NewDecoder(rr.Body).Decode(&data); err != nil {
			t.Fatal(err)
		}
		if data.HasPassword {
			t.Errorf("expected has_password false for corrupted credentials file")
		}
		if data.CredentialsError == "" {
			t.Errorf("expected non-empty credentials_error for corrupted credentials file")
		}
	}
}

func TestSaveSettings_BodyTooLarge(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	handler := APIHandler(configPath, "")

	// 70 KiB payload exceeds 64 KiB MaxBytesReader limit
	hugePayload := fmt.Sprintf(`{"mode":"sysproxy","proxy_host":"%s"}`, strings.Repeat("A", 70*1024))
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(hugePayload))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for payload exceeding 64 KiB, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSaveSettings_UnknownFields(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	handler := APIHandler(configPath, "")

	payload := `{"mode":"sysproxy","unknown_field_name":"bad"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown fields, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown field") {
		t.Errorf("expected error message to mention unknown field, got: %s", rr.Body.String())
	}
}

func TestSaveSettings_TrailingData(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	handler := APIHandler(configPath, "")

	payload := `{"mode":"off"} extra trailing tokens`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing data, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "extra data") {
		t.Errorf("expected error message to mention extra data, got: %s", rr.Body.String())
	}
}

func TestCheckConnection_TrailingData(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	handler := APIHandler(configPath, "")

	payload := `{"host":"127.0.0.1","port":1080} 123`
	req := httptest.NewRequest(http.MethodPost, "/api/check", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing data, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "extra data") {
		t.Errorf("expected error message to mention extra data, got: %s", rr.Body.String())
	}
}

func TestSaveSettings_RollbackDeletesCreatedConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// Ensure config.toml does NOT exist beforehand
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("expected config.toml to not exist initially")
	}

	// Mock autostartSyncFn to fail after config is updated
	origSync := autostartSyncFn
	autostartSyncFn = func(cfgAutostart bool, execPath string) (string, error) {
		return "", fmt.Errorf("simulated failure after creation")
	}
	defer func() { autostartSyncFn = origSync }()

	handler := APIHandler(configPath, "/fake/exec/path")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:      "sysproxy",
		ProxyType: "socks5",
		ProxyHost: "rollback.test.com",
		ProxyPort: 1080,
		Autostart: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}

	// Crucial check (Item 5): config.toml MUST NOT exist after rollback!
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Errorf("expected config.toml to be removed by rollback, but it still exists")
	}
	if _, err := os.Stat(configPath + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("expected config.toml.tmp to be cleaned up")
	}
	if _, err := os.Stat(configPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf("expected config.toml.bak to be cleaned up")
	}
}

func TestSaveSettings_AbortsOnUnreadableConfig(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a directory with the name config.toml so ReadFile fails with a non-ErrNotExist error (EISDIR)
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.Mkdir(configPath, 0755); err != nil {
		t.Fatal(err)
	}

	handler := APIHandler(configPath, "")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:      "sysproxy",
		ProxyType: "socks5",
		ProxyHost: "test.com",
		ProxyPort: 1080,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should abort with 500 without modifying directory
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "read config") {
		t.Errorf("expected error message to mention 'read config', got: %s", rr.Body.String())
	}
}

func TestSaveSettings_PreservesFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(configPath, []byte("version = 1\nmode = \"off\"\n"), 0640); err != nil {
		t.Fatal(err)
	}

	origSync := autostartSyncFn
	autostartSyncFn = func(cfgAutostart bool, execPath string) (string, error) {
		return "", fmt.Errorf("simulated failure")
	}
	defer func() { autostartSyncFn = origSync }()

	handler := APIHandler(configPath, "/fake/exec/path")
	body, _ := json.Marshal(SaveSettingsRequest{
		Mode:      "sysproxy",
		ProxyType: "socks5",
		ProxyHost: "perm.test.com",
		ProxyPort: 1080,
		Autostart: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}

	fi, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Errorf("expected permissions 0640 preserved, got %04o", fi.Mode().Perm())
	}
}

func TestMiddleware_PassesWailsRuntimeToNext(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	// Test with read-only config to ensure it is never blocked
	_ = os.WriteFile(configPath, []byte("version = 1\n[ui]\nconfig_writable = false\n"), 0600)

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if r.URL.Path != "/wails/runtime.js" {
			t.Errorf("unexpected path in next: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("// wails runtime mock"))
	})

	mw := Middleware(Options{ConfigPath: configPath})
	wrapped := mw(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/wails/runtime.js", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected next handler to be called for /wails/runtime.js")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "// wails runtime mock" {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}
