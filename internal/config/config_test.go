package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseValidConfig(t *testing.T) {
	data := []byte(`
version = 1
mode = "sysproxy"
autostart = false
autoconnect = true

[proxy]
type = "socks5"
host = "test.proxy.net"
port = 1080
user = "alice"

[dns]
doh = "https://1.1.1.1/dns-query"

[sysproxy]
http_listen = "127.0.0.1:8888"
socks_listen = "127.0.0.1:1088"

[health]
probe_interval = "30s"

[log]
level = "debug"

[ui]
config_writable = false
`)

	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if cfg.Version != 1 || cfg.Mode != ModeSysproxy || cfg.Autostart != false || cfg.Autoconnect != true {
		t.Errorf("top-level fields mismatch: %+v", cfg)
	}
	if cfg.Proxy.Type != "socks5" || cfg.Proxy.Host != "test.proxy.net" || cfg.Proxy.Port != 1080 || cfg.Proxy.User != "alice" {
		t.Errorf("proxy config mismatch: %+v", cfg.Proxy)
	}
	if cfg.DNS.DoH != "https://1.1.1.1/dns-query" {
		t.Errorf("doh mismatch: %s", cfg.DNS.DoH)
	}
	if cfg.Sysproxy.HTTPListen != "127.0.0.1:8888" || cfg.Sysproxy.SOCKSListen != "127.0.0.1:1088" {
		t.Errorf("sysproxy listen mismatch: %+v", cfg.Sysproxy)
	}
	if cfg.ProbeDuration().Seconds() != 30 {
		t.Errorf("probe interval mismatch: %v", cfg.ProbeDuration())
	}
	if cfg.Log.Level != "debug" || cfg.UI.ConfigWritable != false {
		t.Errorf("log or ui mismatch: log=%s, ui=%v", cfg.Log.Level, cfg.UI.ConfigWritable)
	}

	issues := Validate(cfg)
	if len(issues) != 0 {
		t.Errorf("expected no issues for valid config, got: %v", issues)
	}
}

func TestParseUTF8BOM(t *testing.T) {
	// Prepend UTF-8 BOM: 0xEF, 0xBB, 0xBF
	raw := []byte("\xef\xbb\xbfversion = 1\nmode = \"sysproxy\"\n\n[proxy]\nhost = \"example.com\"\nport = 8080\n")
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse TOML with UTF-8 BOM: %v", err)
	}
	if cfg.Version != 1 || cfg.Mode != ModeSysproxy || cfg.Proxy.Host != "example.com" {
		t.Errorf("parsed config mismatch: %+v", cfg)
	}
}

func TestParseCorruptTOML(t *testing.T) {
	badData := []byte(`
version = 1
mode = "tun"
[proxy
host = "broken"
`)
	_, err := Parse(badData)
	if err == nil {
		t.Fatal("expected error parsing corrupt TOML, got nil")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "line") {
		t.Errorf("expected error message to contain line number, got: %s", errStr)
	}
}

func TestValidateErrorsAndWarnings(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Version = 2
	cfg.Mode = "invalid_mode"
	cfg.Proxy.Type = "unknown_type"
	cfg.Proxy.Host = ""
	cfg.Proxy.Port = 99999
	cfg.Proxy.Secret = "plainpassword"
	cfg.DNS.DoH = "not-a-url"
	cfg.Sysproxy.HTTPListen = "invalid"
	cfg.Health.ProbeInterval = "invalid"
	cfg.Log.Level = "invalid_level"

	issues := Validate(cfg)
	if len(issues) == 0 {
		t.Fatal("expected validation issues, got none")
	}

	hasWarning := false
	hasErrors := false
	for _, issue := range issues {
		if issue.IsWarning {
			hasWarning = true
			if issue.Field != "proxy.secret" {
				t.Errorf("unexpected warning field: %s", issue.Field)
			}
		} else {
			hasErrors = true
		}
	}

	if !hasWarning {
		t.Error("expected a warning for plain-text password in secret")
	}
	if !hasErrors {
		t.Error("expected validation errors")
	}
}

func TestValidateUnsupportedProxyTypes(t *testing.T) {
	for _, unsupported := range []string{"wireguard", "shadowsocks", "ss"} {
		cfg := DefaultConfig()
		cfg.Proxy.Type = unsupported
		cfg.Proxy.Host = "example.com"
		cfg.Proxy.Port = 1080

		issues := Validate(cfg)
		found := false
		for _, issue := range issues {
			if issue.Field == "proxy.type" && strings.Contains(issue.Message, "unsupported proxy type") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected validation error for unsupported proxy type %q, got: %v", unsupported, issues)
		}
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	cfg := DefaultConfig()
	cfg.Proxy.Host = "proxy.saved.net"
	cfg.Proxy.Port = 8000

	if err := Save(configPath, cfg); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	loaded, issues, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load saved config: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("unexpected validation issues on loaded config: %v", issues)
	}
	if loaded.Proxy.Host != "proxy.saved.net" || loaded.Proxy.Port != 8000 {
		t.Errorf("loaded values mismatch: %+v", loaded.Proxy)
	}
}

func TestValidateLineAndColumn(t *testing.T) {
	raw := []byte(`version = 1
mode = "sysproxy"

[proxy]
type = "socks5"
host = "proxy.example.com"
port = 99999
secret = "plainpassword"
`)
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	issues := Validate(cfg, raw)
	if len(issues) == 0 {
		t.Fatal("expected issues, got none")
	}

	foundPort := false
	foundSecret := false
	for _, issue := range issues {
		if issue.Field == "proxy.port" {
			foundPort = true
			if issue.Line != 7 || issue.Column != 1 {
				t.Errorf("proxy.port position mismatch: line=%d col=%d, want line=7 col=1", issue.Line, issue.Column)
			}
		}
		if issue.Field == "proxy.secret" {
			foundSecret = true
			if issue.Line != 8 || issue.Column != 1 {
				t.Errorf("proxy.secret position mismatch: line=%d col=%d, want line=8 col=1", issue.Line, issue.Column)
			}
		}
	}

	if !foundPort {
		t.Error("expected issue for proxy.port")
	}
	if !foundSecret {
		t.Error("expected issue for proxy.secret")
	}
}

func TestSaveBackup(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	bakPath := filepath.Join(tmpDir, "config.toml.bak")

	cfg1 := DefaultConfig()
	cfg1.Proxy.Host = "initial.host"
	if err := Save(configPath, cfg1); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	// First save: no .bak should exist yet
	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Error("expected no .bak file on initial save")
	}

	// Second save: should create .bak containing initial.host
	cfg2 := DefaultConfig()
	cfg2.Proxy.Host = "updated.host"
	if err := Save(configPath, cfg2); err != nil {
		t.Fatalf("failed to save updated config: %v", err)
	}

	bakData, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("failed to read .bak file: %v", err)
	}
	if !strings.Contains(string(bakData), "initial.host") {
		t.Errorf("backup does not contain initial config content: %s", string(bakData))
	}
}

func TestDefaultConfigAutostartDefaultFalse(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Autostart {
		t.Errorf("expected DefaultConfig().Autostart to be false per ADR-014, got true")
	}
}

func TestDefaultConfigModeSysproxy(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Mode != ModeSysproxy {
		t.Errorf("expected DefaultConfig().Mode to be %q, got %q", ModeSysproxy, cfg.Mode)
	}
}
