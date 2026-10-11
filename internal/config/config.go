package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Supported modes
const (
	ModeTun      = "tun"
	ModeSysproxy = "sysproxy"
	ModeOff      = "off"
)

// Supported proxy types in Phase 1
const (
	ProxyTypeSOCKS5 = "socks5"
	ProxyTypeHTTP   = "http"
	ProxyTypeSSH    = "ssh"
)

// Config represents the complete gostpx configuration file (config.toml).
type Config struct {
	Version     int            `toml:"version"`
	Mode        string         `toml:"mode"`
	Autostart   bool           `toml:"autostart"`
	Autoconnect bool           `toml:"autoconnect"`
	Proxy       ProxyConfig    `toml:"proxy"`
	DNS         DNSConfig      `toml:"dns"`
	Sysproxy    SysproxyConfig `toml:"sysproxy"`
	Health      HealthConfig   `toml:"health"`
	Log         LogConfig      `toml:"log"`
	UI          UIConfig       `toml:"ui"`
}

type ProxyConfig struct {
	Type string `toml:"type"`
	Host string `toml:"host"`
	Port int    `toml:"port"`
	User string `toml:"user,omitempty"`
	// Secret is deprecated (ADR-011): the password lives in credentials.toml.
	// Kept only so that older configs with `secret = "keyring:proxy"` still parse.
	Secret string `toml:"secret,omitempty"`
}

type DNSConfig struct {
	DoH string `toml:"doh"`
}

type SysproxyConfig struct {
	HTTPListen  string `toml:"http_listen"`
	SOCKSListen string `toml:"socks_listen"`
}

type HealthConfig struct {
	ProbeInterval string `toml:"probe_interval"`
}

type LogConfig struct {
	Level string `toml:"level"`
}

type UIConfig struct {
	ConfigWritable bool `toml:"config_writable"`
}

// Issue represents a validation error or warning.
type Issue struct {
	Field     string
	Message   string
	Line      int
	Column    int
	IsWarning bool
}

func (i Issue) String() string {
	prefix := "error"
	if i.IsWarning {
		prefix = "warning"
	}
	if i.Line > 0 {
		return fmt.Sprintf("[%s] line %d, col %d (%s): %s", prefix, i.Line, i.Column, i.Field, i.Message)
	}
	if i.Field != "" {
		return fmt.Sprintf("[%s] (%s): %s", prefix, i.Field, i.Message)
	}
	return fmt.Sprintf("[%s]: %s", prefix, i.Message)
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Version:     1,
		Mode:        ModeSysproxy,
		Autostart:   false,
		Autoconnect: true,
		Proxy: ProxyConfig{
			Type: ProxyTypeSOCKS5,
			Host: "",
			Port: 0,
			User: "",
		},
		DNS: DNSConfig{
			DoH: "https://dns.google/dns-query",
		},
		Sysproxy: SysproxyConfig{
			HTTPListen:  "127.0.0.1:8080",
			SOCKSListen: "127.0.0.1:1080",
		},
		Health: HealthConfig{
			ProbeInterval: "60s",
		},
		Log: LogConfig{
			Level: "info",
		},
		UI: UIConfig{
			ConfigWritable: true,
		},
	}
}

// ProbeDuration parses Health.ProbeInterval or returns the default 60s.
func (c *Config) ProbeDuration() time.Duration {
	if c.Health.ProbeInterval == "" {
		return 60 * time.Second
	}
	d, err := time.ParseDuration(c.Health.ProbeInterval)
	if err != nil || d <= 0 {
		return 60 * time.Second
	}
	return d
}

// ConfigDir returns the default directory for user configuration files.
func ConfigDir() (string, error) {
	if dir := os.Getenv("GOSTPX_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, "gostpx"), nil
		}
		return filepath.Join(home, "AppData", "Roaming", "gostpx"), nil
	}
	// macOS
	return filepath.Join(home, "Library", "Application Support", "gostpx"), nil
}

// DefaultConfigPath returns the default absolute path to config.toml.
func DefaultConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

// Parse parses TOML bytes into Config with defaults applied.
// Strips UTF-8 BOM if present.
func Parse(data []byte) (*Config, error) {
	// Strip UTF-8 BOM
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	cfg := DefaultConfig()
	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cfg); err != nil {
		var decodeErr *toml.DecodeError
		if errors.As(err, &decodeErr) {
			row, col := decodeErr.Position()
			return nil, fmt.Errorf("line %d, col %d: %s", row, col, decodeErr.String())
		}
		return nil, fmt.Errorf("decode toml: %w", err)
	}

	return cfg, nil
}

// Load reads and parses the configuration file at the given path.
// Returns loaded config, validation issues, or an error if loading/parsing fails.
func Load(path string) (*Config, []Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config file: %w", err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}

	issues := Validate(cfg, data)
	return cfg, issues, nil
}

// Save writes the configuration to the specified path in TOML format.
// If the destination file already exists, it creates a backup copy at path + ".bak" (ADR-007).
func Save(path string, cfg *Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// Backup existing file before overwriting (ADR-007)
	if existingData, err := os.ReadFile(path); err == nil {
		bakPath := path + ".bak"
		_ = os.WriteFile(bakPath, existingData, 0600)
	}

	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("encode toml: %w", err)
	}

	// Write to temporary file first then rename atomically
	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// Validate checks the configuration against specification rules.
// If raw TOML source bytes are provided, it accurately populates Line and Column for each Issue.
func Validate(cfg *Config, source ...[]byte) []Issue {
	var raw []byte
	if len(source) > 0 {
		raw = source[0]
	}

	var issues []Issue
	addIssue := func(issue Issue) {
		if len(raw) > 0 && issue.Field != "" {
			issue.Line, issue.Column = findFieldPosition(raw, issue.Field)
		}
		issues = append(issues, issue)
	}

	if cfg.Version != 1 {
		addIssue(Issue{
			Field:   "version",
			Message: fmt.Sprintf("unsupported version %d, expected 1", cfg.Version),
		})
	}

	switch cfg.Mode {
	case ModeTun, ModeSysproxy, ModeOff:
		// ok
	default:
		addIssue(Issue{
			Field:   "mode",
			Message: fmt.Sprintf("invalid mode %q (must be 'tun', 'sysproxy', or 'off')", cfg.Mode),
		})
	}

	// Proxy validation
	switch cfg.Proxy.Type {
	case ProxyTypeSOCKS5, ProxyTypeHTTP, ProxyTypeSSH:
		// ok
	default:
		addIssue(Issue{
			Field:   "proxy.type",
			Message: fmt.Sprintf("unsupported proxy type %q (allowed: socks5, http, ssh)", cfg.Proxy.Type),
		})
	}

	if cfg.Proxy.Host == "" && cfg.Mode != ModeOff {
		addIssue(Issue{
			Field:   "proxy.host",
			Message: "proxy host cannot be empty when mode is not 'off'",
		})
	}

	if cfg.Proxy.Port < 1 || cfg.Proxy.Port > 65535 {
		if cfg.Mode != ModeOff || cfg.Proxy.Port != 0 {
			addIssue(Issue{
				Field:   "proxy.port",
				Message: fmt.Sprintf("invalid proxy port %d (must be between 1 and 65535)", cfg.Proxy.Port),
			})
		}
	}

	// Deprecated secret field (ADR-011): ignored, the password lives in credentials.toml.
	if cfg.Proxy.Secret != "" {
		addIssue(Issue{
			Field:     "proxy.secret",
			Message:   "proxy.secret is deprecated and ignored: remove the line and set the password with 'gostpx set' (stored in " + CredentialsFileName + ")",
			IsWarning: true,
		})
	}

	// DNS validation
	if cfg.DNS.DoH != "" {
		u, err := url.Parse(cfg.DNS.DoH)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			addIssue(Issue{
				Field:   "dns.doh",
				Message: fmt.Sprintf("invalid DoH URL %q, must be valid HTTP/HTTPS URL", cfg.DNS.DoH),
			})
		}
	}

	// Sysproxy addresses validation
	validateHostPort := func(field, addr string) {
		if addr == "" {
			addIssue(Issue{
				Field:   field,
				Message: "listen address cannot be empty",
			})
			return
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			addIssue(Issue{
				Field:   field,
				Message: fmt.Sprintf("invalid listen address %q (expected host:port): %v", addr, err),
			})
			return
		}
		if host == "" {
			addIssue(Issue{
				Field:   field,
				Message: "listen host cannot be empty",
			})
		}
		if port == "" {
			addIssue(Issue{
				Field:   field,
				Message: "listen port cannot be empty",
			})
		}
	}

	validateHostPort("sysproxy.http_listen", cfg.Sysproxy.HTTPListen)
	validateHostPort("sysproxy.socks_listen", cfg.Sysproxy.SOCKSListen)

	// Health interval validation
	if cfg.Health.ProbeInterval != "" {
		d, err := time.ParseDuration(cfg.Health.ProbeInterval)
		if err != nil || d <= 0 {
			addIssue(Issue{
				Field:   "health.probe_interval",
				Message: fmt.Sprintf("invalid duration %q (must be positive duration like '60s')", cfg.Health.ProbeInterval),
			})
		}
	}

	// Log level validation
	switch strings.ToLower(cfg.Log.Level) {
	case "debug", "info", "warn", "warning", "error":
		// ok
	default:
		addIssue(Issue{
			Field:   "log.level",
			Message: fmt.Sprintf("invalid log level %q (allowed: debug, info, warn, error)", cfg.Log.Level),
		})
	}

	return issues
}

// findFieldPosition searches TOML source bytes for the line and column of a field.
// Supports top-level keys (e.g. "version", "mode") and section keys (e.g. "proxy.port").
func findFieldPosition(source []byte, field string) (int, int) {
	if len(source) == 0 {
		return 0, 0
	}
	var targetSection, targetKey string
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		targetSection = parts[0]
		targetKey = parts[1]
	} else {
		targetKey = field
	}

	scanner := bufio.NewScanner(bytes.NewReader(source))
	lineNum := 0
	currentSection := ""

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentSection = strings.Trim(trimmed, "[] \t")
			continue
		}

		if currentSection == targetSection {
			eqIdx := strings.Index(line, "=")
			if eqIdx > 0 {
				keyCandidate := strings.TrimSpace(line[:eqIdx])
				if keyCandidate == targetKey {
					col := strings.Index(line, targetKey) + 1
					return lineNum, col
				}
			}
		}
	}
	return 0, 0
}
