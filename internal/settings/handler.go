package settings

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/losoph/gostpx/internal/autostart"
	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/engine"
)

//go:embed assets/*
var Assets embed.FS

var autostartSyncFn = autostart.Sync

// AssetsFS returns an fs.FS rooted at the assets directory.
func AssetsFS() (fs.FS, error) {
	return fs.Sub(Assets, "assets")
}

// SettingsData represents the payload returned to the frontend.
type SettingsData struct {
	Mode             string `json:"mode"`
	Autostart        bool   `json:"autostart"`
	Autoconnect      bool   `json:"autoconnect"`
	ProxyType        string `json:"proxy_type"`
	ProxyHost        string `json:"proxy_host"`
	ProxyPort        int    `json:"proxy_port"`
	ProxyUser        string `json:"proxy_user"`
	HasPassword      bool   `json:"has_password"`
	CredentialsError string `json:"credentials_error,omitempty"`
	DNSDoH           string `json:"dns_doh"`
	ConfigWritable   bool   `json:"config_writable"`
}

// SaveSettingsRequest represents the payload received from the frontend on save.
type SaveSettingsRequest struct {
	Mode            string `json:"mode"`
	Autostart       bool   `json:"autostart"`
	Autoconnect     bool   `json:"autoconnect"`
	ProxyType       string `json:"proxy_type"`
	ProxyHost       string `json:"proxy_host"`
	ProxyPort       int    `json:"proxy_port"`
	ProxyUser       string `json:"proxy_user"`
	Password        string `json:"password"`
	PasswordChanged bool   `json:"password_changed"`
	ClearPassword   bool   `json:"clear_password"`
	DNSDoH          string `json:"dns_doh"`
}

// Options defines settings handler options.
type Options struct {
	ConfigPath  string
	CurrentExec string
	OnSaved     func(changedProxy bool)
}

// CheckRequest represents a proxy connectivity check request.
type CheckRequest struct {
	Type            string `json:"type"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	User            string `json:"user"`
	Password        string `json:"password"`
	PasswordChanged bool   `json:"password_changed"`
}

// CheckResponse represents the result of a proxy connectivity check.
type CheckResponse struct {
	OK    bool   `json:"ok"`
	RTTMs int64  `json:"rtt_ms,omitempty"`
	Error string `json:"error,omitempty"`
}

// APIHandler creates an http.Handler that processes /api/settings and /api/check requests.
func APIHandler(configPath, currentExec string) http.Handler {
	return APIHandlerWithOptions(Options{ConfigPath: configPath, CurrentExec: currentExec})
}

// APIHandlerWithOptions creates an http.Handler with custom Options.
func APIHandlerWithOptions(opts Options) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSettings(w, r, opts.ConfigPath)
		case http.MethodPost:
			handleSaveSettings(w, r, opts)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleCheckConnection(w, r, opts.ConfigPath)
	})

	return mux
}

// Handler returns a combined http.Handler serving both the /api/* endpoints and the embedded frontend assets.
func Handler(configPath, currentExec string) (http.Handler, error) {
	return HandlerWithOptions(Options{ConfigPath: configPath, CurrentExec: currentExec})
}

// HandlerWithOptions returns a combined http.Handler with custom Options.
func HandlerWithOptions(opts Options) (http.Handler, error) {
	subFS, err := AssetsFS()
	if err != nil {
		return nil, fmt.Errorf("assets fs: %w", err)
	}
	fileServer := http.FileServer(http.FS(subFS))
	api := APIHandlerWithOptions(opts)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	}), nil
}

// Middleware returns a middleware function compatible with Wails v3 AssetOptions.Middleware.
func Middleware(opts Options) func(http.Handler) http.Handler {
	api := APIHandlerWithOptions(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				api.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("extra data after JSON object")
	}
	return nil
}

func handleGetSettings(w http.ResponseWriter, r *http.Request, configPath string) {
	cfg, _, err := config.Load(configPath)
	if err != nil || cfg == nil {
		cfg = config.DefaultConfig()
	}

	credPath := config.CredentialsPath(configPath)
	pwd, credErr := config.LoadPassword(credPath)
	hasPassword := pwd != ""
	var credErrStr string
	if credErr != nil {
		credErrStr = credErr.Error()
	}

	data := SettingsData{
		Mode:             cfg.Mode,
		Autostart:        cfg.Autostart,
		Autoconnect:      cfg.Autoconnect,
		ProxyType:        cfg.Proxy.Type,
		ProxyHost:        cfg.Proxy.Host,
		ProxyPort:        cfg.Proxy.Port,
		ProxyUser:        cfg.Proxy.User,
		HasPassword:      hasPassword,
		CredentialsError: credErrStr,
		DNSDoH:           cfg.DNS.DoH,
		ConfigWritable:   cfg.UI.ConfigWritable,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(data)
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request, opts Options) {
	configPath := opts.ConfigPath
	currentExec := opts.CurrentExec
	var req SaveSettingsRequest
	if err := decodeJSON(w, r, &req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": fmt.Sprintf("invalid JSON: %v", err)})
		return
	}

	// 1. Initial snapshot of config and credentials BEFORE any operations (Items 5, 7, 8)
	var configBackup []byte
	configExisted := true
	if data, err := os.ReadFile(configPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			configExisted = false
		} else {
			// Item 7: abort on non-ErrNotExist before any modifications
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": fmt.Sprintf("read config: %v", err)})
			return
		}
	} else {
		configBackup = data
	}

	var configMode os.FileMode = 0600
	if fi, err := os.Stat(configPath); err == nil && fi.Mode().IsRegular() {
		configMode = fi.Mode().Perm()
	}

	credPath := config.CredentialsPath(configPath)
	var credBackup []byte
	credExisted := true
	if data, err := os.ReadFile(credPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			credExisted = false
		} else {
			// Item 7: abort on non-ErrNotExist before any modifications
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": fmt.Sprintf("read credentials: %v", err)})
			return
		}
	} else {
		credBackup = data
	}

	var credMode os.FileMode = 0600
	if fi, err := os.Stat(credPath); err == nil && fi.Mode().IsRegular() {
		credMode = fi.Mode().Perm()
	}

	rollbackConfig := func() error {
		var errs []string
		if configExisted {
			if err := os.WriteFile(configPath, configBackup, configMode); err != nil {
				errs = append(errs, fmt.Sprintf("restore config: %v", err))
			} else {
				_ = os.Chmod(configPath, configMode)
			}
		} else {
			// Item 5: config did not exist before request, remove created config and any .bak/.tmp
			if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Sprintf("remove created config: %v", err))
			}
		}
		_ = os.Remove(configPath + ".tmp")
		_ = os.Remove(configPath + ".bak")
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
	}

	rollbackCred := func() error {
		var errs []string
		if credExisted {
			if err := os.WriteFile(credPath, credBackup, credMode); err != nil {
				errs = append(errs, fmt.Sprintf("restore credentials: %v", err))
			} else {
				_ = os.Chmod(credPath, credMode)
			}
		} else {
			if err := os.Remove(credPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Sprintf("remove created credentials: %v", err))
			}
		}
		_ = os.Remove(credPath + ".tmp")
		_ = os.Remove(credPath + ".bak")
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
	}

	applyRollback := func(origErr error) string {
		var rbErrs []string
		if err := rollbackCred(); err != nil {
			rbErrs = append(rbErrs, err.Error())
		}
		if err := rollbackConfig(); err != nil {
			rbErrs = append(rbErrs, err.Error())
		}
		if len(rbErrs) > 0 {
			rbMsg := strings.Join(rbErrs, "; ")
			log.Printf("settings: ошибка сохранения (%v), откат не удался: %s", origErr, rbMsg)
			return fmt.Sprintf("%v (откат не удался: %s)", origErr, rbMsg)
		}
		return origErr.Error()
	}

	// 2. Check existing config for ui.config_writable
	cfg, _, err := config.Load(configPath)
	if errors.Is(err, os.ErrNotExist) {
		def := config.DefaultConfig()
		if err := config.Save(configPath, def); err != nil {
			_ = rollbackConfig()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": fmt.Sprintf("create config: %v", err)})
			return
		}
		cfg = def
	} else if err != nil && cfg == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": fmt.Sprintf("read config: %v", err)})
		return
	}

	if cfg != nil && !cfg.UI.ConfigWritable {
		if !configExisted {
			_ = rollbackConfig()
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "Конфигурация защищена от записи (ui.config_writable = false)"})
		return
	}

	// 3. Prepare surgical in-place updates map
	updates := map[string]any{
		"mode":       req.Mode,
		"autostart":  req.Autostart,
		"proxy.type": req.ProxyType,
		"proxy.host": req.ProxyHost,
		"proxy.port": req.ProxyPort,
		"proxy.user": req.ProxyUser,
		"dns.doh":    req.DNSDoH,
	}

	proxyIdentityChanged := cfg != nil && (cfg.Proxy.Type != req.ProxyType ||
		cfg.Proxy.Host != req.ProxyHost ||
		cfg.Proxy.Port != req.ProxyPort ||
		cfg.Proxy.User != req.ProxyUser)

	// 4. Update password in credentials.toml (ADR-011)
	// A proxy change without a re-entered password clears credentials.toml so a new proxy never gets the old one.
	var saveCredErr error
	passwordCleared := false
	if req.ClearPassword {
		saveCredErr = config.SavePassword(credPath, "")
		passwordCleared = true
	} else if req.PasswordChanged && req.Password != "" {
		saveCredErr = config.SavePassword(credPath, req.Password)
	} else if proxyIdentityChanged {
		// An emptied field on the same proxy is not a request to clear (that is
		// ClearPassword); on a changed proxy the old password must not carry over.
		saveCredErr = config.SavePassword(credPath, "")
		passwordCleared = true
	}

	if saveCredErr != nil {
		errMsg := applyRollback(fmt.Errorf("сохранение пароля: %w", saveCredErr))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": errMsg})
		return
	}

	// 5. Update config file surgically preserving comments byte-for-byte
	if err := config.UpdateFile(configPath, updates); err != nil {
		errMsg := applyRollback(err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if errors.Is(err, config.ErrConfigReadOnly) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "Конфигурация защищена от записи (ui.config_writable = false)"})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": fmt.Sprintf("Ошибка сохранения: %s", errMsg)})
		return
	}

	// 6. Sync autostart if requested and currentExec is known
	if currentExec != "" {
		if _, err := autostartSyncFn(req.Autostart, currentExec); err != nil {
			errMsg := applyRollback(fmt.Errorf("синхронизация автозапуска: %w", err))
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": errMsg})
			return
		}
	}

	// 7. Check if proxy or credentials changed and invoke OnSaved callback
	changedProxy := false
	if cfg == nil {
		changedProxy = true
	} else {
		if cfg.Mode != req.Mode ||
			cfg.Proxy.Type != req.ProxyType ||
			cfg.Proxy.Host != req.ProxyHost ||
			cfg.Proxy.Port != req.ProxyPort ||
			cfg.Proxy.User != req.ProxyUser {
			changedProxy = true
		}
	}
	if req.ClearPassword && credExisted && len(credBackup) > 0 {
		changedProxy = true
	}
	if req.PasswordChanged && req.Password != "" {
		changedProxy = true
	}
	if passwordCleared && credExisted && len(credBackup) > 0 {
		changedProxy = true
	}

	if opts.OnSaved != nil {
		opts.OnSaved(changedProxy)
	}

	resp := map[string]any{"success": true}
	if passwordCleared {
		resp["password_cleared"] = true
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleCheckConnection(w http.ResponseWriter, r *http.Request, configPath string) {
	var req CheckRequest
	if err := decodeJSON(w, r, &req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(CheckResponse{
			OK:    false,
			Error: fmt.Sprintf("invalid JSON: %v", err),
		})
		return
	}

	host := strings.TrimSpace(req.Host)
	port := req.Port
	proxyType := strings.TrimSpace(req.Type)
	user := strings.TrimSpace(req.User)

	cfg, _, _ := config.Load(configPath)

	if host == "" || port <= 0 {
		if cfg != nil {
			if host == "" {
				host = cfg.Proxy.Host
			}
			if port <= 0 {
				port = cfg.Proxy.Port
			}
			if proxyType == "" {
				proxyType = cfg.Proxy.Type
			}
			if user == "" {
				user = cfg.Proxy.User
			}
		}
	}

	if proxyType == "" {
		proxyType = config.ProxyTypeSOCKS5
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if host == "" || port <= 0 {
		_ = json.NewEncoder(w).Encode(CheckResponse{
			OK:    false,
			Error: "хост или порт не указаны",
		})
		return
	}

	var proxyDiffers bool
	if cfg != nil && (cfg.Proxy.Host != "" || cfg.Proxy.Port > 0) {
		proxyDiffers = cfg.Proxy.Type != proxyType ||
			cfg.Proxy.Host != host ||
			cfg.Proxy.Port != port ||
			cfg.Proxy.User != user
	}

	var plainSecret string
	if req.PasswordChanged {
		plainSecret = req.Password
	} else if !proxyDiffers {
		credPath := config.CredentialsPath(configPath)
		plainSecret, _ = config.LoadPassword(credPath)
	}

	pCfg := config.ProxyConfig{
		Type: proxyType,
		Host: host,
		Port: port,
		User: user,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rtt, err := engine.VerifyUpstream(ctx, pCfg, plainSecret, 5*time.Second)
	if err != nil {
		_ = json.NewEncoder(w).Encode(CheckResponse{
			OK:    false,
			Error: err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(CheckResponse{
		OK:    true,
		RTTMs: rtt.Milliseconds(),
	})
}
