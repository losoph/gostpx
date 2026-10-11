package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/losoph/gostpx/internal/sysproxy"
)

// State represents the runtime state persisted in state.json.
type State struct {
	Mode                 string             `json:"mode"`
	ActiveSession        bool               `json:"active_session"`
	PID                  int                `json:"pid,omitempty"`
	CachedExternalIP     string             `json:"cached_external_ip,omitempty"`
	CachedCountry        string             `json:"cached_country,omitempty"`
	LastConnected        time.Time          `json:"last_connected,omitzero"`
	LastDisconnectReason string             `json:"last_disconnect_reason,omitempty"`
	SysproxySnapshot     *sysproxy.Snapshot `json:"sysproxy_snapshot,omitempty"`
	NetworkDown          bool               `json:"network_down,omitempty"`
	Reconnecting         bool               `json:"reconnecting,omitempty"`
	ReconnectAttempt     int                `json:"reconnect_attempt,omitempty"`
	NextReconnect        time.Time          `json:"next_reconnect,omitzero"`
}

// DefaultState returns the default initial state.
func DefaultState() *State {
	return &State{
		Mode:          "sysproxy",
		ActiveSession: false,
	}
}

// DefaultStatePath returns the path to state.json according to OS conventions.
func DefaultStatePath() (string, error) {
	if dir := os.Getenv("GOSTPX_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "state.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, "gostpx", "state.json"), nil
		}
		return filepath.Join(home, "AppData", "Roaming", "gostpx", "state.json"), nil
	}
	// macOS
	return filepath.Join(home, "Library", "Application Support", "gostpx", "state.json"), nil
}

// Load reads the state from the given path.
// If the file does not exist, returns DefaultState() and nil error.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultState(), nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	st := DefaultState()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("unmarshal state json: %w", err)
	}
	return st, nil
}

// Save atomically writes the state to path (via temp file and rename).
func Save(path string, st *State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("write state tmp file: %w", err)
	}

	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("rename state file: %w", err)
	}

	return nil
}
