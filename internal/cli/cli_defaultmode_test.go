package cli

import (
	"path/filepath"
	"testing"

	"github.com/losoph/gostpx/internal/config"
)

func TestLoadOrCreateConfig_EmptyDefaultMode(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	cfg, _, err := loadOrCreateConfig(configPath)
	if err != nil {
		t.Fatalf("loadOrCreateConfig failed: %v", err)
	}
	if cfg.Mode != config.ModeSysproxy {
		t.Errorf("expected created config to have mode %q, got %q", config.ModeSysproxy, cfg.Mode)
	}

	// Verify from disk as well
	loaded, _, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("failed to reload config from disk: %v", err)
	}
	if loaded.Mode != config.ModeSysproxy {
		t.Errorf("expected saved config on disk to have mode %q, got %q", config.ModeSysproxy, loaded.Mode)
	}
}
