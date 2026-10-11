package engine

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

func TestConfigWatcher(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	initialCfg := config.DefaultConfig()
	initialCfg.Proxy.Host = "1.2.3.4"
	initialCfg.Proxy.Port = 1080
	initialCfg.DNS.DoH = "https://dns.google/dns-query"
	if err := config.Save(configPath, initialCfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	var (
		mu          sync.Mutex
		reloadedCfg *config.Config
		reloadErr   error
	)
	reloaded := make(chan struct{}, 1)
	errored := make(chan struct{}, 1)

	cw, err := NewConfigWatcher(
		configPath,
		initialCfg,
		func(newCfg *config.Config, requiresRestart bool) {
			mu.Lock()
			reloadedCfg = newCfg
			mu.Unlock()
			select {
			case reloaded <- struct{}{}:
			default:
			}
		},
		func(err error, issues []config.Issue) {
			mu.Lock()
			reloadErr = err
			mu.Unlock()
			select {
			case errored <- struct{}{}:
			default:
			}
		},
	)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	if err := cw.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer func() { _ = cw.Stop() }()

	// 1. Valid update
	updatedCfg := config.DefaultConfig()
	updatedCfg.Proxy.Host = "1.2.3.4"
	updatedCfg.Proxy.Port = 1080
	updatedCfg.DNS.DoH = "https://1.1.1.1/dns-query"
	if err := config.Save(configPath, updatedCfg); err != nil {
		t.Fatalf("failed to write updated config: %v", err)
	}

	select {
	case <-reloaded:
		mu.Lock()
		if reloadedCfg.DNS.DoH != "https://1.1.1.1/dns-query" {
			t.Errorf("expected DoH to be https://1.1.1.1/dns-query, got: %s", reloadedCfg.DNS.DoH)
		}
		mu.Unlock()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for config reload")
	}

	// 2. Corrupt update (broken syntax)
	badContent := []byte(`
version = 1
[broken
`)
	if err := os.WriteFile(configPath, badContent, 0600); err != nil {
		t.Fatalf("failed to write broken config: %v", err)
	}

	select {
	case <-errored:
		mu.Lock()
		if reloadErr == nil {
			t.Error("expected reloadErr on broken config, got nil")
		}
		mu.Unlock()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for config error on broken TOML")
	}

	// 3. Verify .bak and .tmp files are ignored (Point 8)
	bakPath := configPath + ".bak"
	if err := os.WriteFile(bakPath, []byte("version = 1\n"), 0600); err != nil {
		t.Fatalf("failed to write .bak: %v", err)
	}
	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte("version = 1\n"), 0600); err != nil {
		t.Fatalf("failed to write .tmp: %v", err)
	}

	select {
	case <-reloaded:
		t.Error("watcher triggered reload on .bak or .tmp file")
	case <-errored:
		t.Error("watcher triggered error on .bak or .tmp file")
	case <-time.After(200 * time.Millisecond):
		// Expected: ignored
	}
}
