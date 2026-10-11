package session

import (
	"path/filepath"
	"testing"

	"github.com/losoph/gostpx/internal/config"
)

func TestRestartPendingOnConfigReload(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	initialCfg := config.DefaultConfig()
	initialCfg.Proxy.Host = "1.2.3.4"
	initialCfg.Proxy.Port = 1080
	initialCfg.Health.ProbeInterval = "30s"
	_ = config.Save(configPath, initialCfg)
	_ = config.SavePassword(config.CredentialsPath(configPath), "pass1")

	sess := New(configPath, statePath)
	sess.active = true
	sess.cfg = initialCfg
	sess.plainSecret = "pass1"

	// 1. Changing [health] does not require restart -> RestartPending remains false
	healthCfg := *initialCfg
	healthCfg.Health.ProbeInterval = "10s"
	sess.handleConfigReload(&healthCfg, false)

	if sess.RestartPending() {
		t.Errorf("expected RestartPending=false after [health] change, got true")
	}
	if sess.Config().Health.ProbeInterval != "10s" {
		t.Errorf("expected active config to be updated for [health], got: %v", sess.Config().Health.ProbeInterval)
	}

	// 2. Changing [proxy] requires restart -> RestartPending becomes true
	proxyCfg := healthCfg
	proxyCfg.Proxy.Host = "5.6.7.8"
	sess.handleConfigReload(&proxyCfg, true)

	if !sess.RestartPending() {
		t.Errorf("expected RestartPending=true after [proxy] change, got false")
	}
	// Active config must remain the old one
	if sess.Config().Proxy.Host != "1.2.3.4" {
		t.Errorf("expected active config to retain old proxy host 1.2.3.4, got: %s", sess.Config().Proxy.Host)
	}
	if sess.PendingConfig().Proxy.Host != "5.6.7.8" {
		t.Errorf("expected pending config to have new proxy host 5.6.7.8, got: %s", sess.PendingConfig().Proxy.Host)
	}
}
