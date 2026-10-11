package engine

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/losoph/gostpx/internal/config"
)

// WatcherCallback receives updated configuration and whether a proxy restart is needed.
type WatcherCallback func(newCfg *config.Config, requiresRestart bool)

// WatcherErrorCallback receives errors or validation issues during reload.
type WatcherErrorCallback func(err error, issues []config.Issue)

// ConfigWatcher monitors config.toml and triggers reload with rollback on failure.
type ConfigWatcher struct {
	configPath  string
	mu          sync.RWMutex
	currentCfg  *config.Config
	currentPass string

	onReload WatcherCallback
	onError  WatcherErrorCallback

	watcher *fsnotify.Watcher
	stopCh  chan struct{}
}

// NewConfigWatcher initializes a new config watcher for path.
func NewConfigWatcher(path string, initialCfg *config.Config, onReload WatcherCallback, onError WatcherErrorCallback) (*ConfigWatcher, error) {
	if initialCfg == nil {
		return nil, errors.New("initial config is nil")
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}

	initialPass, _ := config.LoadPassword(config.CredentialsPath(path))

	cw := &ConfigWatcher{
		configPath:  path,
		currentCfg:  initialCfg,
		currentPass: initialPass,
		onReload:    onReload,
		onError:     onError,
		watcher:     w,
		stopCh:      make(chan struct{}),
	}

	return cw, nil
}

// Start begins watching the config file directory with debouncing.
func (cw *ConfigWatcher) Start() error {
	dir := filepath.Dir(cw.configPath)
	if err := cw.watcher.Add(dir); err != nil {
		return fmt.Errorf("watch config directory %q: %w", dir, err)
	}

	go cw.watchLoop()
	return nil
}

// Stop closes the watcher.
func (cw *ConfigWatcher) Stop() error {
	select {
	case <-cw.stopCh:
		return nil
	default:
		close(cw.stopCh)
	}
	return cw.watcher.Close()
}

func (cw *ConfigWatcher) watchLoop() {
	var (
		debounceTimer *time.Timer
		debounceCh    <-chan time.Time
	)

	targetBase := filepath.Base(cw.configPath)
	credBase := filepath.Base(config.CredentialsPath(cw.configPath))

	for {
		select {
		case <-cw.stopCh:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}
			base := filepath.Base(event.Name)
			// Explicitly ignore backup and temporary files created by Save() or editors
			if strings.HasSuffix(base, ".bak") || strings.HasSuffix(base, ".tmp") {
				continue
			}
			if base != targetBase && base != credBase {
				continue
			}

			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.NewTimer(50 * time.Millisecond)
				debounceCh = debounceTimer.C
			}

		case <-debounceCh:
			cw.reload()

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			if cw.onError != nil {
				cw.onError(err, nil)
			}
		}
	}
}

// Reload reads and validates the config file.
// If valid, triggers onReload. If invalid, preserves current config and triggers onError.
func (cw *ConfigWatcher) reload() {
	newCfg, issues, err := config.Load(cw.configPath)
	if err != nil {
		if cw.onError != nil {
			cw.onError(err, nil)
		}
		return
	}

	var errIssues []config.Issue
	for _, issue := range issues {
		if !issue.IsWarning {
			errIssues = append(errIssues, issue)
		}
	}

	if len(errIssues) > 0 {
		if cw.onError != nil {
			cw.onError(fmt.Errorf("config validation failed with %d error(s)", len(errIssues)), errIssues)
		}
		return
	}

	credPath := config.CredentialsPath(cw.configPath)
	newPass, _ := config.LoadPassword(credPath)

	cw.mu.Lock()
	oldCfg := cw.currentCfg
	cw.currentCfg = newCfg
	oldPass := cw.currentPass
	cw.currentPass = newPass
	cw.mu.Unlock()

	// Check if restart is required (proxy, mode, sysproxy, or credentials changed)
	requiresRestart := (oldCfg.Mode != newCfg.Mode) ||
		(oldCfg.Proxy != newCfg.Proxy) ||
		(oldCfg.Sysproxy != newCfg.Sysproxy) ||
		(oldPass != newPass)

	if cw.onReload != nil {
		cw.onReload(newCfg, requiresRestart)
	}
}
