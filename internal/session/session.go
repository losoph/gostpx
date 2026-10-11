package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/engine"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
)

var (
	ErrAlreadyActive  = errors.New("сессия уже активна")
	ErrNoProxy        = errors.New("прокси не задан")
	ErrSessionClosing = errors.New("сессия завершается")
)

type Phase string

const (
	PhaseOff          Phase = "off"
	PhaseConnected    Phase = "connected"
	PhaseNetworkDown  Phase = "network_down"
	PhaseReconnecting Phase = "reconnecting"
)

type EventType string

const (
	EventConnected    EventType = "connected"
	EventDisconnected EventType = "disconnected"
	EventConfigReload EventType = "config_reload"
	EventReconnected  EventType = "reconnected"
	EventNetworkDown  EventType = "network_down"
	EventNetworkUp    EventType = "network_up"
)

type Event struct {
	Type   EventType
	Reason string
	RTT    time.Duration
}

type ReconnectInfo struct {
	Attempt    int
	Next       time.Time
	LastReason string
}

// Session manages the engine, sysproxy, configuration hot-reloading,
// and state synchronization for a proxy session.
type Session struct {
	mu sync.Mutex

	closing atomic.Bool

	configPath string
	statePath  string

	cfg         *config.Config
	plainSecret string

	pendingCfg        *config.Config
	restartPending    bool
	restarting        bool
	reconnectStarting bool
	stopRequested     bool
	stopReason        string

	engine  *engine.Engine
	watcher *engine.ConfigWatcher

	reconnectCancel   context.CancelFunc
	reconnectAttempt  int
	nextReconnect     time.Time
	reconnectReason   string
	reconnectBackoffs []time.Duration
	networkDown       bool

	active bool
	events chan Event

	cachedIP         string
	cachedCountry    string
	cachedIPTime     time.Time
	cachedIPWasProxy bool

	OnConfigReload func(newCfg *config.Config, requiresRestart bool)
	OnConfigError  func(err error, issues []config.Issue)
}

// New creates a new unstarted session manager.
func New(configPath, statePath string) *Session {
	return &Session{
		configPath: configPath,
		statePath:  statePath,
		events:     make(chan Event, 16),
	}
}

// Events returns the channel receiving session lifecycle events.
func (s *Session) Events() <-chan Event {
	return s.events
}

func (s *Session) emitEvent(e Event) {
	select {
	case s.events <- e:
	default:
	}
}

// RestartPending returns whether configuration or credentials changed
// while a session is active and requires restarting the session.
func (s *Session) RestartPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active && s.restartPending
}

// PendingConfig returns the pending configuration if a restart is pending.
func (s *Session) PendingConfig() *config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingCfg
}

// Phase returns the current operational phase of the session:
// PhaseConnected, PhaseNetworkDown, PhaseReconnecting, or PhaseOff.
func (s *Session) Phase() Phase {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reconnectCancel != nil {
		return PhaseReconnecting
	}
	if s.active {
		if s.networkDown {
			return PhaseNetworkDown
		}
		return PhaseConnected
	}
	return PhaseOff
}

// ReconnectInfo returns information about the current reconnection loop.
func (s *Session) ReconnectInfo() ReconnectInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ReconnectInfo{
		Attempt:    s.reconnectAttempt,
		Next:       s.nextReconnect,
		LastReason: s.reconnectReason,
	}
}

var defaultReconnectBackoffs = []time.Duration{
	5 * time.Second,
	10 * time.Second,
	20 * time.Second,
	40 * time.Second,
	60 * time.Second,
}

// SetReconnectBackoffs overrides the reconnection backoff intervals for tests.
func (s *Session) SetReconnectBackoffs(backoffs []time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconnectBackoffs = backoffs
}

func (s *Session) getReconnectBackoffs() []time.Duration {
	if len(s.reconnectBackoffs) > 0 {
		return s.reconnectBackoffs
	}
	return defaultReconnectBackoffs
}

func (s *Session) cancelReconnectLocked() {
	if s.reconnectCancel != nil {
		s.reconnectCancel()
		s.reconnectCancel = nil
	}
	s.reconnectAttempt = 0
	s.nextReconnect = time.Time{}
	s.reconnectReason = ""
	if st, _ := state.Load(s.statePath); st != nil && (st.Reconnecting || st.ReconnectAttempt != 0) {
		if st.PID == os.Getpid() || st.PID == 0 || !checkPIDAlive(st.PID) {
			st.Reconnecting = false
			st.ReconnectAttempt = 0
			st.NextReconnect = time.Time{}
			if !s.active {
				st.PID = 0
			}
			_ = state.Save(s.statePath, st)
		}
	}
}

func (s *Session) handleConfigReload(newCfg *config.Config, requiresRestart bool) {
	s.mu.Lock()
	credPath := config.CredentialsPath(s.configPath)
	currPass, _ := config.LoadPassword(credPath)

	// If credentials changed as well, mark restart required
	if currPass != s.plainSecret {
		requiresRestart = true
	}

	if requiresRestart && s.active {
		s.restartPending = true
		s.pendingCfg = newCfg
	} else {
		s.cfg = newCfg
		s.plainSecret = currPass
		s.restartPending = false
		s.pendingCfg = nil
	}
	s.mu.Unlock()

	if s.OnConfigReload != nil {
		s.OnConfigReload(newCfg, requiresRestart)
	}
	s.emitEvent(Event{Type: EventConfigReload})
}

// Start validates configuration, launches the engine, enables system proxy,
// and begins monitoring connections and config file changes.
func (s *Session) Start(ctx context.Context) error {
	return s.startWithSnapshot(ctx, nil, "", "", false)
}

// rollbackSession rolls back sysproxy to snap using the provided listen addresses, stops eng if created,
// resets state.json to inactive (ActiveSession=false, PID=0, Reconnecting=false), clears session active state,
// and emits EventDisconnected.
// Must be called with s.mu held.
func (s *Session) rollbackSession(
	snap *sysproxy.Snapshot,
	httpListen, socksListen string,
	eng *engine.Engine,
	reason string,
) {
	if eng != nil {
		_ = eng.Stop()
	}
	var unsetErr error
	if snap != nil {
		unsetErr = sysproxy.Unset(snap, httpListen, socksListen)
	}

	st, _ := state.Load(s.statePath)
	if st == nil {
		st = state.DefaultState()
	}
	st.ActiveSession = false
	st.PID = 0
	st.LastDisconnectReason = reason
	st.CachedExternalIP = ""
	st.CachedCountry = ""
	st.NetworkDown = false
	st.Reconnecting = false
	st.ReconnectAttempt = 0
	st.NextReconnect = time.Time{}
	if unsetErr != nil {
		st.SysproxySnapshot = snap
	} else {
		st.SysproxySnapshot = nil
	}
	_ = state.Save(s.statePath, st)

	s.restartPending = false
	s.pendingCfg = nil
	s.active = false
	s.engine = nil
	s.restarting = false
	s.reconnectStarting = false
	s.stopRequested = false
	s.stopReason = ""
	s.reconnectAttempt = 0
	s.nextReconnect = time.Time{}
	s.reconnectReason = ""
	s.cachedIP = ""
	s.cachedCountry = ""
	s.cachedIPTime = time.Time{}

	s.emitEvent(Event{Type: EventDisconnected, Reason: reason})
}

// rollbackRestart rolls back sysproxy to origSnap using the old listen addresses, stops eng if created,
// resets state.json to inactive (ActiveSession=false, PID=0), clears session active state, and emits EventDisconnected.
// Must be called with s.mu held.
func (s *Session) rollbackRestart(
	origSnap *sysproxy.Snapshot,
	oldHTTPListen, oldSOCKSListen string,
	eng *engine.Engine,
	reason string,
) {
	s.rollbackSession(origSnap, oldHTTPListen, oldSOCKSListen, eng, reason)
}

// Restart re-initializes the session with the latest configuration and credentials from disk,
// stopping the old engine and starting the new one without losing the pre-session sysproxy snapshot (ADR-015).
func (s *Session) Restart(ctx context.Context) error {
	s.mu.Lock()
	if s.closing.Load() {
		s.mu.Unlock()
		return ErrSessionClosing
	}
	if s.restarting {
		s.mu.Unlock()
		return errors.New("restart in progress")
	}

	if !s.active {
		cfg, _, err := config.Load(s.configPath)
		if err == nil && cfg != nil && cfg.Mode == config.ModeOff {
			s.cancelReconnectLocked()
			st, _ := state.Load(s.statePath)
			if st != nil {
				isForeign := checkPIDAlive(st.PID) && st.PID != os.Getpid()
				if !isForeign && (st.PID == os.Getpid() || st.PID == 0) {
					if st.Reconnecting || st.ReconnectAttempt != 0 {
						st.Reconnecting = false
						st.ReconnectAttempt = 0
						st.NextReconnect = time.Time{}
						st.LastDisconnectReason = "user disabled"
						st.PID = 0
						_ = state.Save(s.statePath, st)
					}
				}
			}
			s.emitEvent(Event{Type: EventDisconnected, Reason: "user disabled"})
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		return s.Start(ctx)
	}

	s.restarting = true
	s.stopRequested = false
	s.stopReason = ""
	defer func() {
		s.mu.Lock()
		s.restarting = false
		s.stopRequested = false
		s.stopReason = ""
		s.mu.Unlock()
	}()

	// 1. Preserve the existing sysproxy snapshot from state.json
	var origSnap *sysproxy.Snapshot
	st, _ := state.Load(s.statePath)
	if st != nil && st.SysproxySnapshot != nil {
		origSnap = st.SysproxySnapshot
	}

	oldHTTPListen := ""
	oldSOCKSListen := ""
	if s.cfg != nil {
		oldHTTPListen = s.cfg.Sysproxy.HTTPListen
		oldSOCKSListen = s.cfg.Sysproxy.SOCKSListen
	}

	// 2. Stop old watcher and engine
	if s.watcher != nil {
		s.watcher.Stop()
		s.watcher = nil
	}
	oldEng := s.engine
	s.engine = nil
	s.active = false
	s.mu.Unlock()

	if oldEng != nil {
		_ = oldEng.Stop()
	}

	hookRestartBeforeStart()

	return s.startWithSnapshot(ctx, origSnap, oldHTTPListen, oldSOCKSListen, true)
}

func (s *Session) startWithSnapshot(ctx context.Context, origSnap *sysproxy.Snapshot, oldHTTPListen, oldSOCKSListen string, isRestart bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cancelReconnectLocked()

	if s.restarting && origSnap == nil && !isRestart {
		return errors.New("restart in progress")
	}

	if s.closing.Load() {
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, "session closing")
		} else {
			s.rollbackSession(nil, "", "", nil, "session closing")
		}
		return ErrSessionClosing
	}

	if s.stopRequested {
		reason := s.stopReason
		if reason == "" {
			reason = "user disabled"
		}
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, reason)
		} else {
			s.rollbackSession(nil, "", "", nil, reason)
		}
		return errors.New(reason)
	}

	if s.active {
		return ErrAlreadyActive
	}

	// 1. Check existing state (ignore own PID if restarting)
	st, _ := state.Load(s.statePath)
	if st == nil {
		st = state.DefaultState()
	}
	if origSnap == nil && st.ActiveSession && checkPIDAlive(st.PID) && st.PID != os.Getpid() {
		return fmt.Errorf("%w (PID %d)", ErrAlreadyActive, st.PID)
	}

	// 2. Load and validate config
	cfg, issues, err := config.Load(s.configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = config.DefaultConfig()
			if err := config.Save(s.configPath, cfg); err != nil {
				if origSnap != nil {
					s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, err.Error())
				}
				return fmt.Errorf("сохранение дефолтного конфига: %w", err)
			}
		} else {
			if origSnap != nil {
				s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, err.Error())
			}
			return fmt.Errorf("загрузка конфига: %w", err)
		}
	}
	if isRestart && cfg != nil && cfg.Mode == config.ModeOff {
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, "user disabled")
		} else {
			s.rollbackSession(nil, "", "", nil, "user disabled")
		}
		return nil
	}
	if cfg.Proxy.Host == "" {
		err := fmt.Errorf("%w: укажите его командой gostpx set socks5://host:port (конфиг: %s)", ErrNoProxy, s.configPath)
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, err.Error())
		}
		return err
	}
	for _, issue := range issues {
		if !issue.IsWarning {
			err := fmt.Errorf("ошибка валидации конфига: %s", issue)
			if origSnap != nil {
				s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, err.Error())
			}
			return err
		}
	}

	// 3. Load credentials (ADR-011)
	credPath := config.CredentialsPath(s.configPath)
	plainSecret, err := config.LoadPassword(credPath)
	if err != nil {
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, err.Error())
		}
		return fmt.Errorf("чтение пароля: %w", err)
	}

	// 4. Pre-flight handshake verification (A1)
	initialRTT, err := func() (time.Duration, error) {
		s.mu.Unlock()
		defer s.mu.Lock()
		hookBeforeVerifyUpstream()
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return doVerifyUpstream(probeCtx, cfg.Proxy, plainSecret, 5*time.Second)
	}()

	if s.closing.Load() {
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, "session closing")
		} else {
			s.rollbackSession(nil, "", "", nil, "session closing")
		}
		return ErrSessionClosing
	}
	if s.stopRequested {
		reason := s.stopReason
		if reason == "" {
			reason = "user disabled"
		}
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, reason)
		} else {
			s.rollbackSession(nil, "", "", nil, reason)
		}
		return errors.New(reason)
	}
	if err != nil {
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, err.Error())
		}
		s.restartPending = false
		s.pendingCfg = nil
		return fmt.Errorf("проверка прокси не удалась: %w", err)
	}

	// 5. Create and start engine
	eng, err := engine.New(cfg, plainSecret)
	if err != nil {
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, nil, err.Error())
		}
		return fmt.Errorf("создание движка: %w", err)
	}
	if err := eng.Start(); err != nil {
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, err.Error())
		}
		return fmt.Errorf("запуск движка: %w", err)
	}

	if s.closing.Load() {
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, "session closing")
		} else {
			s.rollbackSession(nil, "", "", eng, "session closing")
		}
		return ErrSessionClosing
	}
	if s.stopRequested {
		reason := s.stopReason
		if reason == "" {
			reason = "user disabled"
		}
		if origSnap != nil {
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, reason)
		} else {
			s.rollbackSession(nil, "", "", eng, reason)
		}
		return errors.New(reason)
	}

	// 6. Set system proxy (ADR-015: capture snapshot before modifying system settings, or reuse preserved)
	var snap *sysproxy.Snapshot
	if origSnap != nil {
		snap = origSnap
	} else {
		var snapErr error
		snap, snapErr = sysproxy.TakeSnapshot()
		if snapErr != nil {
			_ = eng.Stop()
			return fmt.Errorf("take system proxy snapshot: %w", snapErr)
		}
		if isRestart && snap != nil {
			sysproxy.SanitizeSnapshot(snap, oldHTTPListen, oldSOCKSListen, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen)
		}
	}

	if err := sysproxy.Set(cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen); err != nil {
		if origSnap != nil {
			if cfg.Sysproxy.HTTPListen != oldHTTPListen || cfg.Sysproxy.SOCKSListen != oldSOCKSListen {
				_ = sysproxy.Unset(origSnap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen)
			}
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, err.Error())
		} else {
			_ = eng.Stop()
			_ = sysproxy.Unset(snap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen)
		}
		return fmt.Errorf("установка системного прокси: %w", err)
	}

	// If session was closed during sysproxy.Set, immediately roll back sysproxy and engine
	if s.closing.Load() {
		if origSnap != nil {
			if cfg.Sysproxy.HTTPListen != oldHTTPListen || cfg.Sysproxy.SOCKSListen != oldSOCKSListen {
				_ = sysproxy.Unset(origSnap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen)
			}
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, "session closing")
		} else {
			s.rollbackSession(snap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen, eng, "session closing")
		}
		return ErrSessionClosing
	}
	if s.stopRequested {
		reason := s.stopReason
		if reason == "" {
			reason = "user disabled"
		}
		if origSnap != nil {
			if cfg.Sysproxy.HTTPListen != oldHTTPListen || cfg.Sysproxy.SOCKSListen != oldSOCKSListen {
				_ = sysproxy.Unset(origSnap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen)
			}
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, reason)
		} else {
			s.rollbackSession(snap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen, eng, reason)
		}
		return errors.New(reason)
	}

	// 7. Update state.json
	st.ActiveSession = true
	st.PID = os.Getpid()
	st.Mode = config.ModeSysproxy
	st.LastConnected = time.Now()
	st.LastDisconnectReason = ""
	st.CachedExternalIP = ""
	st.CachedCountry = ""
	st.SysproxySnapshot = snap
	st.NetworkDown = false
	st.Reconnecting = false
	st.ReconnectAttempt = 0
	st.NextReconnect = time.Time{}
	if err := state.Save(s.statePath, st); err != nil {
		if origSnap != nil {
			if cfg.Sysproxy.HTTPListen != oldHTTPListen || cfg.Sysproxy.SOCKSListen != oldSOCKSListen {
				_ = sysproxy.Unset(origSnap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen)
			}
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, err.Error())
		} else {
			s.rollbackSession(snap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen, eng, err.Error())
		}
		return fmt.Errorf("сохранение состояния сессии: %w", err)
	}

	// Final check before committing: if stop was requested right before commit, roll back
	if s.closing.Load() {
		if origSnap != nil {
			if cfg.Sysproxy.HTTPListen != oldHTTPListen || cfg.Sysproxy.SOCKSListen != oldSOCKSListen {
				_ = sysproxy.Unset(origSnap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen)
			}
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, "session closing")
		} else {
			s.rollbackSession(snap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen, eng, "session closing")
		}
		return ErrSessionClosing
	}
	if s.stopRequested {
		reason := s.stopReason
		if reason == "" {
			reason = "user disabled"
		}
		if origSnap != nil {
			if cfg.Sysproxy.HTTPListen != oldHTTPListen || cfg.Sysproxy.SOCKSListen != oldSOCKSListen {
				_ = sysproxy.Unset(origSnap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen)
			}
			s.rollbackRestart(origSnap, oldHTTPListen, oldSOCKSListen, eng, reason)
		} else {
			s.rollbackSession(snap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen, eng, reason)
		}
		return errors.New(reason)
	}

	s.cfg = cfg
	s.plainSecret = plainSecret
	s.engine = eng
	s.active = true
	s.restarting = false
	s.reconnectStarting = false
	s.stopRequested = false
	s.stopReason = ""
	s.restartPending = false
	s.pendingCfg = nil
	s.cachedIP = ""
	s.cachedIPTime = time.Time{}

	// 8. Start config hot reload watcher
	watcher, _ := engine.NewConfigWatcher(
		s.configPath,
		cfg,
		s.handleConfigReload,
		func(err error, issues []config.Issue) {
			if s.OnConfigError != nil {
				s.OnConfigError(err, issues)
			}
		},
	)
	if watcher != nil {
		_ = watcher.Start()
		s.watcher = watcher
	}

	// 9. Monitor engine events (fast disconnect detection per ARCHITECTURE §7)
	go s.monitorEngineEvents(eng)

	s.emitEvent(Event{Type: EventConnected, RTT: initialRTT})
	return nil
}

func (s *Session) monitorEngineEvents(eng *engine.Engine) {
	for evt := range eng.Events() {
		switch evt.Type {
		case engine.EventNetworkDown:
			s.mu.Lock()
			if s.engine == eng && s.active {
				s.networkDown = true
				st, _ := state.Load(s.statePath)
				if st != nil {
					st.NetworkDown = true
					_ = state.Save(s.statePath, st)
				}
			}
			s.mu.Unlock()
			s.emitEvent(Event{Type: EventNetworkDown, Reason: evt.Reason})

		case engine.EventNetworkUp:
			s.mu.Lock()
			if s.engine == eng && s.active {
				s.networkDown = false
				st, _ := state.Load(s.statePath)
				if st != nil {
					st.NetworkDown = false
					_ = state.Save(s.statePath, st)
				}
			}
			s.mu.Unlock()
			s.emitEvent(Event{Type: EventNetworkUp, Reason: evt.Reason})

		case engine.EventDisconnected:
			s.mu.Lock()
			if !s.active || s.engine != eng {
				s.mu.Unlock()
				return
			}
			s.active = false
			s.networkDown = false
			s.restartPending = false
			s.pendingCfg = nil
			s.cachedIP = ""
			s.cachedCountry = ""
			s.cachedIPTime = time.Time{}

			var snap *sysproxy.Snapshot
			var httpListen, socksListen string
			st, _ := state.Load(s.statePath)
			if st != nil {
				snap = st.SysproxySnapshot
			}
			if s.cfg != nil {
				httpListen = s.cfg.Sysproxy.HTTPListen
				socksListen = s.cfg.Sysproxy.SOCKSListen
			}
			unsetErr := sysproxy.Unset(snap, httpListen, socksListen)
			if unsetErr != nil {
				fmt.Fprintf(os.Stderr, "gostpx: ошибка снятия системного прокси при обрыве соединения: %v\n", unsetErr)
			}

			if s.watcher != nil {
				s.watcher.Stop()
				s.watcher = nil
			}
			_ = eng.Stop()
			s.engine = nil

			if st == nil {
				st = state.DefaultState()
			}
			st.ActiveSession = false
			st.PID = 0
			st.NetworkDown = false
			if unsetErr != nil {
				st.LastDisconnectReason = fmt.Sprintf("%s (ошибка снятия прокси: %v)", evt.Reason, unsetErr)
				// Do not clear SysproxySnapshot on error so next run can recover
			} else {
				st.LastDisconnectReason = evt.Reason
				st.SysproxySnapshot = nil
			}
			st.CachedExternalIP = ""
			st.CachedCountry = ""
			if err := state.Save(s.statePath, st); err != nil {
				fmt.Fprintf(os.Stderr, "gostpx: ошибка сохранения состояния при обрыве соединения: %v\n", err)
			}

			// Check auto-reconnect eligibility:
			// Not user-stopped, not auth rejected, not config error, not restartPending
			isStoppedByUser := s.stopRequested || s.closing.Load() || evt.Reason == "stopped" || evt.Reason == "user disabled" || evt.Reason == "quit" || evt.Reason == "signal" || evt.Reason == "shutdown"
			isAuthFailed := strings.Contains(evt.Reason, "отказ в авторизации")
			isConfigError := strings.Contains(evt.Reason, "валидаци") || strings.Contains(evt.Reason, "конфиг")

			shouldReconnect := !isStoppedByUser && !isAuthFailed && !isConfigError && !s.restartPending

			if shouldReconnect {
				s.startReconnectLoopLocked(st.LastDisconnectReason)
			}
			s.mu.Unlock()

			s.emitEvent(Event{Type: EventDisconnected, Reason: evt.Reason})
			return
		}
	}
}

func (s *Session) startReconnectLoopLocked(lastReason string) {
	if s.closing.Load() || s.stopRequested || s.restartPending {
		return
	}
	s.cancelReconnectLocked()

	ctx, cancel := context.WithCancel(context.Background())
	s.reconnectCancel = cancel
	s.reconnectReason = lastReason
	s.reconnectAttempt = 1

	backoffs := s.getReconnectBackoffs()
	delay := backoffs[0]
	nextTime := time.Now().Add(delay)
	s.nextReconnect = nextTime

	st, _ := state.Load(s.statePath)
	if st == nil {
		st = state.DefaultState()
	}
	st.PID = os.Getpid()
	st.Reconnecting = true
	st.ReconnectAttempt = 1
	st.NextReconnect = nextTime
	st.NetworkDown = false
	if st.LastDisconnectReason == "" || !strings.Contains(st.LastDisconnectReason, "ошибка снятия прокси") {
		st.LastDisconnectReason = lastReason
	}
	_ = state.Save(s.statePath, st)

	cfg := s.cfg
	plainSecret := s.plainSecret

	go s.runReconnectLoop(ctx, cfg, plainSecret, backoffs)
}

func (s *Session) runReconnectLoop(ctx context.Context, cfg *config.Config, plainSecret string, backoffs []time.Duration) {
	attempt := 1

	for {
		s.mu.Lock()
		curAttempt := s.reconnectAttempt
		s.mu.Unlock()

		delay := defaultReconnectBackoffs[0]
		if len(backoffs) > 0 {
			delayIndex := curAttempt - 1
			if delayIndex < 0 {
				delayIndex = 0
			} else if delayIndex >= len(backoffs) {
				delayIndex = len(backoffs) - 1
			}
			delay = backoffs[delayIndex]
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		s.mu.Lock()
		if s.closing.Load() || s.stopRequested || s.restartPending || ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		if cfg == nil {
			s.mu.Lock()
			s.cancelReconnectLocked()
			st, _ := state.Load(s.statePath)
			if st != nil {
				st.PID = 0
				st.Reconnecting = false
				st.ReconnectAttempt = 0
				st.NextReconnect = time.Time{}
				st.LastDisconnectReason = "нет конфига"
				_ = state.Save(s.statePath, st)
			}
			s.mu.Unlock()
			return
		}

		// Verify upstream reachability
		verifyTimeout := 5 * time.Second
		if delay < verifyTimeout && delay > 0 {
			verifyTimeout = delay
		}
		verifyCtx, verifyCancel := context.WithTimeout(ctx, verifyTimeout)
		rtt, err := doVerifyUpstream(verifyCtx, cfg.Proxy, plainSecret, verifyTimeout)
		verifyCancel()

		if ctx.Err() != nil {
			return
		}

		if err != nil {
			if errors.Is(err, engine.ErrCredentialsRejected) || strings.Contains(err.Error(), "отказ в авторизации") {
				s.mu.Lock()
				s.cancelReconnectLocked()
				st, _ := state.Load(s.statePath)
				if st != nil {
					st.PID = 0
					st.Reconnecting = false
					st.ReconnectAttempt = 0
					st.NextReconnect = time.Time{}
					st.LastDisconnectReason = fmt.Sprintf("отказ в авторизации: %v", err)
					_ = state.Save(s.statePath, st)
				}
				s.mu.Unlock()
				return
			}

			// Failed probe, advance to next attempt
			attempt++
			nextDelayIndex := attempt - 1
			if nextDelayIndex >= len(backoffs) {
				nextDelayIndex = len(backoffs) - 1
			}
			nextDelay := backoffs[nextDelayIndex]
			nextTime := time.Now().Add(nextDelay)

			s.mu.Lock()
			if ctx.Err() != nil {
				s.mu.Unlock()
				return
			}
			s.reconnectAttempt = attempt
			s.nextReconnect = nextTime
			s.reconnectReason = err.Error()

			st, _ := state.Load(s.statePath)
			if st != nil {
				st.PID = os.Getpid()
				st.Reconnecting = true
				st.ReconnectAttempt = attempt
				st.NextReconnect = nextTime
				st.LastDisconnectReason = err.Error()
				_ = state.Save(s.statePath, st)
			}
			s.mu.Unlock()
			continue
		}

		// VerifyUpstream succeeded! Now start the session
		s.mu.Lock()
		if s.closing.Load() || s.stopRequested || s.restartPending || ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		s.reconnectCancel = nil
		s.reconnectAttempt = 0
		s.nextReconnect = time.Time{}
		s.reconnectReason = ""
		s.reconnectStarting = true
		s.stopRequested = false
		s.stopReason = ""
		s.mu.Unlock()

		startErr := s.Start(context.Background())
		if startErr != nil {
			s.mu.Lock()
			s.reconnectStarting = false
			if s.closing.Load() || s.stopRequested || s.restartPending || strings.Contains(startErr.Error(), "user disabled") || strings.Contains(startErr.Error(), "session closing") {
				s.stopRequested = false
				s.stopReason = ""
				s.mu.Unlock()
				return
			}

			// If Start failed, continue reconnect loop
			attempt++
			nextDelayIndex := attempt - 1
			if nextDelayIndex >= len(backoffs) {
				nextDelayIndex = len(backoffs) - 1
			}
			nextDelay := backoffs[nextDelayIndex]
			nextTime := time.Now().Add(nextDelay)

			newCtx, cancel := context.WithCancel(context.Background())
			ctx = newCtx
			s.reconnectCancel = cancel
			s.reconnectAttempt = attempt
			s.nextReconnect = nextTime
			s.reconnectReason = startErr.Error()

			st, _ := state.Load(s.statePath)
			if st != nil {
				st.PID = os.Getpid()
				st.Reconnecting = true
				st.ReconnectAttempt = attempt
				st.NextReconnect = nextTime
				st.LastDisconnectReason = startErr.Error()
				_ = state.Save(s.statePath, st)
			}
			s.mu.Unlock()
			continue
		}

		// Successfully reconnected!
		s.mu.Lock()
		s.reconnectStarting = false
		st, _ := state.Load(s.statePath)
		if st != nil {
			st.Reconnecting = false
			st.ReconnectAttempt = 0
			st.NextReconnect = time.Time{}
			_ = state.Save(s.statePath, st)
		}
		s.mu.Unlock()

		s.emitEvent(Event{
			Type:   EventReconnected,
			Reason: "reconnected",
			RTT:    rtt,
		})
		return
	}
}

// SetClosing sets the atomic closing flag so any current or subsequent Start will immediately abort and roll back.
func (s *Session) SetClosing() {
	s.closing.Store(true)
	s.mu.Lock()
	s.cancelReconnectLocked()
	s.mu.Unlock()
}

// IsClosing returns true if the session is shutting down.
func (s *Session) IsClosing() bool {
	return s.closing.Load()
}

// ResetClosing resets the closing flag (used in tests).
func (s *Session) ResetClosing() {
	s.closing.Store(false)
}

// Stop unconditionally unsets system proxy, stops engine and watchers, and updates state.
func (s *Session) Stop(reason string) error {
	if reason == "shutdown" || reason == "signal" || reason == "quit" {
		s.closing.Store(true)
	}
	s.mu.Lock()

	s.cancelReconnectLocked()
	s.networkDown = false

	if s.restarting || s.reconnectStarting {
		s.stopRequested = true
		if s.stopReason == "" {
			s.stopReason = reason
		}
		s.mu.Unlock()
		return nil
	}

	var snap *sysproxy.Snapshot
	var httpListen, socksListen string
	st, _ := state.Load(s.statePath)
	if st != nil {
		snap = st.SysproxySnapshot
	}
	if s.cfg != nil {
		httpListen = s.cfg.Sysproxy.HTTPListen
		socksListen = s.cfg.Sysproxy.SOCKSListen
	} else if cfg, _, err := config.Load(s.configPath); err == nil && cfg != nil {
		httpListen = cfg.Sysproxy.HTTPListen
		socksListen = cfg.Sysproxy.SOCKSListen
	}

	var firstErr error
	if err := sysproxy.Unset(snap, httpListen, socksListen); err != nil {
		firstErr = err
	}

	if s.watcher != nil {
		s.watcher.Stop()
		s.watcher = nil
	}

	eng := s.engine
	s.engine = nil
	s.active = false
	s.restarting = false
	s.reconnectStarting = false
	s.stopRequested = false
	s.stopReason = ""
	s.restartPending = false
	s.pendingCfg = nil
	s.cachedIP = ""
	s.cachedCountry = ""
	s.cachedIPTime = time.Time{}

	if st == nil {
		st = state.DefaultState()
	}
	st.ActiveSession = false
	st.PID = 0
	st.LastDisconnectReason = reason
	st.CachedExternalIP = ""
	st.CachedCountry = ""
	st.SysproxySnapshot = nil
	st.NetworkDown = false
	st.Reconnecting = false
	st.ReconnectAttempt = 0
	st.NextReconnect = time.Time{}
	if err := state.Save(s.statePath, st); err != nil {
		firstErr = errors.Join(firstErr, fmt.Errorf("сохранение состояния: %w", err))
	}
	s.mu.Unlock()

	if eng != nil {
		if err := eng.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	s.emitEvent(Event{Type: EventDisconnected, Reason: reason})
	return firstErr
}

// IsActive returns whether the local session instance is running.
func (s *Session) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// RTT returns the round-trip time measured by the engine.
func (s *Session) RTT() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine != nil {
		return s.engine.Status().RTT
	}
	return 0
}

// Config returns the currently loaded configuration.
func (s *Session) Config() *config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		cfg, _, err := config.Load(s.configPath)
		if err == nil {
			s.cfg = cfg
		}
	}
	return s.cfg
}

// CheckRTT queries upstream round-trip time via TCP connect probe.
func (s *Session) CheckRTT(ctx context.Context) (time.Duration, error) {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()

	if cfg == nil {
		var err error
		cfg, _, err = config.Load(s.configPath)
		if err != nil {
			return 0, err
		}
	}
	if cfg.Proxy.Host == "" || cfg.Proxy.Port <= 0 {
		return 0, ErrNoProxy
	}
	return engine.CheckProxy(ctx, cfg.Proxy.Host, cfg.Proxy.Port, 3*time.Second)
}

var defaultExternalIPURL = "https://ipinfo.io/json"

type ipCountryResponse struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
}

// CachedIP returns the currently cached external IP and country if it matches the current session mode and hasn't expired.
func (s *Session) CachedIP() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cachedIP != "" && time.Since(s.cachedIPTime) < 60*time.Second && s.cachedIPWasProxy == s.active {
		return s.cachedIP, s.cachedCountry
	}
	return "", ""
}

// ResetIPCache explicitly invalidates the in-memory and state.json external IP cache.
func (s *Session) ResetIPCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cachedIP = ""
	s.cachedCountry = ""
	s.cachedIPTime = time.Time{}
	st, err := state.Load(s.statePath)
	if err == nil && (st.CachedExternalIP != "" || st.CachedCountry != "") {
		st.CachedExternalIP = ""
		st.CachedCountry = ""
		_ = state.Save(s.statePath, st)
	}
}

// GetExternalIP returns the external IP and country, using a 60-second cache.
// If active, the IP is fetched via local HTTP proxy; if direct, via direct HTTP request.
func (s *Session) GetExternalIP(ctx context.Context, force bool) (string, string, error) {
	s.mu.Lock()
	isActive := s.active
	var httpListen string
	if isActive && s.cfg != nil {
		httpListen = s.cfg.Sysproxy.HTTPListen
	}
	if !force && s.cachedIP != "" && time.Since(s.cachedIPTime) < 60*time.Second && s.cachedIPWasProxy == isActive {
		cachedIP := s.cachedIP
		cachedCountry := s.cachedCountry
		s.mu.Unlock()
		return cachedIP, cachedCountry, nil
	}
	s.mu.Unlock()

	ip, country, err := FetchExternalIP(ctx, httpListen)
	if err != nil {
		return "", "", err
	}

	s.mu.Lock()
	s.cachedIP = ip
	s.cachedCountry = country
	s.cachedIPTime = time.Now()
	s.cachedIPWasProxy = isActive
	st, err := state.Load(s.statePath)
	if err == nil {
		st.CachedExternalIP = ip
		st.CachedCountry = country
		_ = state.Save(s.statePath, st)
	}
	s.mu.Unlock()

	return ip, country, nil
}

// FetchExternalIP queries https://ipinfo.io/json (with fallback to https://api.country.is/)
// either through the given proxy address or directly.
// In direct mode (httpProxyAddr == ""), Transport explicitly sets Proxy: nil to ignore environment proxy variables (e.g. HTTPS_PROXY).
// Returns public IP and country code (if available, e.g. "US"). If country is absent or unparseable, returns (ip, "", nil).
func FetchExternalIP(ctx context.Context, httpProxyAddr string) (string, string, error) {
	return fetchExternalIPFromURL(ctx, defaultExternalIPURL, httpProxyAddr)
}

func fetchExternalIPFromURL(ctx context.Context, apiURL, httpProxyAddr string) (string, string, error) {
	var transport *http.Transport
	if httpProxyAddr != "" {
		proxyURL, err := url.Parse("http://" + httpProxyAddr)
		if err != nil {
			return "", "", fmt.Errorf("parse proxy url: %w", err)
		}
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
	} else {
		transport = &http.Transport{
			Proxy: nil, // explicitly direct, ignoring HTTPS_PROXY from environment
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if apiURL == defaultExternalIPURL {
			return fetchExternalIPFromURL(ctx, "https://api.country.is/", httpProxyAddr)
		}
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if apiURL == defaultExternalIPURL {
			return fetchExternalIPFromURL(ctx, "https://api.country.is/", httpProxyAddr)
		}
		return "", "", fmt.Errorf("http error: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var res ipCountryResponse
	if err := json.Unmarshal(body, &res); err == nil && res.IP != "" {
		return strings.TrimSpace(res.IP), strings.TrimSpace(res.Country), nil
	}

	raw := strings.TrimSpace(string(body))
	if raw != "" && !strings.Contains(raw, "{") {
		return raw, "", nil
	}

	if apiURL == defaultExternalIPURL {
		return fetchExternalIPFromURL(ctx, "https://api.country.is/", httpProxyAddr)
	}

	return "", "", fmt.Errorf("unable to parse external IP from response")
}

// StopActiveSession cleanly requests the running session process (e.g. foreground CLI or tray)
// to terminate, and guarantees system proxy is unset.
func StopActiveSession(statePath string, reason string) error {
	st, err := state.Load(statePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("чтение состояния: %w", err)
	}
	if st != nil && st.PID > 0 && checkPIDAlive(st.PID) && st.PID != os.Getpid() {
		_ = terminatePID(st.PID)
		for i := 0; i < 15; i++ {
			if !checkPIDAlive(st.PID) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if checkPIDAlive(st.PID) {
			return fmt.Errorf("процесс PID %d не завершился", st.PID)
		}
	}
	var snap *sysproxy.Snapshot
	if st != nil {
		snap = st.SysproxySnapshot
	}
	var httpListen, socksListen string
	configPath, _ := config.DefaultConfigPath()
	if cfg, _, err := config.Load(configPath); err == nil && cfg != nil {
		httpListen = cfg.Sysproxy.HTTPListen
		socksListen = cfg.Sysproxy.SOCKSListen
	}

	if unsetErr := sysproxy.Unset(snap, httpListen, socksListen); unsetErr != nil {
		return fmt.Errorf("снятие системного прокси: %w", unsetErr)
	}

	if st != nil {
		st.ActiveSession = false
		st.PID = 0
		st.LastDisconnectReason = reason
		st.CachedExternalIP = ""
		st.CachedCountry = ""
		st.SysproxySnapshot = nil
		if saveErr := state.Save(statePath, st); saveErr != nil {
			return fmt.Errorf("сохранение состояния: %w", saveErr)
		}
	}
	return nil
}

// RecoveryStatus describes the result of inspecting dangling system proxy settings.
type RecoveryStatus struct {
	Recovered bool
	Occupied  bool
	Service   string
	Addr      string
}

// RecoverDanglingProxy implements R4 from HANDOFF §0: checks if system proxy
// points to our configured HTTPListen without a live session, and removes it
// only if the port has no active listener (e.g. third-party proxy).
func RecoverDanglingProxy(configPath, statePath string) (RecoveryStatus, error) {
	st, _ := state.Load(statePath)
	if st != nil && st.ActiveSession && checkPIDAlive(st.PID) {
		return RecoveryStatus{}, nil
	}

	cur, err := sysproxy.Current()
	if err != nil || cur == nil || !cur.Enabled {
		return RecoveryStatus{}, nil
	}

	cfg, _, err := config.Load(configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}

	listenHost, listenPort, err := parseHostPort(cfg.Sysproxy.HTTPListen)
	if err != nil {
		return RecoveryStatus{}, err
	}

	matches := (cur.HTTPHost == listenHost ||
		(listenHost == "0.0.0.0" && (cur.HTTPHost == "127.0.0.1" || cur.HTTPHost == "localhost")) ||
		(listenHost == "127.0.0.1" && (cur.HTTPHost == "localhost" || cur.HTTPHost == "127.0.0.1"))) &&
		cur.HTTPPort == listenPort

	if matches {
		dialHost := cur.HTTPHost
		if dialHost == "0.0.0.0" || dialHost == "" {
			dialHost = "127.0.0.1"
		}
		targetAddr := net.JoinHostPort(dialHost, strconv.Itoa(cur.HTTPPort))

		// Check if the port has an active listener (e.g. SwiftBar or another proxy).
		// If someone is listening, DO NOT touch system proxy settings!
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 500*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return RecoveryStatus{
				Occupied: true,
				Service:  cur.Service,
				Addr:     targetAddr,
			}, nil
		}

		var snap *sysproxy.Snapshot
		if st != nil {
			snap = st.SysproxySnapshot
		}
		if err := sysproxy.Unset(snap, cfg.Sysproxy.HTTPListen, cfg.Sysproxy.SOCKSListen); err != nil {
			return RecoveryStatus{Service: cur.Service, Addr: targetAddr}, err
		}
		if st == nil {
			st = state.DefaultState()
		}
		st.ActiveSession = false
		st.PID = 0
		st.LastDisconnectReason = "зависший прокси снят при старте"
		st.CachedExternalIP = ""
		st.CachedCountry = ""
		st.SysproxySnapshot = nil
		if err := state.Save(statePath, st); err != nil {
			return RecoveryStatus{
				Recovered: true,
				Service:   cur.Service,
				Addr:      targetAddr,
			}, fmt.Errorf("сохранение состояния после восстановления прокси: %w", err)
		}
		return RecoveryStatus{
			Recovered: true,
			Service:   cur.Service,
			Addr:      targetAddr,
		}, nil
	}

	return RecoveryStatus{}, nil
}

func parseHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in %q", addr)
	}
	return host, port, nil
}
