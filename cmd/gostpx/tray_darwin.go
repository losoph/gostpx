//go:build darwin

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/losoph/gostpx/internal/autostart"
	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/connwatch"
	"github.com/losoph/gostpx/internal/notify"
	"github.com/losoph/gostpx/internal/session"
	"github.com/losoph/gostpx/internal/settings"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/icons"
)

func runTray() {
	configPath, err := config.DefaultConfigPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка пути конфига: %v\n", err)
		os.Exit(1)
	}
	statePath, err := state.DefaultStatePath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка пути состояния: %v\n", err)
		os.Exit(1)
	}

	if isSelftest() {
		setupSelftestEnvironment(configPath)
	} else {
		initNotifications()
	}

	// R4 from HANDOFF §0: remove dangling proxy if previous session crashed
	danglingRecovery, _ := session.RecoverDanglingProxy(configPath, statePath)

	sess := session.New(configPath, statePath)
	sess.ResetIPCache()

	currentExec, _ := autostart.CurrentExecutable()
	cfg, _, _ := config.Load(configPath)
	autostartEnabled := false
	if cfg != nil {
		autostartEnabled = cfg.Autostart
	}
	autostartWarn, _ := autostart.Sync(autostartEnabled, currentExec)
	assetsFS, err := settings.AssetsFS()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка загрузки ресурсов настроек: %v\n", err)
	}

	var (
		appInstance  *application.App
		cleanupOnce  sync.Once
		stateWatcher *session.StateWatcher
	)
	cleanup := func(reason string) {
		cleanupOnce.Do(func() {
			if stateWatcher != nil {
				_ = stateWatcher.Close()
			}
			sess.SetClosing()
			_ = sess.Stop(reason)
			_ = sysproxy.Unset(nil, "", "")
		})
	}
	quitWithWatchdog := func(reason string) {
		cleanup(reason)

		// Safety fallback watchdog: force exit after 3s if app.Quit() hangs
		time.AfterFunc(3*time.Second, func() {
			os.Exit(0)
		})

		if appInstance != nil {
			appInstance.Quit()
		} else {
			os.Exit(0)
		}
	}

	var (
		refreshUI      func(forceIP bool)
		restartHandler func()
		turnOffProxy   func()
	)

	app := application.New(application.Options{
		Name:                        "gostpx",
		Description:                 "gostpx — быстрый переключатель системного прокси",
		DisableDefaultSignalHandler: true,
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory,
		},
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assetsFS),
			Middleware: settings.Middleware(settings.Options{
				ConfigPath:  configPath,
				CurrentExec: currentExec,
				OnSaved: func(changedProxy bool) {
					savedCfg, _, _ := config.Load(configPath)
					if savedCfg != nil && savedCfg.Mode == config.ModeOff {
						st, _ := state.Load(statePath)
						isActive := sess.IsActive() || (st != nil && st.ActiveSession && session.IsPIDAlive(st.PID))
						isReconnecting := sess.Phase() == session.PhaseReconnecting || (st != nil && st.Reconnecting)
						if isActive || isReconnecting {
							if turnOffProxy != nil {
								go turnOffProxy()
							}
						} else if refreshUI != nil {
							refreshUI(false)
						}
					} else if changedProxy && sess.IsActive() {
						if restartHandler != nil {
							restartHandler()
						}
					} else if refreshUI != nil {
						refreshUI(false)
					}
				},
			}),
		},
		OnShutdown: func() {
			cleanup("shutdown")
		},
	})
	appInstance = app

	systray := app.SystemTray.New()
	systray.SetTemplateIcon(icons.SystrayMacTemplate)

	menu := app.NewMenu()

	// 1. Status header
	statusItem := menu.Add("Статус: прямое подключение")
	statusItem.SetEnabled(false)

	// 1b. Reconnected recovery time
	reconnectedItem := menu.Add("")
	reconnectedItem.SetEnabled(false)
	reconnectedItem.SetHidden(true)

	// 2. Latency
	rttItem := menu.Add("Задержка: —")
	rttItem.SetEnabled(false)
	rttItem.SetHidden(true)

	// 3. External IP (cached 60s)
	ipItem := menu.Add("Внешний IP: —")
	ipItem.SetEnabled(false)

	menu.AddSeparator()

	// 4. Action button
	toggleItem := menu.Add("Включить системный прокси")

	// 4b. Restart pending button
	restartItem := menu.Add("⟳ Прокси изменён — переподключить")
	restartItem.SetHidden(true)

	// 5. Force refresh
	refreshItem := menu.Add("Принудительно обновить")

	// 6. R4 dangling proxy recovery indicator
	var recoveryItem *application.MenuItem
	if danglingRecovery.Recovered {
		recoveryItem = menu.Add(fmt.Sprintf("⚠ Снят зависший прокси (%s)", danglingRecovery.Service))
		recoveryItem.SetEnabled(false)
	} else if danglingRecovery.Occupied {
		recoveryItem = menu.Add(fmt.Sprintf("⚠ Прокси указывает на %s (порт занят)", danglingRecovery.Addr))
		recoveryItem.SetEnabled(false)
	}

	// 6b. Autostart warning if app is not in /Applications
	autostartWarnItem := menu.Add(autostartWarn)
	autostartWarnItem.SetEnabled(false)
	if autostartWarn == "" {
		autostartWarnItem.SetHidden(true)
	}

	menu.AddSeparator()

	// 7. Normative coverage lines from LIMITATIONS.md (ADR-020)
	coverage := menu.AddSubmenu("Охват…")
	for _, item := range session.SysproxyCoverageItems() {
		label := fmt.Sprintf("%s: %s", item.Label, item.Text)
		cItem := coverage.Add(label)
		cItem.SetEnabled(false)
	}
	tunItem := coverage.Add("⚠ режим tun: недоступен (нужен демон, Phase 3)")
	tunItem.SetEnabled(false)
	coverage.AddSeparator()
	checkBypassItem := coverage.Add("Проверить, кто идёт мимо прокси…")
	checkBypassItem.OnClick(func(ctx *application.Context) {
		go runConnwatchCheck(app, sess, configPath, statePath)
	})

	menu.AddSeparator()

	// 8. Settings & Config
	settingsItem := menu.Add("Настройки…")
	configItem := menu.Add("Открыть конфиг")

	// 9. Quit
	quitItem := menu.Add("Выход")

	systray.SetMenu(menu)

	var (
		stateMu              sync.Mutex
		isConnecting         bool
		startError           string
		lastDisconnectReason string
		wasConnected         bool
		reconnectedAt        string

		currentTrayLabel   string
		currentTrayLabelMu sync.RWMutex

		ipFetching     bool
		ipFetchingLock sync.Mutex
	)

	updateExternalIP := func(force bool) {
		ipFetchingLock.Lock()
		if ipFetching && !force {
			ipFetchingLock.Unlock()
			return
		}
		ipFetching = true
		ipFetchingLock.Unlock()

		go func() {
			defer func() {
				ipFetchingLock.Lock()
				ipFetching = false
				ipFetchingLock.Unlock()
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			var ip string
			var country string
			var err error

			st, _ := state.Load(statePath)
			if sess.IsActive() {
				ip, country, err = sess.GetExternalIP(ctx, force)
			} else if st.ActiveSession && session.IsPIDAlive(st.PID) && st.PID != os.Getpid() {
				cfg := sess.Config()
				httpListen := ""
				if cfg != nil {
					httpListen = cfg.Sysproxy.HTTPListen
				}
				ip, country, err = session.FetchExternalIP(ctx, httpListen)
			} else {
				ip, country, err = sess.GetExternalIP(ctx, force)
			}

			application.InvokeAsync(func() {
				if err == nil && ip != "" {
					if country != "" {
						ipItem.SetLabel(fmt.Sprintf("Внешний IP: %s (%s)", ip, country))
					} else {
						ipItem.SetLabel(fmt.Sprintf("Внешний IP: %s", ip))
					}
				} else {
					ipItem.SetLabel("Внешний IP: —")
				}
			})
		}()
	}

	refreshUI = func(forceIP bool) {
		go func() {
			st, _ := state.Load(statePath)

			stateMu.Lock()
			connecting := isConnecting
			errStr := startError
			discReason := lastDisconnectReason
			recAt := reconnectedAt
			stateMu.Unlock()

			isLocalActive := sess.IsActive()
			isAlive := st != nil && st.PID > 0 && session.IsPIDAlive(st.PID)
			isCLIActive := !isLocalActive && st != nil && st.ActiveSession && isAlive && st.PID != os.Getpid()
			isCLIReconnecting := !isLocalActive && isAlive && st != nil && st.Reconnecting && st.PID != os.Getpid()
			isCLINetworkDown := !isLocalActive && isAlive && st != nil && st.NetworkDown && st.PID != os.Getpid()
			restartHidden := !(isLocalActive && sess.RestartPending())
			phase := sess.Phase()

			var (
				trayLabel         string
				statusLabel       string
				toggleLabel       string
				toggleEnabled     bool
				rttHidden         bool
				rttLabel          string
				recoveryHidden    bool
				reconnectedHidden bool
				reconnectedLabel  string
			)
			reconnectedHidden = true

			if connecting {
				trayLabel = "🟡 …"
				statusLabel = "Статус: подключение…"
				toggleLabel = "Подключение…"
				toggleEnabled = false
				rttHidden = true
			} else if phase == session.PhaseNetworkDown || (isLocalActive && st != nil && st.NetworkDown) || isCLINetworkDown {
				trayLabel = "🟡 нет сети"
				statusLabel = "Статус: нет сети (ожидание подключения)"
				toggleLabel = "Выключить системный прокси"
				toggleEnabled = true
				rttHidden = true
			} else if phase == session.PhaseReconnecting || isCLIReconnecting {
				info := sess.ReconnectInfo()
				attempt := info.Attempt
				next := info.Next
				reason := info.LastReason
				if !isLocalActive && isCLIReconnecting {
					attempt = st.ReconnectAttempt
					next = st.NextReconnect
					reason = st.LastDisconnectReason
				}
				secs := int(time.Until(next).Seconds())
				if secs < 0 {
					secs = 0
				}
				if reason == "" {
					reason = "прокси не отвечает"
				}
				trayLabel = fmt.Sprintf("🔴 переподключение (%d)", attempt)
				statusLabel = fmt.Sprintf("Следующая попытка через %d с · %s", secs, reason)
				toggleLabel = "Отменить переподключение"
				toggleEnabled = true
				rttHidden = true
			} else if isLocalActive {
				trayLabel = "🟢 вкл"
				service := "Wi-Fi"
				if cur, err := sysproxy.Current(); err == nil && cur != nil && cur.Service != "" {
					service = cur.Service
				}
				statusLabel = fmt.Sprintf("Статус: подключено (%s)", service)
				toggleLabel = "Выключить системный прокси"
				toggleEnabled = true

				rtt := sess.RTT()
				if rtt > 0 {
					rttHidden = false
					rttLabel = "Задержка: " + formatRTTTray(rtt)
				} else {
					rttHidden = true
				}
				recoveryHidden = true
				if recAt != "" {
					reconnectedHidden = false
					reconnectedLabel = fmt.Sprintf("Восстановлено в %s", recAt)
				}
			} else if isCLIActive {
				trayLabel = "🟢 CLI"
				statusLabel = fmt.Sprintf("Сессия запущена из CLI (PID %d)", st.PID)
				toggleLabel = "Остановить сессию CLI"
				toggleEnabled = true
				rttHidden = true
				recoveryHidden = true

				// Async RTT check without delaying CLI status update
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					rtt, err := sess.CheckRTT(ctx)
					if err == nil && rtt > 0 {
						application.InvokeAsync(func() {
							rttItem.SetLabel("Задержка: " + formatRTTTray(rtt)).SetHidden(false)
						})
					}
				}()
			} else {
				if errStr != "" {
					trayLabel = "🔴 ошибка"
					statusLabel = fmt.Sprintf("Ошибка: %s", errStr)
				} else if discReason != "" && discReason != "user disabled" && discReason != "stopped" && discReason != "quit" {
					trayLabel = "🔴 оборвано"
					statusLabel = fmt.Sprintf("Прямое подключение (%s)", discReason)
				} else {
					trayLabel = "🔴 OFF"
					statusLabel = "Прямое подключение"
				}
				toggleLabel = "Включить системный прокси"
				toggleEnabled = true
				rttHidden = true
			}

			// Store current tray label for inspection and set safely from background goroutine
			currentTrayLabelMu.Lock()
			currentTrayLabel = trayLabel
			currentTrayLabelMu.Unlock()
			systray.SetLabel(trayLabel)

			// Update menu item widgets safely on main thread via InvokeAsync
			application.InvokeAsync(func() {
				statusItem.SetLabel(statusLabel)
				if reconnectedItem != nil {
					if reconnectedHidden {
						reconnectedItem.SetHidden(true)
					} else {
						reconnectedItem.SetLabel(reconnectedLabel).SetHidden(false)
					}
				}
				toggleItem.SetLabel(toggleLabel).SetEnabled(toggleEnabled)
				if restartItem != nil {
					restartItem.SetHidden(restartHidden)
				}
				if rttHidden {
					rttItem.SetHidden(true)
				} else {
					rttItem.SetLabel(rttLabel).SetHidden(false)
				}
				if recoveryItem != nil && recoveryHidden {
					recoveryItem.SetHidden(true)
				}

				// External IP display: show cached IP or "—", never trigger network request automatically
				cachedIP, cachedCountry := sess.CachedIP()
				if !isLocalActive && isCLIActive && st.CachedExternalIP != "" {
					cachedIP = st.CachedExternalIP
					cachedCountry = st.CachedCountry
				}
				if cachedIP != "" {
					if cachedCountry != "" {
						ipItem.SetLabel(fmt.Sprintf("Внешний IP: %s (%s)", cachedIP, cachedCountry))
					} else {
						ipItem.SetLabel(fmt.Sprintf("Внешний IP: %s", cachedIP))
					}
				} else {
					ipItem.SetLabel("Внешний IP: —")
				}
			})
		}()
	}

	turnOffProxy = func() {
		stateMu.Lock()
		reconnectedAt = ""
		stateMu.Unlock()

		st, _ := state.Load(statePath)
		isActive := sess.IsActive()
		isCLI := st != nil && st.ActiveSession && session.IsPIDAlive(st.PID) && st.PID != os.Getpid()
		isReconnecting := sess.Phase() == session.PhaseReconnecting || (st != nil && st.Reconnecting)

		if isReconnecting || isActive {
			_ = sess.Stop("user disabled")
			sess.ResetIPCache()
			stateMu.Lock()
			startError = ""
			lastDisconnectReason = "user disabled"
			wasConnected = false
			stateMu.Unlock()
			refreshUI(false)
		} else if isCLI {
			_ = session.StopActiveSession(statePath, "user disabled")
			sess.ResetIPCache()
			stateMu.Lock()
			startError = ""
			lastDisconnectReason = "user disabled"
			wasConnected = false
			stateMu.Unlock()
			refreshUI(false)
		} else if refreshUI != nil {
			refreshUI(false)
		}
	}

	// Menu actions
	var (
		toggleMu       sync.Mutex
		isToggling     bool
		lastToggleTime time.Time
	)
	toggleHandler := func() {
		toggleMu.Lock()
		now := time.Now()
		if isToggling || now.Sub(lastToggleTime) < 150*time.Millisecond {
			toggleMu.Unlock()
			return // ignore overlapping clicks while toggle is already in flight or rapid double-clicks
		}
		isToggling = true
		lastToggleTime = now
		toggleMu.Unlock()

		go func() {
			defer func() {
				toggleMu.Lock()
				isToggling = false
				toggleMu.Unlock()
			}()

			st, _ := state.Load(statePath)
			isActive := sess.IsActive()
			isCLI := st != nil && st.ActiveSession && session.IsPIDAlive(st.PID) && st.PID != os.Getpid()
			isReconnecting := sess.Phase() == session.PhaseReconnecting || (st != nil && st.Reconnecting)

			if isReconnecting || isActive || isCLI {
				turnOffProxy()
			} else {
				stateMu.Lock()
				isConnecting = true
				startError = ""
				stateMu.Unlock()

				// Immediately set "Подключение…" and disable button
				refreshUI(false)

				sess.ResetIPCache()
				c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err := sess.Start(c)
				cancel()

				stateMu.Lock()
				isConnecting = false
				if err != nil {
					startError = err.Error()
					lastDisconnectReason = ""
					wasConnected = false
				} else {
					startError = ""
					lastDisconnectReason = ""
					wasConnected = true
				}
				stateMu.Unlock()

				refreshUI(false)
			}
		}()
	}

	toggleItem.OnClick(func(ctx *application.Context) {
		toggleHandler()
	})

	restartHandler = func() {
		toggleMu.Lock()
		now := time.Now()
		if isToggling || now.Sub(lastToggleTime) < 150*time.Millisecond {
			toggleMu.Unlock()
			return
		}
		isToggling = true
		lastToggleTime = now
		toggleMu.Unlock()

		go func() {
			defer func() {
				toggleMu.Lock()
				isToggling = false
				toggleMu.Unlock()
			}()

			stateMu.Lock()
			reconnectedAt = ""
			isConnecting = true
			startError = ""
			stateMu.Unlock()
			refreshUI(false)

			sess.ResetIPCache()
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := sess.Restart(c)
			cancel()

			stateMu.Lock()
			isConnecting = false
			if err != nil {
				startError = err.Error()
				lastDisconnectReason = ""
				wasConnected = false
			} else {
				startError = ""
				lastDisconnectReason = ""
				wasConnected = true
			}
			stateMu.Unlock()

			refreshUI(false)
		}()
	}

	restartItem.OnClick(func(ctx *application.Context) {
		restartHandler()
	})

	var (
		lastIPRefreshTime time.Time
		lastIPRefreshMu   sync.Mutex
	)
	refreshHandler := func() {
		stateMu.Lock()
		reconnectedAt = ""
		stateMu.Unlock()

		lastIPRefreshMu.Lock()
		if time.Since(lastIPRefreshTime) < 10*time.Second {
			lastIPRefreshMu.Unlock()
			refreshUI(false)
			return
		}
		lastIPRefreshTime = time.Now()
		lastIPRefreshMu.Unlock()

		sess.ResetIPCache()
		application.InvokeAsync(func() {
			ipItem.SetLabel("Внешний IP: определяется…")
		})
		updateExternalIP(true)
	}

	refreshItem.OnClick(func(ctx *application.Context) {
		refreshHandler()
	})

	var (
		settingsWindow   *application.WebviewWindow
		settingsWindowMu sync.Mutex
	)

	openSettingsWindow := func() {
		settingsWindowMu.Lock()
		defer settingsWindowMu.Unlock()

		if settingsWindow != nil {
			application.InvokeAsync(func() {
				settingsWindow.Show()
				settingsWindow.Focus()
			})
			return
		}

		w := app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:            "settings",
			Title:           "Настройки gostpx",
			Width:           480,
			Height:          600,
			DisableResize:   true,
			InitialPosition: application.WindowCentered,
			URL:             "/",
			Mac: application.MacWindow{
				Backdrop: application.MacBackdropNormal,
			},
		})

		w.OnWindowEvent(events.Common.WindowClosing, func(e *application.WindowEvent) {
			settingsWindowMu.Lock()
			settingsWindow = nil
			settingsWindowMu.Unlock()
		})

		settingsWindow = w
		w.Show()
		w.Focus()
	}

	settingsItem.OnClick(func(ctx *application.Context) {
		go openSettingsWindow()
	})

	configItem.OnClick(func(ctx *application.Context) {
		// Open config in default editor without blocking UI
		_ = exec.Command("open", "-t", configPath).Start()
	})

	quitItem.OnClick(func(ctx *application.Context) {
		quitWithWatchdog("quit")
	})

	// On click handler for selftest / shortcuts
	systrayClickHandler := func() {
		refreshUI(false)
	}

	// Watch state.json for instant CLI session detection without background polling (requirement 5)
	var watcherErr error
	stateWatcher, watcherErr = session.WatchState(statePath, func() {
		refreshUI(false)
	})
	if watcherErr != nil {
		fmt.Fprintf(os.Stderr, "Ошибка запуска watcher state.json: %v\n", watcherErr)
	}

	// Monitor session events for immediate disconnect detection (ARCHITECTURE §7)
	go func() {
		policy := notify.NewPolicy()
		for evt := range sess.Events() {
			if !isSelftest() {
				if msg, ok := policy.Next(evt, time.Now()); ok {
					sendNotification(msg.Title, msg.Body)
				}
			}

			switch evt.Type {
			case session.EventDisconnected:
				sess.ResetIPCache()
				stateMu.Lock()
				if wasConnected {
					lastDisconnectReason = evt.Reason
				}
				wasConnected = false
				stateMu.Unlock()
				refreshUI(false)
			case session.EventConnected:
				sess.ResetIPCache()
				stateMu.Lock()
				wasConnected = true
				startError = ""
				lastDisconnectReason = ""
				stateMu.Unlock()
				refreshUI(false)
			case session.EventReconnected:
				sess.ResetIPCache()
				stateMu.Lock()
				wasConnected = true
				startError = ""
				lastDisconnectReason = ""
				reconnectedAt = time.Now().Format("15:04")
				stateMu.Unlock()
				refreshUI(false)
			case session.EventNetworkDown, session.EventNetworkUp:
				refreshUI(false)
			case session.EventConfigReload:
				if reloadedCfg, _, err := config.Load(configPath); err == nil {
					warn, _ := autostart.Sync(reloadedCfg.Autostart, currentExec)
					application.InvokeAsync(func() {
						if autostartWarnItem != nil {
							if warn != "" {
								autostartWarnItem.SetLabel(warn).SetHidden(false)
							} else {
								autostartWarnItem.SetHidden(true)
							}
						}
					})
				}
				refreshUI(false)
			}
		}
	}()

	// Signal handling for clean rollback on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, session.ShutdownSignals...)
	go func() {
		<-sigCh
		quitWithWatchdog("signal")
	}()

	// Initial render after app starts
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		refreshUI(false)

		if isSelftest() {
			getTrayLabel := func() string {
				currentTrayLabelMu.RLock()
				defer currentTrayLabelMu.RUnlock()
				return currentTrayLabel
			}
			go runSelftest(app, getTrayLabel, sess, toggleHandler, refreshHandler, systrayClickHandler, openSettingsWindow)
		} else {
			// Autoconnect on application start if enabled and configured (B3)
			st, _ := state.Load(statePath)
			isCLIActive := st.ActiveSession && session.IsPIDAlive(st.PID) && st.PID != os.Getpid()
			currentCfg := sess.Config()
			if currentCfg == nil {
				currentCfg = cfg
			}
			if currentCfg != nil && currentCfg.Autoconnect && currentCfg.Proxy.Host != "" && currentCfg.Mode == config.ModeSysproxy && !isCLIActive {
				toggleHandler()
			}
		}
	})

	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Wails application error: %v\n", err)
	}
}

func formatRTTTray(rtt time.Duration) string {
	if rtt > 0 && rtt < time.Millisecond {
		return "<1 мс"
	}
	return fmt.Sprintf("%d мс", rtt.Milliseconds())
}

// connwatchRunning keeps repeated menu clicks from starting parallel checks.
var connwatchRunning atomic.Bool

func runConnwatchCheck(app *application.App, sess *session.Session, configPath, statePath string) {
	if !connwatchRunning.CompareAndSwap(false, true) {
		return
	}
	defer connwatchRunning.Store(false)
	// A failed diagnostic must never take the tray down (it would leave the system proxy set).
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "проверка соединений: %v\n", r)
		}
	}()
	st, _ := state.Load(statePath)
	isLocalActive := sess.IsActive()
	isCLIActive := st != nil && st.ActiveSession && st.PID > 0 && session.IsPIDAlive(st.PID)
	if !isLocalActive && !isCLIActive {
		dialog := app.Dialog.Info()
		dialog.SetTitle("gostpx: соединения мимо прокси")
		dialog.SetMessage("Сессия gostpx не активна — все соединения идут напрямую.")
		dialog.Show()
		return
	}

	cfg, _, _ := config.Load(configPath)
	if cfg == nil {
		cfg = sess.Config()
	}
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	ignore := connwatch.Ignore{
		SelfPID: os.Getpid(),
	}
	if isCLIActive && st.PID > 0 {
		ignore.SelfPID = st.PID
	}

	if ap, ok := parseListenerAddr(cfg.Sysproxy.HTTPListen); ok {
		ignore.Listeners = append(ignore.Listeners, ap)
	}
	if ap, ok := parseListenerAddr(cfg.Sysproxy.SOCKSListen); ok {
		ignore.Listeners = append(ignore.Listeners, ap)
	}

	if cfg.Proxy.Host != "" {
		if ip, err := netip.ParseAddr(cfg.Proxy.Host); err == nil {
			ignore.ProxyIPs = append(ignore.ProxyIPs, ip)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", cfg.Proxy.Host)
			cancel()
			if err == nil {
				for _, ip := range ips {
					if nip, ok := netip.AddrFromSlice(ip); ok {
						ignore.ProxyIPs = append(ignore.ProxyIPs, nip.Unmap())
					}
				}
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conns, err := connwatch.Take(ctx)
	if err != nil {
		dialog := app.Dialog.Info()
		dialog.SetTitle("gostpx: соединения мимо прокси")
		dialog.SetMessage(fmt.Sprintf("Ошибка проверки: %v", err))
		dialog.Show()
		return
	}

	report := connwatch.Classify(conns, ignore)

	var sb strings.Builder
	if len(report.Bypass) == 0 {
		sb.WriteString("Мимо прокси соединений не видно.\n(эвристика: соединение мимо слушателей gostpx и не в локальную сеть)")
	} else {
		sb.WriteString(fmt.Sprintf("Соединения мимо прокси на %s (эвристика):\n", report.Taken.Format("15:04:05")))
		maxLines := 9
		displayed := 0
		for i, g := range report.Bypass {
			if displayed >= maxLines-1 && len(report.Bypass)-i > 1 {
				sb.WriteString(fmt.Sprintf("... и ещё %d процессов\n", len(report.Bypass)-i))
				displayed++
				break
			}
			var pidStrs []string
			for _, pid := range g.PIDs {
				pidStrs = append(pidStrs, strconv.Itoa(pid))
			}
			pidStr := strings.Join(pidStrs, ", ")

			var sampleStrs []string
			for _, s := range g.Samples {
				sampleStrs = append(sampleStrs, s.String())
			}

			if len(sampleStrs) > 0 {
				sb.WriteString(fmt.Sprintf("• %s (PID %s): %d соед., напр. %s\n", g.Process, pidStr, g.Count, strings.Join(sampleStrs, ", ")))
			} else {
				sb.WriteString(fmt.Sprintf("• %s (PID %s): %d соед.\n", g.Process, pidStr, g.Count))
			}
			displayed++
		}
	}

	dialog := app.Dialog.Info()
	dialog.SetTitle("gostpx: соединения мимо прокси")
	dialog.SetMessage(strings.TrimSpace(sb.String()))
	dialog.Show()
}

func parseListenerAddr(addrStr string) (netip.AddrPort, bool) {
	if addrStr == "" {
		return netip.AddrPort{}, false
	}
	if strings.HasPrefix(addrStr, ":") {
		addrStr = "127.0.0.1" + addrStr
	}
	if ap, err := netip.ParseAddrPort(addrStr); err == nil {
		return ap, true
	}
	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return netip.AddrPort{}, false
	}
	if host == "" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return netip.AddrPort{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, uint16(port)), true
}
