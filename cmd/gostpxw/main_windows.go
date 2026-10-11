//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"time"

	trayIcons "github.com/losoph/gostpx/cmd/gostpxw/icons"
	"github.com/losoph/gostpx/internal/autostart"
	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/session"
	"github.com/losoph/gostpx/internal/settings"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

func main() {
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
		Windows: application.WindowsOptions{
			DisableQuitOnLastWindowClosed: true,
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
	systray.SetIcon(trayIcons.IconOff)
	systray.SetTooltip("gostpx: прямое подключение")

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

	// 6b. Autostart warning if any
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

	menu.AddSeparator()

	// 8. Settings & Config
	settingsItem := menu.Add("Настройки…")
	configItem := menu.Add("Открыть конфиг")

	// 9. Quit
	quitItem := menu.Add("Выход")

	systray.SetMenu(menu)

	// On Windows, clicking tray icon opens menu
	systray.OnClick(func() {
		systray.OpenMenu()
	})

	var (
		stateMu              sync.Mutex
		isConnecting         bool
		startError           string
		lastDisconnectReason string
		wasConnected         bool
		reconnectedAt        string

		currentTrayTooltip   string
		currentTrayTooltipMu sync.RWMutex

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
				trayIcon          []byte
				trayTooltip       string
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
				trayIcon = trayIcons.IconConnecting
				trayTooltip = "gostpx: подключение…"
				statusLabel = "Статус: подключение…"
				toggleLabel = "Подключение…"
				toggleEnabled = false
				rttHidden = true
			} else if phase == session.PhaseNetworkDown || (isLocalActive && st != nil && st.NetworkDown) || isCLINetworkDown {
				trayIcon = trayIcons.IconConnecting
				trayTooltip = "gostpx: нет сети (ожидание подключения)"
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
				trayIcon = trayIcons.IconBroken
				trayTooltip = fmt.Sprintf("gostpx: переподключение (%d)", attempt)
				statusLabel = fmt.Sprintf("Следующая попытка через %d с · %s", secs, reason)
				toggleLabel = "Отменить переподключение"
				toggleEnabled = true
				rttHidden = true
			} else if isLocalActive {
				trayIcon = trayIcons.IconOn
				service := "WinINET"
				if cur, err := sysproxy.Current(); err == nil && cur != nil && cur.Service != "" {
					service = cur.Service
				}
				statusLabel = fmt.Sprintf("Статус: подключено (%s)", service)
				trayTooltip = "gostpx: подключено"
				toggleLabel = "Выключить системный прокси"
				toggleEnabled = true

				rtt := sess.RTT()
				if rtt > 0 {
					rttHidden = false
					rttLabel = "Задержка: " + formatRTTTray(rtt)
					trayTooltip = fmt.Sprintf("gostpx: подключено (%s)", formatRTTTray(rtt))
				} else {
					rttHidden = true
				}
				recoveryHidden = true
				if recAt != "" {
					reconnectedHidden = false
					reconnectedLabel = fmt.Sprintf("Восстановлено в %s", recAt)
				}
			} else if isCLIActive {
				trayIcon = trayIcons.IconOn
				statusLabel = fmt.Sprintf("Сессия запущена из CLI (PID %d)", st.PID)
				trayTooltip = fmt.Sprintf("gostpx: сессия из CLI (PID %d)", st.PID)
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
					trayIcon = trayIcons.IconError
					statusLabel = fmt.Sprintf("Ошибка: %s", errStr)
					trayTooltip = fmt.Sprintf("gostpx: ошибка (%s)", errStr)
				} else if discReason != "" && discReason != "user disabled" && discReason != "stopped" && discReason != "quit" {
					trayIcon = trayIcons.IconBroken
					statusLabel = fmt.Sprintf("Прямое подключение (%s)", discReason)
					trayTooltip = fmt.Sprintf("gostpx: оборвано (%s)", discReason)
				} else {
					trayIcon = trayIcons.IconOff
					statusLabel = "Прямое подключение"
					trayTooltip = "gostpx: прямое подключение"
				}
				toggleLabel = "Включить системный прокси"
				toggleEnabled = true
				rttHidden = true
			}

			currentTrayTooltipMu.Lock()
			currentTrayTooltip = trayTooltip
			currentTrayTooltipMu.Unlock()

			systray.SetIcon(trayIcon)
			systray.SetTooltip(trayTooltip)

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
		cmd := exec.Command("cmd.exe", "/c", "start", "", configPath)
		if err := cmd.Start(); err != nil {
			_ = exec.Command("notepad.exe", configPath).Start()
		}
	})

	quitItem.OnClick(func(ctx *application.Context) {
		quitWithWatchdog("quit")
	})

	systrayClickHandler := func() {
		refreshUI(false)
	}

	var watcherErr error
	stateWatcher, watcherErr = session.WatchState(statePath, func() {
		refreshUI(false)
	})
	if watcherErr != nil {
		fmt.Fprintf(os.Stderr, "Ошибка запуска watcher state.json: %v\n", watcherErr)
	}

	// Monitor session events for immediate disconnect detection (ARCHITECTURE §7)
	go func() {
		for evt := range sess.Events() {
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, session.ShutdownSignals...)
	go func() {
		<-sigCh
		quitWithWatchdog("signal")
	}()

	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		refreshUI(false)

		if isSelftest() {
			getTrayTooltip := func() string {
				currentTrayTooltipMu.RLock()
				defer currentTrayTooltipMu.RUnlock()
				return currentTrayTooltip
			}
			go runSelftest(app, getTrayTooltip, sess, toggleHandler, refreshHandler, systrayClickHandler, openSettingsWindow)
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
