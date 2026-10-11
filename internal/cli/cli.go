package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/engine"
	"github.com/losoph/gostpx/internal/session"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

// Exit codes conforming to CLI.md
const (
	ExitSuccess          = 0
	ExitGeneralError     = 1
	ExitConfigError      = 2
	ExitDaemonUnreach    = 3
	ExitPermissionDenied = 4
	ExitUpstreamUnreach  = 5
)

// Version is injected at build time via -ldflags "-X .../internal/cli.Version=...".
var Version = "dev"

// RootCmd is the base command for gostpx CLI.
var RootCmd = &cobra.Command{
	Use:   "gostpx",
	Short: "gostpx — быстрый переключатель системного прокси",
	Long: `gostpx — утилита для переключения системного прокси на macOS и Windows.
Один прокси из конфига, одна команда — и его начинают использовать
приложения, уважающие системный прокси.

Это переключатель системного прокси, а не перехватчик всего трафика:
консоль, UDP/QUIC и приложения со своим сетевым стеком идут мимо.
Режим TUN, который ловит весь IPv4-трафик, появится в Phase 3.
Точный охват — gostpx status и docs/LIMITATIONS.md.`,
	Version: Version,
	RunE: func(cmd *cobra.Command, args []string) error {
		// In Phase 1 without GUI/tray, default action without args shows status and help
		_ = runStatus(cmd, args)
		fmt.Println()
		printGuiHint()
		fmt.Println("Для справки по командам используйте: gostpx --help")
		return nil
	},
}

var (
	jsonOutput bool
	checkIP    bool
	showFlag   bool
)

func init() {
	RootCmd.SilenceUsage = true
	RootCmd.SilenceErrors = true

	// on
	RootCmd.AddCommand(onCmd)

	// off
	RootCmd.AddCommand(offCmd)

	// toggle
	RootCmd.AddCommand(toggleCmd)

	// mode
	RootCmd.AddCommand(modeCmd)

	// status
	statusCmd.Flags().BoolVar(&jsonOutput, "json", false, "вывод в формате JSON")
	statusCmd.Flags().BoolVar(&checkIP, "check-ip", false, "проверить внешний IP через прокси")
	RootCmd.AddCommand(statusCmd)

	// env
	RootCmd.AddCommand(envCmd)

	// set
	setCmd.Flags().BoolVar(&showFlag, "show", false, "показать текущий настроенный прокси")
	RootCmd.AddCommand(setCmd)

	// dns
	dnsCmd.Flags().BoolVar(&showFlag, "show", false, "показать текущий DoH")
	RootCmd.AddCommand(dnsCmd)

	// test
	RootCmd.AddCommand(testCmd)

	// config
	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configEditCmd)
	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configReloadCmd)
	RootCmd.AddCommand(configCmd)
}

// Execute runs the root command and exits with the appropriate status code.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		var exitCode = ExitGeneralError
		var cliErr *CLIError
		if errors.As(err, &cliErr) {
			exitCode = cliErr.Code
		}
		if err.Error() != "" {
			fmt.Fprintln(os.Stderr, "Ошибка:", err.Error())
		}
		os.Exit(exitCode)
	}
}

// CLIError associates an exit code with an error.
type CLIError struct {
	Code int
	Err  error
}

func (e *CLIError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return ""
}

func newCLIError(code int, err error) error {
	return &CLIError{Code: code, Err: err}
}

// --- onCmd ---
var onCmd = &cobra.Command{
	Use:   "on",
	Short: "Включить системный прокси и запустить перехват",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		statePath, err := state.DefaultStatePath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}

		sess := session.New(configPath, statePath)
		sess.OnConfigReload = func(newCfg *config.Config, requiresRestart bool) {
			if requiresRestart {
				fmt.Println("\n[конфиг обновлен] Изменение режима или параметров прокси требует перезапуска (gostpx on)")
			} else {
				fmt.Println("\n[конфиг обновлен] Новые настройки применены без разрыва соединения")
			}
		}
		sess.OnConfigError = func(err error, issues []config.Issue) {
			fmt.Printf("\n[ошибка конфига] %v (старый конфиг продолжает работать)\n", err)
		}

		// Preview config for warnings before start
		cfg, _, _ := config.Load(configPath)
		if cfg != nil && cfg.Mode == config.ModeTun {
			fmt.Println("⚠ Режим 'tun' требует системного демона (Phase 3). Подключение в режиме 'sysproxy'...")
		}

		if err := sess.Start(context.Background()); err != nil {
			if errors.Is(err, session.ErrAlreadyActive) {
				st, _ := state.Load(statePath)
				fmt.Printf("● Сессия уже активна (PID %d)\n", st.PID)
				return nil
			}
			if errors.Is(err, session.ErrNoProxy) || strings.Contains(err.Error(), "валидации конфига") || strings.Contains(err.Error(), "загрузка конфига") || strings.Contains(err.Error(), "чтение пароля") {
				return newCLIError(ExitConfigError, err)
			}
			if strings.Contains(err.Error(), "прокси недоступен") ||
				errors.Is(err, engine.ErrUpstreamUnreachable) ||
				errors.Is(err, engine.ErrAuthFailed) ||
				errors.Is(err, engine.ErrInvalidProtocol) ||
				errors.Is(err, engine.ErrTargetUnreachable) {
				return newCLIError(ExitUpstreamUnreach, err)
			}
			return newCLIError(ExitGeneralError, err)
		}

		curCfg := sess.Config()
		fmt.Printf("● подключено      %s  %s:%d   режим: sysproxy   %s\n",
			curCfg.Proxy.Type, curCfg.Proxy.Host, curCfg.Proxy.Port, FormatRTT(sess.RTT()))
		for _, line := range session.SysproxyCoverageLines() {
			fmt.Println(line)
		}

		// Listen for termination signals for clean rollback
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, session.ShutdownSignals...)

	wait:
		for {
			select {
			case sig := <-sigCh:
				fmt.Printf("\nПолучен сигнал %s, отключение...\n", sig)
				_ = sess.Stop("stopped")
				break wait
			case evt := <-sess.Events():
				action, msg := HandleOnEvent(evt, sess.Phase(), time.Now())
				if msg != "" {
					fmt.Println(msg)
				}
				if action == OnActionExit {
					_ = sess.Stop("disconnected")
					break wait
				}
			}
		}

		fmt.Println("○ системный прокси отключен")
		return nil
	},
}

// OnEventAction defines the action onCmd should take on a session event.
type OnEventAction int

const (
	OnActionContinue OnEventAction = iota
	OnActionExit
)

// HandleOnEvent decides the action and message to print for a session event in gostpx on.
func HandleOnEvent(evt session.Event, phase session.Phase, now time.Time) (OnEventAction, string) {
	switch evt.Type {
	case session.EventDisconnected:
		if phase == session.PhaseReconnecting {
			return OnActionContinue, fmt.Sprintf("○ обрыв: %s — переподключение…", evt.Reason)
		}
		if phase == session.PhaseNetworkDown {
			return OnActionContinue, "🟡 нет сети…"
		}
		msg := fmt.Sprintf("\n○ прямое подключение        причина: %s\n  ⚠ весь трафик идёт мимо прокси, с реальным IP", evt.Reason)
		return OnActionExit, msg

	case session.EventNetworkDown:
		return OnActionContinue, "🟡 нет сети…"

	case session.EventNetworkUp:
		return OnActionContinue, fmt.Sprintf("● восстановлено %s", now.Format("15:04:05"))

	case session.EventReconnected:
		return OnActionContinue, fmt.Sprintf("● восстановлено %s", now.Format("15:04:05"))

	default:
		return OnActionContinue, ""
	}
}

// --- offCmd ---
var offCmd = &cobra.Command{
	Use:   "off",
	Short: "Отключить системный прокси",
	RunE: func(cmd *cobra.Command, args []string) error {
		statePath, err := state.DefaultStatePath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}

		if err := session.StopActiveSession(statePath, "user disabled"); err != nil {
			return newCLIError(ExitGeneralError, err)
		}

		fmt.Println("○ системный прокси отключен")
		return nil
	},
}

// --- toggleCmd ---
var toggleCmd = &cobra.Command{
	Use:   "toggle",
	Short: "Переключить состояние прокси (вкл/выкл)",
	RunE: func(cmd *cobra.Command, args []string) error {
		statePath, err := state.DefaultStatePath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		st, _ := state.Load(statePath)
		if st.ActiveSession && session.IsPIDAlive(st.PID) {
			return offCmd.RunE(cmd, args)
		}
		return onCmd.RunE(cmd, args)
	},
}

// --- modeCmd ---
var modeCmd = &cobra.Command{
	Use:   "mode [tun|sysproxy|off]",
	Short: "Установить или просмотреть текущий режим работы",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		statePath, err := state.DefaultStatePath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		st, _ := state.Load(statePath)

		if len(args) == 0 {
			fmt.Printf("Текущий режим: %s\n", st.Mode)
			return nil
		}

		targetMode := args[0]
		switch targetMode {
		case config.ModeTun:
			fmt.Println("⚠ Режим 'tun' требует системного демона (Phase 3). В Phase 1 доступен режим 'sysproxy'.")
			st.Mode = config.ModeTun
			_ = state.Save(statePath, st)
		case config.ModeSysproxy:
			st.Mode = config.ModeSysproxy
			_ = state.Save(statePath, st)
			fmt.Println("Режим переключен на sysproxy")
		case config.ModeOff:
			_ = offCmd.RunE(cmd, nil)
			st.Mode = config.ModeOff
			_ = state.Save(statePath, st)
			fmt.Println("Режим переключен на off")
		default:
			return newCLIError(ExitGeneralError, fmt.Errorf("неизвестный режим %q (допустимы: tun, sysproxy, off)", targetMode))
		}
		return nil
	},
}

// --- statusCmd ---
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Показать текущий статус и охват трафика",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	configPath, err := config.DefaultConfigPath()
	if err != nil {
		return newCLIError(ExitGeneralError, err)
	}
	statePath, err := state.DefaultStatePath()
	if err != nil {
		return newCLIError(ExitGeneralError, err)
	}

	cfg, _, err := config.Load(configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}

	st, _ := state.Load(statePath)
	if st == nil {
		st = state.DefaultState()
	}

	isAlive := st.PID > 0 && session.IsPIDAlive(st.PID)

	// Check if PID is still alive; if crashed, recover state
	if st.ActiveSession && !isAlive {
		var httpListen, socksListen string
		if cfg != nil {
			httpListen = cfg.Sysproxy.HTTPListen
			socksListen = cfg.Sysproxy.SOCKSListen
		}
		if unsetErr := sysproxy.Unset(st.SysproxySnapshot, httpListen, socksListen); unsetErr != nil {
			st.LastDisconnectReason = fmt.Sprintf("процесс завершился аварийно (ошибка снятия прокси: %v)", unsetErr)
			_ = state.Save(statePath, st)
			return newCLIError(ExitGeneralError, fmt.Errorf("процесс PID %d завершился аварийно, не удалось снять системный прокси: %w", st.PID, unsetErr))
		}
		st.ActiveSession = false
		st.PID = 0
		st.LastDisconnectReason = "процесс завершился аварийно, прокси сброшен"
		st.SysproxySnapshot = nil
		st.Reconnecting = false
		st.NetworkDown = false
		st.ReconnectAttempt = 0
		st.NextReconnect = time.Time{}
		if err := state.Save(statePath, st); err != nil {
			return newCLIError(ExitGeneralError, fmt.Errorf("сохранение состояния: %w", err))
		}
	} else if (st.Reconnecting || st.NetworkDown) && !isAlive {
		st.Reconnecting = false
		st.NetworkDown = false
		st.ReconnectAttempt = 0
		st.NextReconnect = time.Time{}
		st.PID = 0
		if st.LastDisconnectReason == "" {
			st.LastDisconnectReason = "процесс завершился"
		}
		_ = state.Save(statePath, st)
	}

	active := st.ActiveSession && isAlive

	// Optional external IP check
	var externalIP string
	var externalCountry string
	if checkIP && active {
		externalIP, externalCountry = fetchExternalIP(cfg.Sysproxy.HTTPListen)
	}

	if jsonOutput {
		return printJSONStatus(active, cfg, st, externalIP, externalCountry)
	}

	rttStr := ""
	if active && cfg.Proxy.Host != "" && cfg.Proxy.Port > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		rtt, err := engine.CheckProxy(ctx, cfg.Proxy.Host, cfg.Proxy.Port, 2*time.Second)
		cancel()
		if err == nil {
			rttStr = "   " + FormatRTT(rtt)
		}
	}

	printTextStatus(active, cfg, st, externalIP, externalCountry, rttStr)
	return nil
}

func printTextStatus(active bool, cfg *config.Config, st *state.State, externalIP, externalCountry, rttStr string) {
	isAlive := st.PID > 0 && session.IsPIDAlive(st.PID)
	isReconnecting := st.Reconnecting && isAlive
	isNetworkDown := st.NetworkDown && isAlive

	if active && isAlive {
		fmt.Printf("● подключено      %s  %s:%d   режим: %s%s\n",
			cfg.Proxy.Type, cfg.Proxy.Host, cfg.Proxy.Port, st.Mode, rttStr)
		if isNetworkDown {
			fmt.Println("  Сеть: нет локального подключения (ожидание)")
		}
		for _, line := range session.SysproxyCoverageLines() {
			fmt.Println(line)
		}
		if externalIP != "" {
			if externalCountry != "" {
				fmt.Printf("  внешний IP      %s (%s)\n", externalIP, externalCountry)
			} else {
				fmt.Printf("  внешний IP      %s\n", externalIP)
			}
		}
		if !st.LastConnected.IsZero() {
			uptime := time.Since(st.LastConnected).Round(time.Minute)
			fmt.Printf("  сессия          %v\n", uptime)
		}
	} else if isReconnecting {
		secs := int(time.Until(st.NextReconnect).Seconds())
		if secs < 0 {
			secs = 0
		}
		reason := st.LastDisconnectReason
		if reason == "" {
			reason = "неизвестно"
		}
		fmt.Printf("Переподключение: попытка %d, следующая через %d с (причина: %s)\n",
			st.ReconnectAttempt, secs, reason)
		if isNetworkDown {
			fmt.Println("  Сеть: нет локального подключения (ожидание)")
		}
		fmt.Println("  ⚠ весь трафик идёт мимо прокси, с реальным IP")
	} else {
		if isNetworkDown {
			fmt.Println("  Сеть: нет локального подключения (ожидание)")
		}
		if st.LastDisconnectReason != "" && st.LastDisconnectReason != "stopped" && st.LastDisconnectReason != "user disabled" {
			fmt.Printf("○ прямое подключение        причина: %s\n", st.LastDisconnectReason)
		} else {
			fmt.Println("○ прямое подключение")
		}
		fmt.Println("  ⚠ весь трафик идёт мимо прокси, с реальным IP")
	}
}

type statusJSON struct {
	State            string         `json:"state"`
	Mode             string         `json:"mode"`
	Proxy            string         `json:"proxy,omitempty"`
	RTTMs            int64          `json:"rtt_ms,omitempty"`
	UptimeS          int64          `json:"uptime_s,omitempty"`
	ExternalIP       string         `json:"external_ip,omitempty"`
	ExternalCountry  string         `json:"external_country,omitempty"`
	Coverage         statusCoverage `json:"coverage"`
	Warnings         []string       `json:"warnings"`
	Reason           string         `json:"reason,omitempty"`
	NetworkDown      bool           `json:"network_down"`
	Reconnecting     bool           `json:"reconnecting"`
	ReconnectAttempt int            `json:"reconnect_attempt,omitempty"`
	NextReconnect    string         `json:"next_reconnect,omitempty"`
}

type statusCoverage struct {
	IPv4    bool   `json:"ipv4"`
	IPv6    bool   `json:"ipv6"`
	DNS     string `json:"dns"`
	Console bool   `json:"console"`
}

func printJSONStatus(active bool, cfg *config.Config, st *state.State, extIP, extCountry string) error {
	isAlive := st.PID > 0 && session.IsPIDAlive(st.PID)
	isReconnecting := st.Reconnecting && isAlive
	isNetworkDown := st.NetworkDown && isAlive

	sj := statusJSON{
		Mode:         st.Mode,
		NetworkDown:  isNetworkDown,
		Reconnecting: isReconnecting,
	}
	if isReconnecting {
		sj.ReconnectAttempt = st.ReconnectAttempt
		if !st.NextReconnect.IsZero() {
			sj.NextReconnect = st.NextReconnect.Format(time.RFC3339)
		}
	}

	if active && isAlive {
		sj.State = "connected"
		sj.Proxy = fmt.Sprintf("%s://%s:%d", cfg.Proxy.Type, cfg.Proxy.Host, cfg.Proxy.Port)
		if !st.LastConnected.IsZero() {
			sj.UptimeS = int64(time.Since(st.LastConnected).Seconds())
		}
		sj.ExternalIP = extIP
		sj.ExternalCountry = extCountry
		sj.Coverage = statusCoverage{
			IPv4:    false,
			IPv6:    false,
			DNS:     "system",
			Console: false,
		}
		sj.Warnings = []string{"console_direct", "udp_quic_direct", "doh_not_applicable"}
	} else if isReconnecting {
		sj.State = "reconnecting"
		sj.Reason = st.LastDisconnectReason
		sj.Coverage = statusCoverage{
			IPv4:    false,
			IPv6:    false,
			DNS:     "direct",
			Console: false,
		}
		sj.Warnings = []string{"all_traffic_direct"}
	} else {
		sj.State = "disconnected"
		sj.Reason = st.LastDisconnectReason
		sj.Coverage = statusCoverage{
			IPv4:    false,
			IPv6:    false,
			DNS:     "direct",
			Console: false,
		}
		sj.Warnings = []string{"all_traffic_direct"}
	}

	data, err := json.MarshalIndent(sj, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func fetchExternalIP(httpProxyAddr string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, country, err := session.FetchExternalIP(ctx, httpProxyAddr)
	if err != nil {
		return "", ""
	}
	return ip, country
}

// --- setCmd ---
var setCmd = &cobra.Command{
	Use:   "set [url]",
	Short: "Задать адрес и параметры прокси-сервера",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		cfg, _, err := loadOrCreateConfig(configPath)
		if err != nil {
			return newCLIError(ExitConfigError, err)
		}

		if showFlag || len(args) == 0 {
			masked := fmt.Sprintf("%s://%s:%d", cfg.Proxy.Type, cfg.Proxy.Host, cfg.Proxy.Port)
			if cfg.Proxy.User != "" {
				masked = fmt.Sprintf("%s://%s:***@%s:%d", cfg.Proxy.Type, cfg.Proxy.User, cfg.Proxy.Host, cfg.Proxy.Port)
			}
			fmt.Printf("Текущий прокси: %s\n", masked)
			return nil
		}

		rawURL := args[0]
		pCfg, plainPass, err := engine.ParseProxyURL(rawURL)
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}

		// Password goes to credentials.toml, never to config.toml (ADR-011).
		// A URL without a password clears it, so a new proxy never gets the old one.
		if err := config.SavePassword(config.CredentialsPath(configPath), plainPass); err != nil {
			return newCLIError(ExitGeneralError, fmt.Errorf("сохранение пароля: %w", err))
		}

		cfg.Proxy = pCfg
		if err := config.Save(configPath, cfg); err != nil {
			return newCLIError(ExitGeneralError, fmt.Errorf("сохранение конфига: %w", err))
		}

		fmt.Printf("Прокси настроен: %s\n", engine.MaskURLString(rawURL))
		return nil
	},
}

// --- dnsCmd ---
var dnsCmd = &cobra.Command{
	Use:   "dns [url]",
	Short: "Настроить DoH (DNS over HTTPS) резолвер",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		cfg, _, err := loadOrCreateConfig(configPath)
		if err != nil {
			return newCLIError(ExitConfigError, err)
		}

		if showFlag || len(args) == 0 {
			fmt.Printf("Текущий DoH: %s\n", cfg.DNS.DoH)
			fmt.Println("⚠ Внимание: в режиме sysproxy DoH не применяется (см. LIMITATIONS.md)")
			return nil
		}

		newDoH := args[0]
		u, err := url.Parse(newDoH)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return newCLIError(ExitGeneralError, fmt.Errorf("невалидный DoH URL %q (требуется https://...)", newDoH))
		}

		cfg.DNS.DoH = newDoH
		if err := config.Save(configPath, cfg); err != nil {
			return newCLIError(ExitGeneralError, fmt.Errorf("сохранение конфига: %w", err))
		}

		fmt.Printf("DoH настроен: %s\n", newDoH)
		fmt.Println("⚠ Внимание: в режиме sysproxy DoH не применяется (см. LIMITATIONS.md)")
		return nil
	},
}

// --- testCmd ---
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Проверить доступность прокси-сервера без переключения настроек",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		cfg, _, err := config.Load(configPath)
		if err != nil {
			return newCLIError(ExitConfigError, err)
		}

		if cfg.Proxy.Host == "" || cfg.Proxy.Port <= 0 {
			return newCLIError(ExitGeneralError, errors.New("прокси не настроен. Задайте через 'gostpx set <url>'"))
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		credPath := config.CredentialsPath(configPath)
		plainSecret, _ := config.LoadPassword(credPath)

		rtt, err := engine.VerifyUpstream(ctx, cfg.Proxy, plainSecret, 5*time.Second)
		if err != nil {
			fmt.Printf("✗ Прокси недоступен: %v\n", engine.SanitizeError(err, plainSecret))
			return newCLIError(ExitUpstreamUnreach, nil)
		}

		fmt.Printf("✓ Прокси доступен: %s:%d (%s)\n", cfg.Proxy.Host, cfg.Proxy.Port, FormatRTT(rtt))
		return nil
	},
}

// --- config commands ---
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Управление файлом конфигурации",
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Вывести путь к файлу config.toml",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		fmt.Println(p)
		return nil
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Проверить файл конфигурации на ошибки",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}

		cfg, issues, err := config.Load(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Ошибка парсинга: %v\n", err)
			return newCLIError(ExitConfigError, nil)
		}

		hasErrors := false
		for _, issue := range issues {
			if issue.IsWarning {
				fmt.Printf("⚠ %s\n", issue)
			} else {
				hasErrors = true
				fmt.Fprintf(os.Stderr, "✗ %s\n", issue)
			}
		}

		if hasErrors {
			return newCLIError(ExitConfigError, nil)
		}

		_ = cfg
		fmt.Println("✓ Конфигурация валидна")
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Показать эффективный конфиг с дефолтами (пароль скрыт)",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		cfg, _, err := loadOrCreateConfig(p)
		if err != nil {
			return newCLIError(ExitConfigError, err)
		}

		// Mask the deprecated secret field in case it holds a plain password
		cfgCopy := *cfg
		if cfgCopy.Proxy.Secret != "" {
			cfgCopy.Proxy.Secret = "***"
		}

		data, err := toml.Marshal(cfgCopy)
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		fmt.Println(string(data))
		return nil
	},
}

var configEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Открыть файл конфигурации в текстовом редакторе",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		_, _, _ = loadOrCreateConfig(p)

		editor := os.Getenv("VISUAL")
		if editor == "" {
			editor = os.Getenv("EDITOR")
		}
		var editCmd *exec.Cmd
		if editor != "" {
			editCmd = exec.Command(editor, p)
		} else if runtime.GOOS == "darwin" {
			editCmd = exec.Command("open", "-t", p)
		} else {
			editCmd = exec.Command("notepad", p)
		}

		editCmd.Stdin = os.Stdin
		editCmd.Stdout = os.Stdout
		editCmd.Stderr = os.Stderr

		if err := editCmd.Run(); err != nil {
			return newCLIError(ExitGeneralError, fmt.Errorf("запуск редактора: %w", err))
		}

		// Validate after edit
		return configValidateCmd.RunE(cmd, args)
	},
}

var configReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Принудительно перечитать файл конфигурации",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := config.DefaultConfigPath()
		if err != nil {
			return newCLIError(ExitGeneralError, err)
		}
		_, issues, err := config.Load(p)
		if err != nil {
			return newCLIError(ExitConfigError, fmt.Errorf("ошибка перезагрузки конфига: %w", err))
		}
		for _, issue := range issues {
			if !issue.IsWarning {
				return newCLIError(ExitConfigError, fmt.Errorf("ошибка валидации: %s", issue))
			}
		}
		fmt.Println("✓ Конфиг перечитан и валиден")
		return nil
	},
}

func loadOrCreateConfig(path string) (*config.Config, []config.Issue, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		def := config.DefaultConfig()
		if err := config.Save(path, def); err != nil {
			return nil, nil, fmt.Errorf("создание дефолтного конфига: %w", err)
		}
		return def, config.Validate(def), nil
	}
	return config.Load(path)
}

// FormatRTT formats a round-trip time duration for CLI display.
// Returns "<1 ms" for 0 < rtt < 1ms, and "%d ms" for rtt >= 1ms.
func FormatRTT(rtt time.Duration) string {
	if rtt > 0 && rtt < time.Millisecond {
		return "<1 ms"
	}
	return fmt.Sprintf("%d ms", rtt.Milliseconds())
}
