package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/session"
	"github.com/losoph/gostpx/internal/state"
	"github.com/spf13/cobra"
)

var (
	envUnset bool
	envShell string
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Вывести команды экспорта переменных окружения прокси для терминала",
	Long: `Выводит команды установки или снятия переменных окружения (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY)
для использования в eval в текущем шелле.

Примеры:
  eval "$(gostpx env)"              # применить для текущего шелла
  eval "$(gostpx env --unset)"      # снять переменные окружения
  gostpx env --shell powershell     # синтаксис PowerShell`,
	RunE: runEnv,
}

func init() {
	envCmd.Flags().BoolVar(&envUnset, "unset", false, "вывести команды для снятия переменных окружения")
	envCmd.Flags().StringVar(&envShell, "shell", defaultEnvShell, "целевой шелл (posix, powershell)")
}

func runEnv(cmd *cobra.Command, args []string) error {
	configPath, err := config.DefaultConfigPath()
	if err != nil {
		return newCLIError(ExitGeneralError, err)
	}

	var cfg *config.Config
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
		cfg = config.DefaultConfig()
	} else {
		var loadErr error
		cfg, _, loadErr = config.Load(configPath)
		if loadErr != nil {
			return newCLIError(ExitConfigError, loadErr)
		}
	}

	shell := strings.ToLower(strings.TrimSpace(envShell))
	if shell != "posix" && shell != "powershell" {
		return newCLIError(ExitGeneralError, fmt.Errorf("неподдерживаемый шелл %q (допустимы: posix, powershell)", envShell))
	}

	// Active session check conforming to gostpx status
	statePath, err := state.DefaultStatePath()
	active := false
	if err == nil {
		if st, _ := state.Load(statePath); st != nil {
			isAlive := st.PID > 0 && session.IsPIDAlive(st.PID)
			active = st.ActiveSession && isAlive
		}
	}

	if !active && !envUnset {
		fmt.Fprintln(cmd.ErrOrStderr(), "⚠ gostpx сейчас выключен: консоль через эти адреса не выйдет")
	}

	out := formatEnvOutput(cfg, envUnset, shell)
	fmt.Fprint(cmd.OutOrStdout(), out)
	return nil
}

func posixEscape(s string) string {
	needsQuote := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '.' || r == ':' || r == '/' || r == '_' || r == ',' || r == '-' {
			continue
		}
		needsQuote = true
		break
	}
	if !needsQuote {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// powershellQuote returns a single-quoted PowerShell literal: no $ or backtick
// expansion inside, and a quote is escaped by doubling it.
func powershellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func formatEnvOutput(cfg *config.Config, unset bool, shell string) string {
	httpListen := cfg.Sysproxy.HTTPListen
	socksListen := cfg.Sysproxy.SOCKSListen

	if shell == "powershell" {
		if unset {
			return "Remove-Item Env:HTTP_PROXY -ErrorAction SilentlyContinue\n" +
				"Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue\n" +
				"Remove-Item Env:ALL_PROXY -ErrorAction SilentlyContinue\n" +
				"Remove-Item Env:NO_PROXY -ErrorAction SilentlyContinue\n"
		}
		httpVal := "http://" + httpListen
		socksVal := "socks5h://" + socksListen
		noProxyVal := "localhost,127.0.0.1,::1"
		return fmt.Sprintf("$env:HTTP_PROXY = %s\n$env:HTTPS_PROXY = %s\n$env:ALL_PROXY = %s\n$env:NO_PROXY = %s\n",
			powershellQuote(httpVal), powershellQuote(httpVal), powershellQuote(socksVal), powershellQuote(noProxyVal))
	}

	// POSIX shell
	if unset {
		return "unset HTTP_PROXY http_proxy\n" +
			"unset HTTPS_PROXY https_proxy\n" +
			"unset ALL_PROXY all_proxy\n" +
			"unset NO_PROXY no_proxy\n"
	}

	httpVal := posixEscape("http://" + httpListen)
	socksVal := posixEscape("socks5h://" + socksListen)
	noProxyVal := posixEscape("localhost,127.0.0.1,::1")

	return fmt.Sprintf("export HTTP_PROXY=%s http_proxy=%s\n"+
		"export HTTPS_PROXY=%s https_proxy=%s\n"+
		"export ALL_PROXY=%s all_proxy=%s\n"+
		"export NO_PROXY=%s no_proxy=%s\n",
		httpVal, httpVal,
		httpVal, httpVal,
		socksVal, socksVal,
		noProxyVal, noProxyVal)
}
