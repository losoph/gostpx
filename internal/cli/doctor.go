package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/connwatch"
	"github.com/losoph/gostpx/internal/session"
	"github.com/losoph/gostpx/internal/state"
	"github.com/spf13/cobra"
)

var (
	doctorConnections bool
	doctorJSON        bool

	// connwatchTake is a function variable to allow substituting Take in unit tests.
	connwatchTake = connwatch.Take
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Диагностика и проверка соединений мимо прокси",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !doctorConnections {
			cmd.Println("Используйте: gostpx doctor --connections [--json]")
			return nil
		}
		return runDoctorConnections(cmd)
	},
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorConnections, "connections", false, "проверить соединения процессов мимо прокси")
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "вывод в формате JSON")
}

func runDoctorConnections(cmd *cobra.Command) error {
	statePath, err := state.DefaultStatePath()
	if err != nil {
		return newCLIError(ExitGeneralError, err)
	}

	st, _ := state.Load(statePath)
	active := st != nil && st.ActiveSession && st.PID > 0 && session.IsPIDAlive(st.PID)

	if !active {
		if doctorJSON {
			out := map[string]any{
				"active":  false,
				"message": "сессия gostpx не активна (весь трафик идёт напрямую)",
			}
			data, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return err
			}
			cmd.Println(string(data))
			return nil
		}
		cmd.Println("Сессия gostpx не активна (весь трафик идёт напрямую).")
		return nil
	}

	configPath, err := config.DefaultConfigPath()
	if err != nil {
		return newCLIError(ExitGeneralError, err)
	}
	cfg, _, _ := config.Load(configPath)
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	ignore := connwatch.Ignore{
		SelfPID: os.Getpid(),
	}
	if st != nil && st.PID > 0 {
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
			resolveCtx, cancel := context.WithTimeout(cmd.Context(), 2*time.Second)
			ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", cfg.Proxy.Host)
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

	conns, err := connwatchTake(cmd.Context())
	if err != nil {
		return newCLIError(ExitGeneralError, fmt.Errorf("ошибка получения соединений: %w", err))
	}

	report := connwatch.Classify(conns, ignore)

	if doctorJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		cmd.Println(string(data))
		return nil
	}

	cmd.Printf("Соединения мимо прокси на %s (эвристика: соединение мимо слушателей gostpx и не в локальную сеть):\n", report.Taken.Format("15:04:05"))

	if len(report.Bypass) == 0 {
		cmd.Println("мимо прокси соединений не видно")
		return nil
	}

	for _, g := range report.Bypass {
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
			cmd.Printf("%s (PID %s): %d %s, напр. %s\n", g.Process, pidStr, g.Count, connwatch.ConnectionsWord(g.Count), strings.Join(sampleStrs, ", "))
		} else {
			cmd.Printf("%s (PID %s): %d %s\n", g.Process, pidStr, g.Count, connwatch.ConnectionsWord(g.Count))
		}
	}

	return nil
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
