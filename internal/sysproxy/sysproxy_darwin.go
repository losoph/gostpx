//go:build darwin

package sysproxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Set configures macOS system proxy on the active network service.
func Set(httpAddr, socksAddr string) error {
	if path := dryFile(); path != "" {
		return drySet(path, httpAddr, socksAddr)
	}
	if err := guardRealChange(); err != nil {
		return err
	}
	httpHost, httpPort, err := parseHostPort(httpAddr)
	if err != nil {
		return fmt.Errorf("invalid httpAddr %q: %w", httpAddr, err)
	}
	socksHost, socksPort, err := parseHostPort(socksAddr)
	if err != nil {
		return fmt.Errorf("invalid socksAddr %q: %w", socksAddr, err)
	}

	service, err := ActiveService()
	if err != nil {
		return fmt.Errorf("detect active network service: %w", err)
	}

	// 1. HTTP Proxy
	if err := runNetworksetup("-setwebproxy", service, httpHost, strconv.Itoa(httpPort)); err != nil {
		return fmt.Errorf("set web proxy on %q: %w", service, err)
	}
	if err := runNetworksetup("-setwebproxystate", service, "on"); err != nil {
		return fmt.Errorf("enable web proxy on %q: %w", service, err)
	}

	// 2. HTTPS / Secure Web Proxy
	if err := runNetworksetup("-setsecurewebproxy", service, httpHost, strconv.Itoa(httpPort)); err != nil {
		return fmt.Errorf("set secure web proxy on %q: %w", service, err)
	}
	if err := runNetworksetup("-setsecurewebproxystate", service, "on"); err != nil {
		return fmt.Errorf("enable secure web proxy on %q: %w", service, err)
	}

	// 3. SOCKS Firewall Proxy
	if err := runNetworksetup("-setsocksfirewallproxy", service, socksHost, strconv.Itoa(socksPort)); err != nil {
		return fmt.Errorf("set socks proxy on %q: %w", service, err)
	}
	if err := runNetworksetup("-setsocksfirewallproxystate", service, "on"); err != nil {
		return fmt.Errorf("enable socks proxy on %q: %w", service, err)
	}

	return nil
}

// TakeSnapshot captures the current proxy configuration across network services before gostpx modifies them (ADR-015).
func TakeSnapshot() (*Snapshot, error) {
	if path := dryFile(); path != "" {
		return takeSnapshotDry(path)
	}

	services, err := ListAllNetworkServices()
	if err != nil {
		if active, errActive := ActiveService(); errActive == nil {
			services = []string{active}
		} else {
			return nil, fmt.Errorf("list network services: %w", err)
		}
	}

	snap := &Snapshot{
		DarwinServices: make(map[string]DarwinServiceSnapshot),
	}

	for _, s := range services {
		var sSnap DarwinServiceSnapshot

		webOut, err := runNetworksetupOut("-getwebproxy", s)
		if err != nil {
			return nil, fmt.Errorf("get webproxy on %q: %w", s, err)
		}
		webEnabled, webHost, webPort := parseProxyInfo(webOut)
		sSnap.WebProxy = ProxyEndpoint{Enabled: webEnabled, Host: webHost, Port: webPort}

		secOut, err := runNetworksetupOut("-getsecurewebproxy", s)
		if err != nil {
			return nil, fmt.Errorf("get securewebproxy on %q: %w", s, err)
		}
		secEnabled, secHost, secPort := parseProxyInfo(secOut)
		sSnap.SecureWebProxy = ProxyEndpoint{Enabled: secEnabled, Host: secHost, Port: secPort}

		socksOut, err := runNetworksetupOut("-getsocksfirewallproxy", s)
		if err != nil {
			return nil, fmt.Errorf("get socksfirewallproxy on %q: %w", s, err)
		}
		socksEnabled, socksHost, socksPort := parseProxyInfo(socksOut)
		sSnap.SOCKSProxy = ProxyEndpoint{Enabled: socksEnabled, Host: socksHost, Port: socksPort}

		snap.DarwinServices[s] = sSnap
	}

	return snap, nil
}

// Unset restores original system proxy settings from snapshot if current settings
// still point to our proxy (httpListen/socksListen). Each protocol (web, secureweb, socks)
// is verified independently (ADR-015).
func Unset(snap *Snapshot, httpListen, socksListen string) error {
	if path := dryFile(); path != "" {
		return dryUnset(path, snap, httpListen, socksListen)
	}
	if err := guardRealChange(); err != nil {
		return err
	}
	services, err := ListAllNetworkServices()
	if err != nil {
		services = []string{"Wi-Fi", "Ethernet"}
	}

	var allErrs []string

	for _, s := range services {
		var sSnap *DarwinServiceSnapshot
		if snap != nil && snap.DarwinServices != nil {
			if v, ok := snap.DarwinServices[s]; ok {
				sSnap = &v
			}
		}

		// 1. Web proxy
		webOut, err := runNetworksetupOut("-getwebproxy", s)
		if err != nil {
			allErrs = append(allErrs, fmt.Sprintf("get webproxy on %q: %v", s, err))
		} else {
			webEnabled, webHost, webPort := parseProxyInfo(webOut)
			if httpListen == "" || (webEnabled && matchesListenAddr(webHost, webPort, httpListen)) {
				if sSnap != nil && sSnap.WebProxy.Enabled {
					if err := runNetworksetup("-setwebproxy", s, sSnap.WebProxy.Host, strconv.Itoa(sSnap.WebProxy.Port)); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("set webproxy on %q: %v", s, err))
					} else if err := runNetworksetup("-setwebproxystate", s, "on"); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("enable webproxy on %q: %v", s, err))
					}
				} else {
					if err := runNetworksetup("-setwebproxystate", s, "off"); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("disable webproxy on %q: %v", s, err))
					}
				}
			}
		}

		// 2. Secure web proxy
		secOut, err := runNetworksetupOut("-getsecurewebproxy", s)
		if err != nil {
			allErrs = append(allErrs, fmt.Sprintf("get securewebproxy on %q: %v", s, err))
		} else {
			secEnabled, secHost, secPort := parseProxyInfo(secOut)
			if httpListen == "" || (secEnabled && matchesListenAddr(secHost, secPort, httpListen)) {
				if sSnap != nil && sSnap.SecureWebProxy.Enabled {
					if err := runNetworksetup("-setsecurewebproxy", s, sSnap.SecureWebProxy.Host, strconv.Itoa(sSnap.SecureWebProxy.Port)); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("set securewebproxy on %q: %v", s, err))
					} else if err := runNetworksetup("-setsecurewebproxystate", s, "on"); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("enable securewebproxy on %q: %v", s, err))
					}
				} else {
					if err := runNetworksetup("-setsecurewebproxystate", s, "off"); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("disable securewebproxy on %q: %v", s, err))
					}
				}
			}
		}

		// 3. SOCKS proxy
		socksOut, err := runNetworksetupOut("-getsocksfirewallproxy", s)
		if err != nil {
			allErrs = append(allErrs, fmt.Sprintf("get socksfirewallproxy on %q: %v", s, err))
		} else {
			socksEnabled, socksHost, socksPort := parseProxyInfo(socksOut)
			shouldTouchSOCKS := (httpListen == "" && socksListen == "") || (socksListen != "" && socksEnabled && matchesListenAddr(socksHost, socksPort, socksListen))
			if shouldTouchSOCKS {
				if sSnap != nil && sSnap.SOCKSProxy.Enabled {
					if err := runNetworksetup("-setsocksfirewallproxy", s, sSnap.SOCKSProxy.Host, strconv.Itoa(sSnap.SOCKSProxy.Port)); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("set socksproxy on %q: %v", s, err))
					} else if err := runNetworksetup("-setsocksfirewallproxystate", s, "on"); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("enable socksproxy on %q: %v", s, err))
					}
				} else {
					if err := runNetworksetup("-setsocksfirewallproxystate", s, "off"); err != nil {
						allErrs = append(allErrs, fmt.Sprintf("disable socksproxy on %q: %v", s, err))
					}
				}
			}
		}
	}

	if len(allErrs) > 0 {
		return errors.New(strings.Join(allErrs, "; "))
	}
	return nil
}

// Current inspects the current proxy settings on the active network service.
func Current() (*Status, error) {
	if path := dryFile(); path != "" {
		return dryCurrent(path)
	}
	service, err := ActiveService()
	if err != nil {
		return nil, fmt.Errorf("detect active network service: %w", err)
	}

	st := &Status{
		Service: service,
	}

	// Read web proxy
	webOut, err := runNetworksetupOut("-getwebproxy", service)
	if err == nil {
		enabled, host, port := parseProxyInfo(webOut)
		st.HTTPHost = host
		st.HTTPPort = port
		if enabled {
			st.Enabled = true
		}
	}

	// Read SOCKS proxy
	socksOut, err := runNetworksetupOut("-getsocksfirewallproxy", service)
	if err == nil {
		enabled, host, port := parseProxyInfo(socksOut)
		st.SOCKSHost = host
		st.SOCKSPort = port
		if enabled {
			st.Enabled = true
		}
	}

	return st, nil
}

// ActiveService finds the macOS network service associated with the default route interface.
func ActiveService() (string, error) {
	iface, err := DefaultRouteInterface()
	if err != nil {
		return "", err
	}
	return FindServiceForDevice(iface)
}

// DefaultRouteInterface queries `route -n get default` to find the default interface (e.g. en0).
func DefaultRouteInterface() (string, error) {
	cmd := exec.Command("route", "-n", "get", "default")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("route -n get default: %w", err)
	}

	return parseDefaultInterface(out)
}

func parseDefaultInterface(out []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	return "", errors.New("default interface not found in route output")
}

// FindServiceForDevice maps a device name (e.g. "en0") to a service name (e.g. "Wi-Fi").
func FindServiceForDevice(device string) (string, error) {
	cmd := exec.Command("networksetup", "-listnetworkserviceorder")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("listnetworkserviceorder: %w", err)
	}

	return parseServiceOrder(out, device)
}

var (
	serviceHeaderRegex = regexp.MustCompile(`^\(\d+\)\s+(.+)$`)
	deviceRegex        = regexp.MustCompile(`Device:\s*([a-zA-Z0-9_]+)`)
)

func parseServiceOrder(out []byte, targetDevice string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	currentService := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if m := serviceHeaderRegex.FindStringSubmatch(line); len(m) > 1 {
			currentService = strings.TrimSpace(m[1])
			// Strip leading asterisk if disabled service
			currentService = strings.TrimPrefix(currentService, "*")
			continue
		}

		if strings.Contains(line, "Device:") {
			if m := deviceRegex.FindStringSubmatch(line); len(m) > 1 {
				dev := m[1]
				if dev == targetDevice && currentService != "" {
					return currentService, nil
				}
			}
		}
	}

	return "", fmt.Errorf("service for device %q not found", targetDevice)
}

// ListAllNetworkServices returns all network services on the system.
func ListAllNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listallnetworkservices: %w", err)
	}

	var services []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "An asterisk (*)") {
			continue
		}
		// If disabled, it starts with '*'
		clean := strings.TrimPrefix(line, "*")
		services = append(services, clean)
	}
	return services, nil
}

func parseProxyInfo(out []byte) (enabled bool, host string, port int) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch strings.ToLower(k) {
		case "enabled":
			enabled = strings.EqualFold(v, "yes")
		case "server":
			host = v
		case "port":
			p, _ := strconv.Atoi(v)
			port = p
		}
	}
	return
}

func runNetworksetup(args ...string) error {
	cmd := exec.Command("networksetup", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w (output: %s)", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runNetworksetupOut(args ...string) ([]byte, error) {
	cmd := exec.Command("networksetup", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
