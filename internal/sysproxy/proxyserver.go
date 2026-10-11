package sysproxy

import "strings"

// parseProxyServer extracts the HTTP proxy address from a WinINET ProxyServer
// value. The value is either a single "host:port" used for all protocols, or
// a per-protocol list such as "http=host:port;https=host:port;socks=host:port".
func parseProxyServer(v string) (host string, port int, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", 0, false
	}
	if !strings.Contains(v, "=") {
		h, p, err := parseHostPort(v)
		return h, p, err == nil
	}
	for _, part := range strings.Split(v, ";") {
		scheme, addr, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || !strings.EqualFold(scheme, "http") {
			continue
		}
		h, p, err := parseHostPort(strings.TrimSpace(addr))
		return h, p, err == nil
	}
	return "", 0, false
}
