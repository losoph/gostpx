package sysproxy

import (
	"fmt"
	"net"
	"strconv"
)

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

func matchesListenAddr(host string, port int, listenAddr string) bool {
	if listenAddr == "" {
		return false
	}
	listenHost, listenPort, err := parseHostPort(listenAddr)
	if err != nil {
		return false
	}
	if port != listenPort {
		return false
	}
	if host == listenHost {
		return true
	}
	if (listenHost == "0.0.0.0" || listenHost == "127.0.0.1") && (host == "127.0.0.1" || host == "localhost") {
		return true
	}
	if listenHost == "localhost" && (host == "127.0.0.1" || host == "localhost") {
		return true
	}
	return false
}

// MatchesListenAddr checks if a host:port matches the configured listen address.
func MatchesListenAddr(host string, port int, listenAddr string) bool {
	return matchesListenAddr(host, port, listenAddr)
}
