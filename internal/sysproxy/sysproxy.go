package sysproxy

import (
	"errors"
	"testing"
)

// errRealChangeFromTest is returned when a test binary is about to change the
// real system proxy. Tests must use the dry hook (see dry_testhook.go): on 2026-10-11 a
// test that called Session.Stop without it switched off the owner's live proxy,
// because the default listen address matched the running tray.
var errRealChangeFromTest = errors.New("sysproxy: тест пытается изменить настоящий системный прокси — нужен dry-режим теста")

// guardRealChange refuses real system changes from test binaries.
// testing.Testing is false in release builds.
func guardRealChange() error {
	if testing.Testing() {
		return errRealChangeFromTest
	}
	return nil
}

// Status contains the current system proxy status.
type Status struct {
	Enabled   bool   `json:"enabled"`
	HTTPHost  string `json:"http_host,omitempty"`
	HTTPPort  int    `json:"http_port,omitempty"`
	SOCKSHost string `json:"socks_host,omitempty"`
	SOCKSPort int    `json:"socks_port,omitempty"`
	Service   string `json:"service,omitempty"`
}

// ProxyEndpoint represents proxy configuration for a single protocol on macOS.
type ProxyEndpoint struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
}

// DarwinServiceSnapshot captures proxy settings for one macOS network service.
type DarwinServiceSnapshot struct {
	WebProxy       ProxyEndpoint `json:"web_proxy"`
	SecureWebProxy ProxyEndpoint `json:"secure_web_proxy"`
	SOCKSProxy     ProxyEndpoint `json:"socks_proxy"`
}

// WindowsSnapshot captures WinINET proxy settings from registry.
type WindowsSnapshot struct {
	ProxyEnable   uint32 `json:"proxy_enable"`
	ProxyServer   string `json:"proxy_server,omitempty"`
	ProxyOverride string `json:"proxy_override,omitempty"`
}

// Snapshot captures the system proxy configuration before gostpx modified it (ADR-015).
type Snapshot struct {
	DarwinServices map[string]DarwinServiceSnapshot `json:"darwin_services,omitempty"`
	Windows        *WindowsSnapshot                 `json:"windows,omitempty"`
	Dry            *Status                          `json:"dry,omitempty"`
}

// SanitizeSnapshot marks any proxy entries in snap that match any of the given listen addresses
// as disabled (Enabled = false), treating them as if no proxy was configured.
func SanitizeSnapshot(snap *Snapshot, listenAddrs ...string) {
	if snap == nil {
		return
	}
	matchesAny := func(host string, port int) bool {
		for _, addr := range listenAddrs {
			if addr != "" && matchesListenAddr(host, port, addr) {
				return true
			}
		}
		return false
	}

	if snap.Dry != nil && snap.Dry.Enabled {
		touchHTTP := matchesAny(snap.Dry.HTTPHost, snap.Dry.HTTPPort)
		touchSOCKS := matchesAny(snap.Dry.SOCKSHost, snap.Dry.SOCKSPort)
		if touchHTTP {
			snap.Dry.HTTPHost = ""
			snap.Dry.HTTPPort = 0
		}
		if touchSOCKS {
			snap.Dry.SOCKSHost = ""
			snap.Dry.SOCKSPort = 0
		}
		if touchHTTP || touchSOCKS {
			snap.Dry.Enabled = (snap.Dry.HTTPHost != "" && snap.Dry.HTTPPort != 0) ||
				(snap.Dry.SOCKSHost != "" && snap.Dry.SOCKSPort != 0)
		}
	}

	if snap.DarwinServices != nil {
		for name, svc := range snap.DarwinServices {
			changed := false
			if svc.WebProxy.Enabled && matchesAny(svc.WebProxy.Host, svc.WebProxy.Port) {
				svc.WebProxy.Enabled = false
				svc.WebProxy.Host = ""
				svc.WebProxy.Port = 0
				changed = true
			}
			if svc.SecureWebProxy.Enabled && matchesAny(svc.SecureWebProxy.Host, svc.SecureWebProxy.Port) {
				svc.SecureWebProxy.Enabled = false
				svc.SecureWebProxy.Host = ""
				svc.SecureWebProxy.Port = 0
				changed = true
			}
			if svc.SOCKSProxy.Enabled && matchesAny(svc.SOCKSProxy.Host, svc.SOCKSProxy.Port) {
				svc.SOCKSProxy.Enabled = false
				svc.SOCKSProxy.Host = ""
				svc.SOCKSProxy.Port = 0
				changed = true
			}
			if changed {
				snap.DarwinServices[name] = svc
			}
		}
	}

	if snap.Windows != nil {
		if snap.Windows.ProxyEnable != 0 {
			if host, port, ok := parseProxyServer(snap.Windows.ProxyServer); ok {
				if matchesAny(host, port) {
					snap.Windows.ProxyEnable = 0
					snap.Windows.ProxyServer = ""
				}
			}
		}
	}
}
