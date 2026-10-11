package engine

import (
	"net"
	"sync"
)

var (
	globalLocalNetworkDownMu sync.RWMutex
	globalLocalNetworkDownFn func(lastErr error) bool
)

// hasUpIPv4Interface returns true if at least one non-loopback network interface
// has FlagUp and has an assigned IPv4 address.
func hasUpIPv4Interface() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp == 0) || (iface.Flags&net.FlagLoopback != 0) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
					return true
				}
			}
		}
	}
	return false
}

// localNetworkDown determines if the failure is caused by a local network outage.
// Returns true if:
// 1. lastErr matches network down errors (ENETUNREACH, EHOSTUNREACH, ENETDOWN / WSA*),
// 2. OR no non-loopback up network interface with IPv4,
// 3. OR no default route exists in OS routing table.
// Note: i/o timeout alone is NOT considered a sign of network down.
func localNetworkDown(lastErr error) bool {
	if isNetworkDownError(lastErr) {
		return true
	}
	if !hasUpIPv4Interface() {
		return true
	}
	if !hasDefaultRoute() {
		return true
	}
	return false
}
