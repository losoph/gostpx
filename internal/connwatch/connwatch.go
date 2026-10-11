package connwatch

import (
	"net/netip"
	"sort"
	"time"
)

// Conn represents an established network connection.
type Conn struct {
	PID     int            `json:"pid"`
	Process string         `json:"process"`
	Local   netip.AddrPort `json:"local"`
	Remote  netip.AddrPort `json:"remote"`
}

// ProcessGroup groups bypass connections by process name.
type ProcessGroup struct {
	Process string           `json:"process"`
	PIDs    []int            `json:"pids"`
	Count   int              `json:"count"`
	Samples []netip.AddrPort `json:"samples"`
}

// Report holds the result of a bypass classification check.
type Report struct {
	Taken   time.Time      `json:"taken"`
	Bypass  []ProcessGroup `json:"bypass"`
	Checked int            `json:"checked"`
}

// Ignore specifies targets, listeners, and processes excluded from bypass reporting.
type Ignore struct {
	Listeners []netip.AddrPort
	ProxyIPs  []netip.Addr
	SelfPID   int
}

var (
	prefix10   = netip.MustParsePrefix("10.0.0.0/8")
	prefix172  = netip.MustParsePrefix("172.16.0.0/12")
	prefix192  = netip.MustParsePrefix("192.168.0.0/16")
	prefix100  = netip.MustParsePrefix("100.64.0.0/10")
	prefix169  = netip.MustParsePrefix("169.254.0.0/16")
	prefixFC00 = netip.MustParsePrefix("fc00::/7")
	prefixFE80 = netip.MustParsePrefix("fe80::/10")
)

// Classify is a pure function that analyzes conns against ignore criteria
// and produces a Report of connections bypassing the proxy.
func Classify(conns []Conn, ignore Ignore) Report {
	rep := Report{
		Taken:   time.Now(),
		Bypass:  make([]ProcessGroup, 0),
		Checked: len(conns),
	}

	type groupData struct {
		pids    map[int]struct{}
		count   int
		samples []netip.AddrPort
	}

	groups := make(map[string]*groupData)

	for _, conn := range conns {
		if ignore.SelfPID > 0 && conn.PID == ignore.SelfPID {
			continue
		}
		if isListener(conn, ignore.Listeners) {
			continue
		}
		if !isBypass(conn.Remote.Addr(), ignore.ProxyIPs) {
			continue
		}

		g, ok := groups[conn.Process]
		if !ok {
			g = &groupData{
				pids: make(map[int]struct{}),
			}
			groups[conn.Process] = g
		}

		g.count++
		g.pids[conn.PID] = struct{}{}

		// Add sample if not already present and <= 3 samples
		hasSample := false
		for _, s := range g.samples {
			if s == conn.Remote {
				hasSample = true
				break
			}
		}
		if !hasSample && len(g.samples) < 3 {
			g.samples = append(g.samples, conn.Remote)
		}
	}

	result := make([]ProcessGroup, 0, len(groups))
	for procName, g := range groups {
		pids := make([]int, 0, len(g.pids))
		for pid := range g.pids {
			pids = append(pids, pid)
		}
		sort.Ints(pids)

		result = append(result, ProcessGroup{
			Process: procName,
			PIDs:    pids,
			Count:   g.count,
			Samples: g.samples,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Process < result[j].Process
	})

	rep.Bypass = result
	return rep
}

func isListener(conn Conn, listeners []netip.AddrPort) bool {
	remoteAddr := conn.Remote.Addr().Unmap()
	localAddr := conn.Local.Addr().Unmap()

	for _, l := range listeners {
		lAddr := l.Addr().Unmap()
		if (lAddr.IsUnspecified() || lAddr == remoteAddr) && l.Port() == conn.Remote.Port() {
			return true
		}
		if (lAddr.IsUnspecified() || lAddr == localAddr) && l.Port() == conn.Local.Port() {
			return true
		}
	}
	return false
}

func isBypass(addr netip.Addr, proxyIPs []netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	if prefix10.Contains(addr) ||
		prefix172.Contains(addr) ||
		prefix192.Contains(addr) ||
		prefix100.Contains(addr) ||
		prefix169.Contains(addr) ||
		prefixFC00.Contains(addr) ||
		prefixFE80.Contains(addr) {
		return false
	}

	for _, pIP := range proxyIPs {
		if pIP.Unmap() == addr {
			return false
		}
	}

	return true
}

// ConnectionsWord returns the Russian plural form for n connections:
// 1 соединение, 2–4 соединения, 5–20 соединений, 21 соединение, …
func ConnectionsWord(n int) string {
	if n < 0 {
		n = -n
	}
	switch {
	case n%100 >= 11 && n%100 <= 14:
		return "соединений"
	case n%10 == 1:
		return "соединение"
	case n%10 >= 2 && n%10 <= 4:
		return "соединения"
	default:
		return "соединений"
	}
}
