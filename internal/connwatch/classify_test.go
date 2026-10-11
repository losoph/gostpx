package connwatch

import (
	"net/netip"
	"testing"
)

func TestClassifyTable(t *testing.T) {
	proxyIP := netip.MustParseAddr("203.0.113.10")
	gostpxPID := 4242
	listenerAddr := netip.MustParseAddrPort("127.0.0.1:8080")

	ignore := Ignore{
		Listeners: []netip.AddrPort{listenerAddr},
		ProxyIPs:  []netip.Addr{proxyIP},
		SelfPID:   gostpxPID,
	}

	tests := []struct {
		name       string
		conn       Conn
		wantBypass bool
	}{
		// 1. Loopback
		{
			name: "IPv4 loopback 127.0.0.1",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("127.0.0.1:50000"),
				Remote:  netip.MustParseAddrPort("127.0.0.1:1234"),
			},
			wantBypass: false,
		},
		{
			name: "IPv6 loopback ::1",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("[::1]:50000"),
				Remote:  netip.MustParseAddrPort("[::1]:1234"),
			},
			wantBypass: false,
		},

		// 2. Unspecified
		{
			name: "IPv4 unspecified 0.0.0.0",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("127.0.0.1:50000"),
				Remote:  netip.MustParseAddrPort("0.0.0.0:80"),
			},
			wantBypass: false,
		},
		{
			name: "IPv6 unspecified ::",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("[::1]:50000"),
				Remote:  netip.MustParseAddrPort("[::]:80"),
			},
			wantBypass: false,
		},

		// 3. Private networks
		{
			name: "Private 10/8",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("10.0.0.2:50000"),
				Remote:  netip.MustParseAddrPort("10.1.2.3:80"),
			},
			wantBypass: false,
		},
		{
			name: "Private 172.16/12",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("172.16.0.2:50000"),
				Remote:  netip.MustParseAddrPort("172.20.5.6:443"),
			},
			wantBypass: false,
		},
		{
			name: "Private 192.168/16",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("192.168.1.100:50000"),
				Remote:  netip.MustParseAddrPort("192.168.1.1:80"),
			},
			wantBypass: false,
		},

		// 4. CGNAT 100.64/10
		{
			name: "CGNAT 100.64/10",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("100.64.0.5:50000"),
				Remote:  netip.MustParseAddrPort("100.65.1.1:443"),
			},
			wantBypass: false,
		},

		// 5. Link-local 169.254/16 and fe80::/10
		{
			name: "IPv4 Link-local 169.254/16",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("169.254.1.2:50000"),
				Remote:  netip.MustParseAddrPort("169.254.1.1:80"),
			},
			wantBypass: false,
		},
		{
			name: "IPv6 Link-local fe80::/10",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("[fe80::1]:50000"),
				Remote:  netip.MustParseAddrPort("[fe80::2]:80"),
			},
			wantBypass: false,
		},

		// 6. IPv6 ULA fc00::/7
		{
			name: "IPv6 ULA fc00::/7",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("[fd00::1]:50000"),
				Remote:  netip.MustParseAddrPort("[fd12:3456::1]:443"),
			},
			wantBypass: false,
		},

		// 7. Multicast
		{
			name: "IPv4 Multicast 224.0.0.1",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("192.168.1.5:50000"),
				Remote:  netip.MustParseAddrPort("224.0.0.1:80"),
			},
			wantBypass: false,
		},
		{
			name: "IPv6 Multicast ff02::1",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("[fe80::1]:50000"),
				Remote:  netip.MustParseAddrPort("[ff02::1]:80"),
			},
			wantBypass: false,
		},

		// 8. Proxy server IP (different port should also be ignored)
		{
			name: "Proxy server IP on different port 443",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("192.168.1.5:50000"),
				Remote:  netip.MustParseAddrPort("203.0.113.10:443"),
			},
			wantBypass: false,
		},
		{
			name: "Proxy server IP on standard proxy port 8080",
			conn: Conn{
				PID:     100,
				Process: "testproc",
				Local:   netip.MustParseAddrPort("192.168.1.5:50000"),
				Remote:  netip.MustParseAddrPort("203.0.113.10:8080"),
			},
			wantBypass: false,
		},

		// 9. gostpx PID itself
		{
			name: "gostpx PID connecting to public IP",
			conn: Conn{
				PID:     gostpxPID,
				Process: "gostpx",
				Local:   netip.MustParseAddrPort("192.168.1.5:50000"),
				Remote:  netip.MustParseAddrPort("1.1.1.1:443"),
			},
			wantBypass: false,
		},

		// 10. Connections to listeners
		{
			name: "Client connected to gostpx listener",
			conn: Conn{
				PID:     200,
				Process: "browser",
				Local:   netip.MustParseAddrPort("127.0.0.1:51234"),
				Remote:  listenerAddr,
			},
			wantBypass: false,
		},
		{
			name: "Listener socket local endpoint matching listener",
			conn: Conn{
				PID:     300,
				Process: "other",
				Local:   listenerAddr,
				Remote:  netip.MustParseAddrPort("127.0.0.1:51234"),
			},
			wantBypass: false,
		},

		// 11. Public IPv4 — must be in report
		{
			name: "Public IPv4 bypass",
			conn: Conn{
				PID:     500,
				Process: "curl",
				Local:   netip.MustParseAddrPort("192.168.1.5:50000"),
				Remote:  netip.MustParseAddrPort("93.184.216.34:80"),
			},
			wantBypass: true,
		},

		// 12. Public IPv6 — must be in report
		{
			name: "Public IPv6 bypass",
			conn: Conn{
				PID:     600,
				Process: "chrome",
				Local:   netip.MustParseAddrPort("[2001:db8::5]:50000"),
				Remote:  netip.MustParseAddrPort("[2606:2800:220:1:248:1893:25c8:1946]:443"),
			},
			wantBypass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := Classify([]Conn{tt.conn}, ignore)
			if report.Checked != 1 {
				t.Errorf("expected Checked=1, got %d", report.Checked)
			}
			isBypassed := len(report.Bypass) > 0
			if isBypassed != tt.wantBypass {
				t.Errorf("wantBypass=%v, got=%v (report: %+v)", tt.wantBypass, isBypassed, report)
			}
		})
	}
}

func TestClassifyGroupingAndLimits(t *testing.T) {
	ignore := Ignore{
		SelfPID: 9999,
	}

	conns := []Conn{
		// Process "curl" with 4 connections to distinct public IPs and 2 PIDs
		{PID: 101, Process: "curl", Local: netip.MustParseAddrPort("192.168.1.2:1001"), Remote: netip.MustParseAddrPort("1.1.1.1:80")},
		{PID: 101, Process: "curl", Local: netip.MustParseAddrPort("192.168.1.2:1002"), Remote: netip.MustParseAddrPort("1.0.0.1:80")},
		{PID: 102, Process: "curl", Local: netip.MustParseAddrPort("192.168.1.2:1003"), Remote: netip.MustParseAddrPort("8.8.8.8:53")},
		{PID: 102, Process: "curl", Local: netip.MustParseAddrPort("192.168.1.2:1004"), Remote: netip.MustParseAddrPort("8.8.4.4:53")},

		// Process "git" with 1 connection
		{PID: 201, Process: "git", Local: netip.MustParseAddrPort("192.168.1.2:1005"), Remote: netip.MustParseAddrPort("140.82.121.4:443")},

		// Loopback (excluded)
		{PID: 301, Process: "daemon", Local: netip.MustParseAddrPort("127.0.0.1:1006"), Remote: netip.MustParseAddrPort("127.0.0.1:8080")},
	}

	report := Classify(conns, ignore)

	if report.Checked != len(conns) {
		t.Fatalf("expected Checked=%d, got %d", len(conns), report.Checked)
	}

	if len(report.Bypass) != 2 {
		t.Fatalf("expected 2 bypass groups, got %d", len(report.Bypass))
	}

	// curl should be first because it has count 4 > git count 1
	curlGroup := report.Bypass[0]
	if curlGroup.Process != "curl" {
		t.Errorf("expected first group to be 'curl', got %q", curlGroup.Process)
	}
	if curlGroup.Count != 4 {
		t.Errorf("expected curl Count=4, got %d", curlGroup.Count)
	}
	if len(curlGroup.PIDs) != 2 || curlGroup.PIDs[0] != 101 || curlGroup.PIDs[1] != 102 {
		t.Errorf("expected curl PIDs [101, 102], got %v", curlGroup.PIDs)
	}
	if len(curlGroup.Samples) > 3 {
		t.Errorf("expected <= 3 samples, got %d", len(curlGroup.Samples))
	}
	if len(curlGroup.Samples) != 3 {
		t.Errorf("expected exactly 3 samples (capped from 4), got %d", len(curlGroup.Samples))
	}

	gitGroup := report.Bypass[1]
	if gitGroup.Process != "git" {
		t.Errorf("expected second group to be 'git', got %q", gitGroup.Process)
	}
	if gitGroup.Count != 1 {
		t.Errorf("expected git Count=1, got %d", gitGroup.Count)
	}
	if len(gitGroup.Samples) != 1 {
		t.Errorf("expected 1 sample for git, got %d", len(gitGroup.Samples))
	}
}
