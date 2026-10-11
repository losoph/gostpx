package connwatch

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseLsof(t *testing.T) {
	// Sample lsof -F pcn output including IPv4, IPv6 with brackets,
	// multiple file descriptors under one process, and lines without '->'.
	sample := `p512
ctrustd
f24
n127.0.0.1:49744->127.0.0.1:8080
p522
cidentityservicesd
f47
n[fe80:12::f546:ce31:a151:8345]:1024->[fe80:12::f3ca:46b4:7761:263d]:1024
f57
n[2001:db8::1]:443->[2001:db8::2]:80
f60
n*:80
f61
n127.0.0.1:1000
p1234
ccurl
f3
n192.168.1.50:54321->93.184.216.34:80
`

	conns, err := ParseLsof(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Total valid connections with '->':
	// 1. trustd: 127.0.0.1:49744->127.0.0.1:8080
	// 2. identityservicesd: [fe80:12::f546:ce31:a151:8345]:1024->[fe80:12::f3ca:46b4:7761:263d]:1024
	// 3. identityservicesd: [2001:db8::1]:443->[2001:db8::2]:80
	// (n*:80 skipped: no ->)
	// (n127.0.0.1:1000 skipped: no ->)
	// 4. curl: 192.168.1.50:54321->93.184.216.34:80
	if len(conns) != 4 {
		t.Fatalf("expected 4 connections, got %d", len(conns))
	}

	// 1. trustd
	if conns[0].PID != 512 || conns[0].Process != "trustd" {
		t.Errorf("conn[0] mismatch: PID=%d, Proc=%s", conns[0].PID, conns[0].Process)
	}
	if conns[0].Local != netip.MustParseAddrPort("127.0.0.1:49744") || conns[0].Remote != netip.MustParseAddrPort("127.0.0.1:8080") {
		t.Errorf("conn[0] endpoints mismatch: Local=%v, Remote=%v", conns[0].Local, conns[0].Remote)
	}

	// 2. identityservicesd link-local IPv6
	if conns[1].PID != 522 || conns[1].Process != "identityservicesd" {
		t.Errorf("conn[1] mismatch: PID=%d, Proc=%s", conns[1].PID, conns[1].Process)
	}
	if conns[1].Local != netip.MustParseAddrPort("[fe80:12::f546:ce31:a151:8345]:1024") ||
		conns[1].Remote != netip.MustParseAddrPort("[fe80:12::f3ca:46b4:7761:263d]:1024") {
		t.Errorf("conn[1] endpoints mismatch: Local=%v, Remote=%v", conns[1].Local, conns[1].Remote)
	}

	// 3. identityservicesd public IPv6
	if conns[2].PID != 522 || conns[2].Process != "identityservicesd" {
		t.Errorf("conn[2] mismatch: PID=%d, Proc=%s", conns[2].PID, conns[2].Process)
	}
	if conns[2].Local != netip.MustParseAddrPort("[2001:db8::1]:443") ||
		conns[2].Remote != netip.MustParseAddrPort("[2001:db8::2]:80") {
		t.Errorf("conn[2] endpoints mismatch: Local=%v, Remote=%v", conns[2].Local, conns[2].Remote)
	}

	// 4. curl
	if conns[3].PID != 1234 || conns[3].Process != "curl" {
		t.Errorf("conn[3] mismatch: PID=%d, Proc=%s", conns[3].PID, conns[3].Process)
	}
	if conns[3].Local != netip.MustParseAddrPort("192.168.1.50:54321") ||
		conns[3].Remote != netip.MustParseAddrPort("93.184.216.34:80") {
		t.Errorf("conn[3] endpoints mismatch: Local=%v, Remote=%v", conns[3].Local, conns[3].Remote)
	}
}
