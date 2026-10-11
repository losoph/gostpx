//go:build darwin

package sysproxy

import (
	"testing"
)

func TestParseDefaultInterface(t *testing.T) {
	routeOutput := []byte(`
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`)
	iface, err := parseDefaultInterface(routeOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if iface != "en0" {
		t.Errorf("got %q, want \"en0\"", iface)
	}
}

func TestParseServiceOrder(t *testing.T) {
	orderOutput := []byte(`
An asterisk (*) denotes that a network service is disabled.
(1) iPhone USB
(Hardware Port: iPhone USB, Device: en7)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(3) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)
`)
	service, err := parseServiceOrder(orderOutput, "en0")
	if err != nil {
		t.Fatalf("unexpected error for en0: %v", err)
	}
	if service != "Wi-Fi" {
		t.Errorf("got %q, want \"Wi-Fi\"", service)
	}

	service, err = parseServiceOrder(orderOutput, "en7")
	if err != nil {
		t.Fatalf("unexpected error for en7: %v", err)
	}
	if service != "iPhone USB" {
		t.Errorf("got %q, want \"iPhone USB\"", service)
	}

	_, err = parseServiceOrder(orderOutput, "en99")
	if err == nil {
		t.Error("expected error for non-existent device en99, got nil")
	}
}

func TestParseProxyInfo(t *testing.T) {
	sample := []byte(`
Enabled: Yes
Server: 127.0.0.1
Port: 8080
Authenticated Proxy Enabled: 0
`)
	enabled, host, port := parseProxyInfo(sample)
	if !enabled || host != "127.0.0.1" || port != 8080 {
		t.Errorf("parseProxyInfo mismatch: enabled=%v, host=%s, port=%d", enabled, host, port)
	}

	sampleDisabled := []byte(`
Enabled: No
Server:
Port: 0
`)
	enabled, host, port = parseProxyInfo(sampleDisabled)
	if enabled || host != "" || port != 0 {
		t.Errorf("parseProxyInfo disabled mismatch: enabled=%v, host=%s, port=%d", enabled, host, port)
	}
}

func TestParseHostPort(t *testing.T) {
	host, port, err := parseHostPort("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "127.0.0.1" || port != 8080 {
		t.Errorf("got %s:%d, want 127.0.0.1:8080", host, port)
	}

	_, _, err = parseHostPort("invalid")
	if err == nil {
		t.Error("expected error for invalid host:port, got nil")
	}
}
