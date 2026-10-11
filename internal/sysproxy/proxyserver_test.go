package sysproxy

import "testing"

func TestParseProxyServer(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
		wantOK   bool
	}{
		{"127.0.0.1:8080", "127.0.0.1", 8080, true},
		{" 127.0.0.1:8080 ", "127.0.0.1", 8080, true},
		{"http=127.0.0.1:8080;https=127.0.0.1:8443", "127.0.0.1", 8080, true},
		{"HTTP=proxy.example:3128;socks=127.0.0.1:1080", "proxy.example", 3128, true},
		{"https=127.0.0.1:8443;socks=127.0.0.1:1080", "", 0, false},
		{"", "", 0, false},
		{"127.0.0.1", "", 0, false},
		{"127.0.0.1:0", "", 0, false},
	}
	for _, tt := range tests {
		host, port, ok := parseProxyServer(tt.in)
		if host != tt.wantHost || port != tt.wantPort || ok != tt.wantOK {
			t.Errorf("parseProxyServer(%q) = (%q, %d, %v), want (%q, %d, %v)",
				tt.in, host, port, ok, tt.wantHost, tt.wantPort, tt.wantOK)
		}
	}
}
