package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

// 1. isLoopbackTarget table test.
func TestIsLoopbackTarget_Table(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.1.2.3", true},
		{"::1", true},
		{"[::1]", true},
		{"::ffff:127.0.0.1", true},
		{"localhost", true},
		{"LOCALHOST.", true},
		{"app.localhost", true},
		{"localhost.example.com", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"0.0.0.0", false},
		{"example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := isLoopbackTarget(tt.host)
			if got != tt.want {
				t.Errorf("isLoopbackTarget(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// 2. CONNECT on 127.0.0.1:<port> goes directly; mockDialer is not called.
func TestLoopback_HTTPConnect_Direct(t *testing.T) {
	localEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local echo listen: %v", err)
	}
	defer localEcho.Close()
	go func() {
		for {
			conn, err := localEcho.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	var mockCalls atomic.Int32
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			mockCalls.Add(1)
			return nil, fmt.Errorf("mockDialer called for %s:%d", host, port)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial httpListener: %v", err)
	}
	defer clientConn.Close()

	targetAddr := localEcho.Addr().String()
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := clientConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status: got %d, want 200", resp.StatusCode)
	}

	msg := []byte("hello-loopback-connect\n")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("write data: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read data: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}

	if calls := mockCalls.Load(); calls != 0 {
		t.Fatalf("mockDialer was called %d times, expected 0", calls)
	}
}

// 3. Plain HTTP http://localhost:<port>/ receives response of local server; mockDialer is not called.
func TestLoopback_PlainHTTP_Direct(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local listen: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("response from local server"))
	}))
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	localPort := ts.Listener.Addr().(*net.TCPAddr).Port

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	var mockCalls atomic.Int32
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			mockCalls.Add(1)
			return nil, fmt.Errorf("mockDialer called for %s:%d", host, port)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	proxyURL, _ := url.Parse("http://" + eng.httpListener.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	reqURL := fmt.Sprintf("http://localhost:%d/test", localPort)
	resp, err := client.Get(reqURL)
	if err != nil {
		t.Fatalf("client.Get(%s): %v", reqURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if string(body) != "response from local server" {
		t.Fatalf("got body %q, want 'response from local server'", string(body))
	}

	if calls := mockCalls.Load(); calls != 0 {
		t.Fatalf("mockDialer was called %d times, expected 0", calls)
	}
}

// 4. SOCKS5: ATYP IPv4 127.0.0.1 and ATYP domain localhost go directly; mockDialer is not called.
func TestLoopback_SOCKS5_Direct(t *testing.T) {
	localEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local echo listen: %v", err)
	}
	defer localEcho.Close()
	go func() {
		for {
			conn, err := localEcho.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	localPort := uint16(localEcho.Addr().(*net.TCPAddr).Port)

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	var mockCalls atomic.Int32
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			mockCalls.Add(1)
			return nil, fmt.Errorf("mockDialer called for %s:%d", host, port)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	socksAddr := eng.socksListener.Addr().String()

	// 4a: ATYP IPv4 127.0.0.1
	t.Run("IPv4", func(t *testing.T) {
		conn, err := net.Dial("tcp", socksAddr)
		if err != nil {
			t.Fatalf("dial socks: %v", err)
		}
		defer conn.Close()

		// Greeting: VER 5, 1 method, NO AUTH (0x00)
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("read greeting resp: %v", err)
		}
		if resp[0] != 0x05 || resp[1] != 0x00 {
			t.Fatalf("greeting rejected: %x", resp)
		}

		// Connect req: VER 5, CMD 1, RSV 0, ATYP 1 (IPv4), 127.0.0.1, Port
		req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
		binary.BigEndian.PutUint16(req[8:10], localPort)
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("write connect req: %v", err)
		}

		connResp := make([]byte, 10)
		if _, err := io.ReadFull(conn, connResp); err != nil {
			t.Fatalf("read connect resp: %v", err)
		}
		if connResp[1] != 0x00 {
			t.Fatalf("SOCKS5 connect failed: status 0x%02x", connResp[1])
		}

		msg := []byte("socks-ipv4-echo\n")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write echo: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
		}
	})

	// 4b: ATYP domain "localhost"
	t.Run("Domain", func(t *testing.T) {
		conn, err := net.Dial("tcp", socksAddr)
		if err != nil {
			t.Fatalf("dial socks: %v", err)
		}
		defer conn.Close()

		// Greeting
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("read greeting resp: %v", err)
		}
		if resp[0] != 0x05 || resp[1] != 0x00 {
			t.Fatalf("greeting rejected: %x", resp)
		}

		// Connect req: VER 5, CMD 1, RSV 0, ATYP 3 (Domain), len 9, "localhost", Port
		domain := "localhost"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
		req = append(req, []byte(domain)...)
		req = append(req, 0, 0)
		binary.BigEndian.PutUint16(req[len(req)-2:], localPort)
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("write connect req: %v", err)
		}

		connResp := make([]byte, 10)
		if _, err := io.ReadFull(conn, connResp); err != nil {
			t.Fatalf("read connect resp: %v", err)
		}
		if connResp[1] != 0x00 {
			t.Fatalf("SOCKS5 connect failed: status 0x%02x", connResp[1])
		}

		msg := []byte("socks-domain-echo\n")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write echo: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
		}
	})

	if calls := mockCalls.Load(); calls != 0 {
		t.Fatalf("mockDialer was called %d times, expected 0", calls)
	}
}

// 5. Non-loopback (example.test:80) goes to mockDialer.
func TestLoopback_NonLoopback_GoesToMockDialer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	var dialedHost string
	var dialedPort int
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			dialedHost = host
			dialedPort = port
			c1, c2 := net.Pipe()
			go func() {
				defer c2.Close()
				_, _ = io.Copy(c2, c2)
			}()
			return c1, nil
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial httpListener: %v", err)
	}
	defer clientConn.Close()

	connectReq := "CONNECT example.test:80 HTTP/1.1\r\nHost: example.test:80\r\n\r\n"
	if _, err := clientConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	if dialedHost != "example.test" || dialedPort != 80 {
		t.Fatalf("mockDialer dialed %s:%d, want example.test:80", dialedHost, dialedPort)
	}
}

// 6. Closed local port: client receives error (502 / SOCKS5 0x05),
// consecutiveErrors remains 0, no disconnect event.
func TestLoopback_ClosedPort_ClientRefusal_NoFailureRecorded(t *testing.T) {
	// Allocate and immediately close a listener to get an unused closed port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return nil, fmt.Errorf("mockDialer should not be called")
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	// Drain initial EventConnected
	select {
	case evt := <-eng.Events():
		if evt.Type != EventConnected {
			t.Fatalf("expected EventConnected, got: %+v", evt)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial EventConnected")
	}

	// 6a: HTTP CONNECT to closed port -> 502 Bad Gateway
	conn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial http: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", closedPort, closedPort)
	_, _ = conn.Write([]byte(req))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway, got: %d", resp.StatusCode)
	}

	// Invariant: consecutiveErrors must remain 0
	if count := eng.consecutiveErrors.Load(); count != 0 {
		t.Fatalf("consecutiveErrors = %d, expected 0", count)
	}

	// Invariant: no disconnect event emitted
	select {
	case evt := <-eng.Events():
		t.Fatalf("unexpected engine event: %+v", evt)
	case <-time.After(100 * time.Millisecond):
	}
}

// 7. Engine without upstream (cfg.Proxy.Host == ""): loopback still works.
func TestLoopback_NoUpstreamConfigured(t *testing.T) {
	localEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local echo listen: %v", err)
	}
	defer localEcho.Close()
	go func() {
		for {
			conn, err := localEcho.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = ""
	cfg.Proxy.Port = 0

	eng, err := New(cfg, "")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if eng.dialer != nil {
		t.Fatalf("expected eng.dialer to be nil when proxy host is empty")
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial httpListener: %v", err)
	}
	defer clientConn.Close()

	targetAddr := localEcho.Addr().String()
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := clientConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status: got %d, want 200", resp.StatusCode)
	}

	msg := []byte("hello-no-upstream\n")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("write data: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read data: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}
