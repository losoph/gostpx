package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

// mockDialer implements TargetDialer interface for testing.
type mockDialer struct {
	dialTargetFunc func(ctx context.Context, host string, port int) (net.Conn, error)
	closeFunc      func() error
}

func (m *mockDialer) DialTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	if m.dialTargetFunc != nil {
		return m.dialTargetFunc(ctx, host, port)
	}
	return nil, fmt.Errorf("mockDialer dial error")
}

func (m *mockDialer) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestEngineLifecycle(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng, err := New(cfg, "testpass")
	if err != nil {
		t.Fatalf("unexpected New error: %v", err)
	}

	st := eng.Status()
	if st.Connected {
		t.Errorf("expected engine to start disconnected")
	}

	ch := eng.Events()
	if ch == nil {
		t.Errorf("expected non-nil events channel")
	}
}

func TestHTTPConnectIngress(t *testing.T) {
	// Start a mock target echo server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target echo server: %v", err)
	}
	defer targetListener.Close()

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}(conn)
		}
	}()

	targetAddr := targetListener.Addr().String()

	// Setup engine with mock outbound that dials target directly
	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = targetListener.Addr().(*net.TCPAddr).Port

	eng, err := New(cfg, "pass")
	if err != nil {
		t.Fatalf("unexpected New error: %v", err)
	}

	// Substitute outbound with mock that connects to targetListener
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", targetAddr)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	httpAddr := eng.httpListener.Addr().String()

	// Client sends CONNECT request to engine
	clientConn, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatalf("client dial http proxy failed: %v", err)
	}
	defer clientConn.Close()

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT failed: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", resp.StatusCode)
	}

	// Now send data through tunnel and expect echo
	testPayload := []byte("hello through http connect\n")
	if _, err := clientConn.Write(testPayload); err != nil {
		t.Fatalf("write payload failed: %v", err)
	}

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read echo payload failed: %v", err)
	}
	if string(buf) != string(testPayload) {
		t.Errorf("got %q, want %q", string(buf), string(testPayload))
	}
}

func TestSOCKS5Ingress(t *testing.T) {
	// Start target echo server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target echo server: %v", err)
	}
	defer targetListener.Close()

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	targetAddr := targetListener.Addr().String()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = targetListener.Addr().(*net.TCPAddr).Port

	eng, err := New(cfg, "pass")
	if err != nil {
		t.Fatalf("unexpected New error: %v", err)
	}

	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", targetAddr)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	socksAddr := eng.socksListener.Addr().String()

	clientConn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("client dial socks5 proxy failed: %v", err)
	}
	defer clientConn.Close()

	// 1. Send SOCKS5 greeting: VER 5, NMETHODS 1, METHOD 0 (No Auth)
	if _, err := clientConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting failed: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read greeting reply failed: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("unexpected greeting reply: %v", reply)
	}

	// 2. Send SOCKS5 CONNECT to 127.0.0.1:<targetPort>
	port := targetListener.Addr().(*net.TCPAddr).Port
	req := []byte{
		0x05, 0x01, 0x00, 0x01, // VER 5, CMD 1, RSV 0, ATYP 1 (IPv4)
		127, 0, 0, 1, // 127.0.0.1
		byte(port >> 8), byte(port & 0xFF), // Port
	}
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("write CONNECT request failed: %v", err)
	}

	connReply := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, connReply); err != nil {
		t.Fatalf("read CONNECT reply failed: %v", err)
	}
	if connReply[0] != 0x05 || connReply[1] != 0x00 {
		t.Fatalf("unexpected CONNECT reply: %v", connReply)
	}

	// 3. Test data echo
	testPayload := []byte("socks5 test message\n")
	if _, err := clientConn.Write(testPayload); err != nil {
		t.Fatalf("write payload failed: %v", err)
	}

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read echo failed: %v", err)
	}
	if string(buf) != string(testPayload) {
		t.Errorf("got %q, want %q", string(buf), string(testPayload))
	}
}

func TestEngineRestart(t *testing.T) {
	// Point 3: Engine survives restart (Stop -> Start -> Stop)
	probeL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen error: %v", err)
	}
	defer probeL.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = probeL.Addr().(*net.TCPAddr).Port

	eng, err := New(cfg, "pass")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	eng.dialer = &mockDialer{}

	// First cycle
	if err := eng.Start(); err != nil {
		t.Fatalf("first Start error: %v", err)
	}
	if !eng.Status().Connected {
		t.Error("expected connected after first Start")
	}
	if err := eng.Stop(); err != nil {
		t.Fatalf("first Stop error: %v", err)
	}
	if eng.Status().Connected {
		t.Error("expected disconnected after first Stop")
	}

	// Second cycle
	if err := eng.Start(); err != nil {
		t.Fatalf("second Start error: %v", err)
	}
	if !eng.Status().Connected {
		t.Error("expected connected after second Start")
	}
	if err := eng.Stop(); err != nil {
		t.Fatalf("second Stop error: %v", err)
	}
	if eng.Status().Connected {
		t.Error("expected disconnected after second Stop")
	}
}

func TestSingleDialFailureDoesNotDisconnect(t *testing.T) {
	// Point 2: Single failed target dial returns 502 but keeps engine connected
	probeL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen error: %v", err)
	}
	defer probeL.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = probeL.Addr().(*net.TCPAddr).Port

	eng, err := New(cfg, "pass")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return nil, fmt.Errorf("simulated host unreachable")
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial client error: %v", err)
	}
	defer clientConn.Close()

	req := "CONNECT 127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n"
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT error: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response error: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway, got: %d", resp.StatusCode)
	}

	// Status must still be connected!
	if !eng.Status().Connected {
		t.Error("single target failure incorrectly set engine to disconnected")
	}
}

func TestSOCKS5AuthMethodNegotiation(t *testing.T) {
	// Point 11: Reject negotiation if 0x00 (No Auth) is not offered
	probeL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen error: %v", err)
	}
	defer probeL.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = probeL.Addr().(*net.TCPAddr).Port

	eng, err := New(cfg, "pass")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	eng.dialer = &mockDialer{}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.socksListener.Addr().String())
	if err != nil {
		t.Fatalf("dial client error: %v", err)
	}
	defer clientConn.Close()

	// Send VER 5, NMETHODS 1, METHOD 0x02 (User/Pass only)
	if _, err := clientConn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write greeting error: %v", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read reply error: %v", err)
	}
	// Expected: VER 5, METHOD 0xFF (No acceptable methods)
	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Errorf("expected [0x05, 0xFF], got: %v", reply)
	}
}

func TestHopByHopHeadersStripped(t *testing.T) {
	// Point 12: Verify hop-by-hop headers are removed in plain HTTP forward
	var receivedHeaders http.Header
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer targetServer.Close()

	go func() {
		for {
			conn, err := targetServer.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err == nil {
					receivedHeaders = req.Header.Clone()
					resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
					_, _ = c.Write([]byte(resp))
				}
			}(conn)
		}
	}()

	targetAddr := targetServer.Addr().String()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = targetServer.Addr().(*net.TCPAddr).Port

	eng, err := New(cfg, "pass")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", targetAddr)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial client error: %v", err)
	}
	defer clientConn.Close()

	reqStr := fmt.Sprintf("GET http://%s/test HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: basic xyz\r\nCustom-Header: value\r\n\r\n", targetAddr, targetAddr)
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request error: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got: %d", resp.StatusCode)
	}

	if receivedHeaders.Get("Proxy-Connection") != "" {
		t.Errorf("Proxy-Connection was not stripped: %s", receivedHeaders.Get("Proxy-Connection"))
	}
	if receivedHeaders.Get("Proxy-Authorization") != "" {
		t.Errorf("Proxy-Authorization was not stripped: %s", receivedHeaders.Get("Proxy-Authorization"))
	}
	if receivedHeaders.Get("Custom-Header") != "value" {
		t.Errorf("expected Custom-Header to be preserved, got: %s", receivedHeaders.Get("Custom-Header"))
	}
}

// TestHTTPConnectPipelinedPayload covers a client that sends data right after
// CONNECT without waiting for "200": bytes already buffered while reading the
// request line must reach the upstream.
func TestHTTPConnectPipelinedPayload(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target echo server: %v", err)
	}
	defer targetListener.Close()
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	targetAddr := targetListener.Addr().String()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = targetListener.Addr().(*net.TCPAddr).Port

	eng, err := New(cfg, "")
	if err != nil {
		t.Fatalf("unexpected New error: %v", err)
	}
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", targetAddr)
		},
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("client dial http proxy failed: %v", err)
	}
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))

	payload := "pipelined-before-200\n"
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", targetAddr, targetAddr, payload)
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT failed: %v", err)
	}

	br := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", resp.StatusCode)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("pipelined payload lost: %v", err)
	}
	if string(buf) != payload {
		t.Errorf("got %q, want %q", buf, payload)
	}
}

func TestEngineStart_NoUpstreamNoProbeLoop(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = ""
	cfg.Proxy.Port = 0
	cfg.Health.ProbeInterval = "20ms"

	eng, err := New(cfg, "")
	if err != nil {
		t.Fatalf("unexpected New error: %v", err)
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed with empty proxy host: %v", err)
	}
	defer func() {
		_ = eng.Stop()
	}()

	st := eng.Status()
	if !st.Connected {
		t.Errorf("expected engine status Connected=true initially")
	}

	select {
	case evt := <-eng.Events():
		if evt.Type != EventConnected {
			t.Errorf("expected EventConnected, got: %v", evt.Type)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial EventConnected")
	}

	select {
	case evt := <-eng.Events():
		t.Fatalf("unexpected event from engine without upstream (probe loop should not run): %+v", evt)
	case <-time.After(100 * time.Millisecond):
		// Success: no spurious health check disconnect events
	}

	stAfter := eng.Status()
	if !stAfter.Connected {
		t.Errorf("expected engine to remain connected, got disconnected with reason: %s", stAfter.LastDisconnectReason)
	}
}
