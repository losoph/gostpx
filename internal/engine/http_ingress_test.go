package engine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

func newTestEngine(t *testing.T, cfg *config.Config, plainSecret string) *Engine {
	eng, err := New(cfg, plainSecret)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	eng.SetCheckProxy(func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
		return time.Millisecond, nil
	})
	return eng
}

// Test 1: Keep-Alive requests to DIFFERENT hosts over a single client connection.
// Verifies that each request reaches its intended host, responses are distinct,
// and the second request does not go to the first server.
func TestHTTPIngress_KeepAlive_DifferentHosts(t *testing.T) {
	var s1Reqs atomic.Int32
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s1Reqs.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("response from server A"))
	}))
	defer s1.Close()

	var s2Reqs atomic.Int32
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s2Reqs.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("response from server B"))
	}))
	defer s2.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, "pass")

	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			switch host {
			case "server-a.test":
				return net.Dial("tcp", s1.Listener.Addr().String())
			case "server-b.test":
				return net.Dial("tcp", s2.Listener.Addr().String())
			default:
				return nil, fmt.Errorf("unexpected host %q", host)
			}
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("client dial proxy error: %v", err)
	}
	defer clientConn.Close()

	br := bufio.NewReader(clientConn)

	// First request to server-a.test
	req1 := "GET http://server-a.test/ HTTP/1.1\r\nHost: server-a.test\r\n\r\n"
	if _, err := clientConn.Write([]byte(req1)); err != nil {
		t.Fatalf("write req1 error: %v", err)
	}
	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read resp1 error: %v", err)
	}
	body1, err := io.ReadAll(resp1.Body)
	if err != nil {
		t.Fatalf("read body1 error: %v", err)
	}
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("resp1 status = %d, want 200", resp1.StatusCode)
	}
	if string(body1) != "response from server A" {
		t.Errorf("resp1 body = %q, want %q", string(body1), "response from server A")
	}

	// Second request on the SAME client connection to server-b.test
	req2 := "GET http://server-b.test/ HTTP/1.1\r\nHost: server-b.test\r\n\r\n"
	if _, err := clientConn.Write([]byte(req2)); err != nil {
		t.Fatalf("write req2 error: %v", err)
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read resp2 error: %v", err)
	}
	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("read body2 error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("resp2 status = %d, want 200", resp2.StatusCode)
	}
	if string(body2) != "response from server B" {
		t.Errorf("resp2 body = %q, want %q", string(body2), "response from server B")
	}

	// Verify server A received exactly 1 request (second request didn't hit server A)
	if s1Reqs.Load() != 1 {
		t.Errorf("server A received %d requests, want 1", s1Reqs.Load())
	}
	// Verify server B received exactly 1 request
	if s2Reqs.Load() != 1 {
		t.Errorf("server B received %d requests, want 1", s2Reqs.Load())
	}
}

// Test 2: Two requests to the SAME host over a single connection: both 200.
func TestHTTPIngress_KeepAlive_SameHost(t *testing.T) {
	var reqCount atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("ok-%d", n)))
	}))
	defer s.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, "pass")

	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", s.Listener.Addr().String())
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy error: %v", err)
	}
	defer clientConn.Close()

	br := bufio.NewReader(clientConn)

	// First request
	req1 := "GET http://same-host.test/1 HTTP/1.1\r\nHost: same-host.test\r\n\r\n"
	if _, err := clientConn.Write([]byte(req1)); err != nil {
		t.Fatalf("write req1 error: %v", err)
	}
	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read resp1 error: %v", err)
	}
	b1, _ := io.ReadAll(resp1.Body)
	if resp1.StatusCode != http.StatusOK || string(b1) != "ok-1" {
		t.Errorf("req1 failed: status=%d body=%q", resp1.StatusCode, string(b1))
	}

	// Second request
	req2 := "GET http://same-host.test/2 HTTP/1.1\r\nHost: same-host.test\r\n\r\n"
	if _, err := clientConn.Write([]byte(req2)); err != nil {
		t.Fatalf("write req2 error: %v", err)
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read resp2 error: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK || string(b2) != "ok-2" {
		t.Errorf("req2 failed: status=%d body=%q", resp2.StatusCode, string(b2))
	}

	if reqCount.Load() != 2 {
		t.Errorf("server received %d requests, want 2", reqCount.Load())
	}
}

// Test 3: Hop-by-hop headers stripped.
// Connection: X-Custom and X-Custom header must be stripped;
// Proxy-Authorization and Proxy-Connection must be stripped;
// Normal header must reach the backend.
func TestHTTPIngress_HopByHopCustomStripped(t *testing.T) {
	var receivedHeaders http.Header
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer s.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, "pass")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", s.Listener.Addr().String())
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy error: %v", err)
	}
	defer clientConn.Close()

	req := "GET http://target.test/headers HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"Connection: X-Custom\r\n" +
		"X-Custom: secret-hop-value\r\n" +
		"Proxy-Authorization: Basic c2VjcmV0OnBhc3M=\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"X-Normal-Header: normal-user-value\r\n\r\n"

	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write request error: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	if v := receivedHeaders.Get("X-Custom"); v != "" {
		t.Errorf("X-Custom was not stripped: %q", v)
	}
	if v := receivedHeaders.Get("Proxy-Authorization"); v != "" {
		t.Errorf("Proxy-Authorization was not stripped: %q", v)
	}
	if v := receivedHeaders.Get("Proxy-Connection"); v != "" {
		t.Errorf("Proxy-Connection was not stripped: %q", v)
	}
	if v := receivedHeaders.Get("X-Normal-Header"); v != "normal-user-value" {
		t.Errorf("X-Normal-Header = %q, want %q", v, "normal-user-value")
	}
}

// Test 4:
//   - POST 1 MB body arrives at the server completely.
//   - Streaming response: server writes chunk 1, flushes, pauses 300 ms, writes chunk 2.
//     Client receives chunk 1 before chunk 2 is produced.
func TestHTTPIngress_Post1MB_And_StreamingResponse(t *testing.T) {
	oneMB := 1024 * 1024
	postPayload := make([]byte, oneMB)
	for i := range postPayload {
		postPayload[i] = byte(i % 251)
	}

	var receivedLen atomic.Int64
	var bodyMatches atomic.Bool

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			receivedLen.Store(int64(len(body)))
			bodyMatches.Store(bytes.Equal(body, postPayload))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("post-ok"))
			return
		}
		if r.URL.Path == "/stream" {
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "no flusher", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("chunk-1\n"))
			flusher.Flush()
			time.Sleep(300 * time.Millisecond)
			_, _ = w.Write([]byte("chunk-2\n"))
			flusher.Flush()
			return
		}
	}))
	defer s.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, "pass")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", s.Listener.Addr().String())
		},
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	// Part A: POST 1 MB
	conn1, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy error: %v", err)
	}
	defer conn1.Close()

	reqHead := fmt.Sprintf("POST http://target.test/post HTTP/1.1\r\nHost: target.test\r\nContent-Length: %d\r\n\r\n", len(postPayload))
	if _, err := conn1.Write([]byte(reqHead)); err != nil {
		t.Fatalf("write post header error: %v", err)
	}
	if _, err := conn1.Write(postPayload); err != nil {
		t.Fatalf("write post payload error: %v", err)
	}

	respPost, err := http.ReadResponse(bufio.NewReader(conn1), nil)
	if err != nil {
		t.Fatalf("read post response error: %v", err)
	}
	if respPost.StatusCode != http.StatusOK {
		t.Errorf("post status = %d, want 200", respPost.StatusCode)
	}
	if receivedLen.Load() != int64(oneMB) {
		t.Errorf("server received %d bytes, want %d", receivedLen.Load(), oneMB)
	}
	if !bodyMatches.Load() {
		t.Errorf("server received corrupted post body")
	}

	// Part B: Streaming response
	conn2, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy error: %v", err)
	}
	defer conn2.Close()

	reqStream := "GET http://target.test/stream HTTP/1.1\r\nHost: target.test\r\n\r\n"
	if _, err := conn2.Write([]byte(reqStream)); err != nil {
		t.Fatalf("write stream request error: %v", err)
	}

	brStream := bufio.NewReader(conn2)
	respStream, err := http.ReadResponse(brStream, nil)
	if err != nil {
		t.Fatalf("read stream response error: %v", err)
	}
	if respStream.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", respStream.StatusCode)
	}

	brBody := bufio.NewReader(respStream.Body)
	t0 := time.Now()
	chunk1, err := brBody.ReadString('\n')
	if err != nil {
		t.Fatalf("read chunk1 error: %v", err)
	}
	tChunk1 := time.Since(t0)

	if chunk1 != "chunk-1\n" {
		t.Errorf("chunk1 = %q, want %q", chunk1, "chunk-1\n")
	}
	// Chunk 1 must be received well before the 300 ms server pause completes
	if tChunk1 > 200*time.Millisecond {
		t.Errorf("chunk 1 received too late (%v > 200ms), flush may not be immediate", tChunk1)
	}

	chunk2, err := brBody.ReadString('\n')
	if err != nil {
		t.Fatalf("read chunk2 error: %v", err)
	}
	tTotal := time.Since(t0)

	if chunk2 != "chunk-2\n" {
		t.Errorf("chunk2 = %q, want %q", chunk2, "chunk-2\n")
	}
	// Total time must reflect the 300 ms sleep between chunks
	if tTotal < 280*time.Millisecond {
		t.Errorf("chunk 2 received too quickly (%v < 280ms)", tTotal)
	}
	_ = respStream.Body.Close()
}

// Test 5: Non-absolute request (GET / HTTP/1.1) returns 400 Bad Request
// without dialing (mockDialer calls count = 0).
func TestHTTPIngress_NonAbsoluteRequest_Returns400_NoDial(t *testing.T) {
	var dialCount atomic.Int32

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, "pass")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			dialCount.Add(1)
			return nil, fmt.Errorf("should not be called")
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy error: %v", err)
	}
	defer clientConn.Close()

	// Non-absolute URL request line
	req := "GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write request error: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if dialCount.Load() != 0 {
		t.Errorf("dialCount = %d, want 0", dialCount.Load())
	}
}

// Test 6: Dial failure returns 502 Bad Gateway; response body does not leak plain password.
func TestHTTPIngress_DialFailure_Returns502_SecretMasked(t *testing.T) {
	plainSecret := "SuperSecretPassword123!"

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, plainSecret)
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return nil, fmt.Errorf("connection to http://user:%s@proxy.net failed", plainSecret)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy error: %v", err)
	}
	defer clientConn.Close()

	req := "GET http://unreachable.test/ HTTP/1.1\r\nHost: unreachable.test\r\n\r\n"
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write request error: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response error: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body error: %v", err)
	}
	bodyStr := string(body)

	if strings.Contains(bodyStr, plainSecret) {
		t.Errorf("plain password leaked in response body: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "***") {
		t.Errorf("expected masked '***' in sanitized error body, got: %q", bodyStr)
	}
}

// Test 7: CONNECT + half-close.
// Target server reads until EOF and only then responds with ~64 KB.
// Client issues CloseWrite after request; client receives entire 64 KB response.
func TestHTTPIngress_Connect_HalfClose(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target error: %v", err)
	}
	defer targetListener.Close()

	expectedResponse := bytes.Repeat([]byte("A"), 64*1024)

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read until EOF
				clientData, err := io.ReadAll(c)
				if err != nil {
					return
				}
				if string(clientData) != "hello from client with half close" {
					return
				}
				// Write full 64 KB response only after client EOF
				_, _ = c.Write(expectedResponse)
			}(conn)
		}
	}()

	targetAddr := targetListener.Addr().String()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, "pass")
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
		t.Fatalf("dial proxy error: %v", err)
	}
	defer clientConn.Close()

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT error: %v", err)
	}

	br := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Send client payload into the tunnel
	if _, err := clientConn.Write([]byte("hello from client with half close")); err != nil {
		t.Fatalf("write payload error: %v", err)
	}

	// Perform half-close on client TCP connection
	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn")
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite error: %v", err)
	}

	// Read entire response from tunnel until server closes connection
	receivedResponse, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("read full response error: %v", err)
	}

	if len(receivedResponse) != len(expectedResponse) {
		t.Fatalf("received response len = %d, want %d", len(receivedResponse), len(expectedResponse))
	}
	if !bytes.Equal(receivedResponse, expectedResponse) {
		t.Errorf("received response does not match expected response")
	}
}

// Test 8: HTTP Upgrade: server replies 101 Switching Protocols,
// followed by raw byte echo over the connection through the proxy.
func TestHTTPIngress_Upgrade101_Echo(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		rc := http.NewResponseController(w)
		conn, brw, err := rc.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		if _, err := brw.WriteString(resp); err != nil {
			return
		}
		if err := brw.Flush(); err != nil {
			return
		}

		// Echo back all bytes received
		_, _ = io.Copy(conn, conn)
	}))
	defer s.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, "pass")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", s.Listener.Addr().String())
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.Dial("tcp", eng.httpListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy error: %v", err)
	}
	defer clientConn.Close()

	req := "GET http://target.test/ws HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n\r\n"

	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade request error: %v", err)
	}

	br := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response error: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	// Send echo payload over upgraded stream
	testMsg := []byte("echo-payload-through-upgraded-tunnel\n")
	if _, err := clientConn.Write(testMsg); err != nil {
		t.Fatalf("write echo payload error: %v", err)
	}

	echoBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(br, echoBuf); err != nil {
		t.Fatalf("read echo payload error: %v", err)
	}

	if !bytes.Equal(echoBuf, testMsg) {
		t.Errorf("echoed = %q, want %q", string(echoBuf), string(testMsg))
	}
}

// Test 9: Engine Stop and Restart lifecycle without goroutine leaks.
// Tests that Start -> Stop -> Start works, re-opening listener and serving requests.
func TestHTTPIngress_Stop_Restart_Lifecycle(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer s.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 12345

	eng := newTestEngine(t, cfg, "pass")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.Dial("tcp", s.Listener.Addr().String())
		},
	}

	for cycle := 1; cycle <= 2; cycle++ {
		if err := eng.Start(); err != nil {
			t.Fatalf("cycle %d Start error: %v", cycle, err)
		}
		if !eng.Status().Connected {
			t.Fatalf("cycle %d expected connected", cycle)
		}

		// Send request
		c, err := net.Dial("tcp", eng.httpListener.Addr().String())
		if err != nil {
			t.Fatalf("cycle %d dial proxy error: %v", cycle, err)
		}
		req := "GET http://target.test/ HTTP/1.1\r\nHost: target.test\r\n\r\n"
		if _, err := c.Write([]byte(req)); err != nil {
			_ = c.Close()
			t.Fatalf("cycle %d write req error: %v", cycle, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			_ = c.Close()
			t.Fatalf("cycle %d read resp error: %v", cycle, err)
		}
		_ = c.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("cycle %d status = %d, want 200", cycle, resp.StatusCode)
		}

		if err := eng.Stop(); err != nil {
			t.Fatalf("cycle %d Stop error: %v", cycle, err)
		}
		if eng.Status().Connected {
			t.Fatalf("cycle %d expected disconnected", cycle)
		}
	}
}
