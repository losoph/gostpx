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
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

func startEchoServer(t *testing.T) (net.Listener, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}
	var wg sync.WaitGroup
	closed := atomic.Bool{}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	cleanup := func() {
		if closed.CompareAndSwap(false, true) {
			_ = l.Close()
			wg.Wait()
		}
	}
	return l, cleanup
}

func connectHTTP(t *testing.T, proxyAddr, targetAddr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial http proxy %s: %v", proxyAddr, err)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		t.Fatalf("CONNECT status: got %d, want 200", resp.StatusCode)
	}
	return conn, reader
}

func connectSOCKS5(t *testing.T, proxyAddr, targetHost string, targetPort int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks5 proxy %s: %v", proxyAddr, err)
	}
	// Greeting: VER 5, 1 method, NO AUTH (0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 greeting resp: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		_ = conn.Close()
		t.Fatalf("SOCKS5 greeting failed: %v", resp)
	}

	// Connect request
	req := make([]byte, 0, 32)
	req = append(req, 0x05, 0x01, 0x00) // VER 5, CMD 1 (CONNECT), RSV 0
	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01) // ATYP IPv4
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04) // ATYP IPv6
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(targetHost))) // ATYP Domain
		req = append(req, []byte(targetHost)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetPort))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 connect req: %v", err)
	}

	replyHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHdr); err != nil {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 connect reply hdr: %v", err)
	}
	if replyHdr[1] != 0x00 {
		_ = conn.Close()
		t.Fatalf("SOCKS5 connect rejected: rep=%d", replyHdr[1])
	}

	var addrLen int
	switch replyHdr[3] {
	case 0x01:
		addrLen = 4
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			_ = conn.Close()
			t.Fatalf("read domain len: %v", err)
		}
		addrLen = int(lenBuf[0])
	case 0x04:
		addrLen = 16
	}
	bindBuf := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, bindBuf); err != nil {
		_ = conn.Close()
		t.Fatalf("read bind addr: %v", err)
	}

	return conn
}

// 1. CONNECT-туннель к тестовому серверу (держит соединение открытым), Stop() -> клиент получает EOF
// или ошибку чтения не позже чем через 1 с.
func TestTunnelClose_HTTPConnect(t *testing.T) {
	echoL, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.DialTimeout("tcp", echoL.Addr().String(), 2*time.Second)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, reader := connectHTTP(t, eng.httpListener.Addr().String(), "upstream.example.com:443")
	defer clientConn.Close()

	// Verify tunnel functions
	msg := []byte("ping-connect\n")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("write to tunnel: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read from tunnel: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}

	if active := eng.ActiveTunnels(); active != 1 {
		t.Fatalf("expected 1 active tunnel, got %d", active)
	}

	readErrCh := make(chan error, 1)
	go func() {
		sink := make([]byte, 64)
		_, err := reader.Read(sink)
		readErrCh <- err
	}()

	// Stop engine — must close the hijacked CONNECT tunnel
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("expected EOF or read error, got nil")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("client did not receive EOF or read error within 1 second after Stop()")
	}

	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active tunnels after Stop(), got %d", active)
	}
}

// 2. SOCKS5-туннель к тестовому серверу, Stop() -> клиент получает EOF или ошибку чтения не позже чем через 1 с.
func TestTunnelClose_SOCKS5(t *testing.T) {
	echoL, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.DialTimeout("tcp", echoL.Addr().String(), 2*time.Second)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn := connectSOCKS5(t, eng.socksListener.Addr().String(), "upstream.example.com", 443)
	defer clientConn.Close()

	// Verify tunnel functions
	msg := []byte("ping-socks5\n")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("write to socks5 tunnel: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read from socks5 tunnel: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}

	if active := eng.ActiveTunnels(); active != 1 {
		t.Fatalf("expected 1 active tunnel, got %d", active)
	}

	readErrCh := make(chan error, 1)
	go func() {
		sink := make([]byte, 64)
		_, err := clientConn.Read(sink)
		readErrCh <- err
	}()

	// Stop engine — must close the SOCKS5 tunnel
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("expected EOF or read error, got nil")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("client did not receive EOF or read error within 1 second after Stop()")
	}

	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active tunnels after Stop(), got %d", active)
	}
}

// 3. Туннель к loopback-назначению (127.0.0.1:<порт>) после Stop() — НЕ закрыт (ADR-021).
func TestTunnelClose_LoopbackNotClosed(t *testing.T) {
	echoL, echoCleanup := startEchoServer(t)
	defer echoCleanup()
	echoAddr := echoL.Addr().String()
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	var echoPort int
	_, _ = fmt.Sscanf(echoPortStr, "%d", &echoPort)

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			t.Fatalf("mockDialer must not be called for loopback target %s:%d", host, port)
			return nil, nil
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	// Part A: CONNECT tunnel to loopback target
	httpConn, httpReader := connectHTTP(t, eng.httpListener.Addr().String(), echoAddr)
	defer httpConn.Close()

	// Part B: SOCKS5 tunnel to loopback target
	socksConn := connectSOCKS5(t, eng.socksListener.Addr().String(), "127.0.0.1", echoPort)
	defer socksConn.Close()

	// Check loopback tunnels are NOT registered in active upstream tunnels
	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active registered tunnels for loopback, got %d", active)
	}

	// Verify both work before Stop()
	if _, err := httpConn.Write([]byte("http-before\n")); err != nil {
		t.Fatalf("httpConn write before stop: %v", err)
	}
	hBuf := make([]byte, len("http-before\n"))
	if _, err := io.ReadFull(httpReader, hBuf); err != nil {
		t.Fatalf("httpReader read before stop: %v", err)
	}

	if _, err := socksConn.Write([]byte("socks-before\n")); err != nil {
		t.Fatalf("socksConn write before stop: %v", err)
	}
	sBuf := make([]byte, len("socks-before\n"))
	if _, err := io.ReadFull(socksConn, sBuf); err != nil {
		t.Fatalf("socksConn read before stop: %v", err)
	}

	// Stop engine
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	// Verify loopback tunnels are STILL OPEN and functional after Stop() (ADR-021)
	if _, err := httpConn.Write([]byte("http-after\n")); err != nil {
		t.Fatalf("httpConn write after stop: %v (loopback tunnel must NOT be closed)", err)
	}
	hBufAfter := make([]byte, len("http-after\n"))
	if _, err := io.ReadFull(httpReader, hBufAfter); err != nil {
		t.Fatalf("httpReader read after stop: %v (loopback tunnel must NOT be closed)", err)
	}
	if string(hBufAfter) != "http-after\n" {
		t.Fatalf("got %q, want 'http-after\\n'", string(hBufAfter))
	}

	if _, err := socksConn.Write([]byte("socks-after\n")); err != nil {
		t.Fatalf("socksConn write after stop: %v (loopback tunnel must NOT be closed)", err)
	}
	sBufAfter := make([]byte, len("socks-after\n"))
	if _, err := io.ReadFull(socksConn, sBufAfter); err != nil {
		t.Fatalf("socksConn read after stop: %v (loopback tunnel must NOT be closed)", err)
	}
	if string(sBufAfter) != "socks-after\n" {
		t.Fatalf("got %q, want 'socks-after\\n'", string(sBufAfter))
	}
}

// 4. 20 туннелей, Stop() -> все закрыты, горутины pipe завершились (счётчик или runtime.NumGoroutine
// с допуском), под -race.
func TestTunnelClose_20Tunnels(t *testing.T) {
	echoL, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.DialTimeout("tcp", echoL.Addr().String(), 2*time.Second)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	const totalTunnels = 20
	httpAddr := eng.httpListener.Addr().String()
	socksAddr := eng.socksListener.Addr().String()

	gBefore := runtime.NumGoroutine()

	conns := make([]net.Conn, totalTunnels)
	readers := make([]*bufio.Reader, totalTunnels)

	for i := 0; i < totalTunnels; i++ {
		if i%2 == 0 {
			c, r := connectHTTP(t, httpAddr, "target.upstream:443")
			conns[i] = c
			readers[i] = r
		} else {
			c := connectSOCKS5(t, socksAddr, "target.upstream", 443)
			conns[i] = c
			readers[i] = bufio.NewReader(c)
		}
		defer conns[i].Close()

		// Verify data transfer
		ping := fmt.Sprintf("ping-%d\n", i)
		if _, err := conns[i].Write([]byte(ping)); err != nil {
			t.Fatalf("write conn %d: %v", i, err)
		}
		buf := make([]byte, len(ping))
		if _, err := io.ReadFull(readers[i], buf); err != nil {
			t.Fatalf("read conn %d: %v", i, err)
		}
	}

	if active := eng.ActiveTunnels(); active != totalTunnels {
		t.Fatalf("expected %d active tunnels, got %d", totalTunnels, active)
	}

	readErrCh := make(chan error, totalTunnels)
	for i := 0; i < totalTunnels; i++ {
		r := readers[i]
		go func() {
			sink := make([]byte, 64)
			_, err := r.Read(sink)
			readErrCh <- err
		}()
	}

	// Stop engine
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	// Verify all 20 connections receive EOF or error within 1 second
	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()
	for i := 0; i < totalTunnels; i++ {
		select {
		case err := <-readErrCh:
			if err == nil {
				t.Fatalf("tunnel %d expected error/EOF, got nil", i)
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for tunnel %d to close", i)
		}
	}

	// Wait for pipe goroutines to terminate and active tunnels counter to reach 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if eng.ActiveTunnels() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active tunnels after pipe completion, got %d", active)
	}

	// Wait up to 1s for goroutines to return to baseline with tolerance
	deadlineG := time.Now().Add(1 * time.Second)
	var gAfter int
	for time.Now().Before(deadlineG) {
		gAfter = runtime.NumGoroutine()
		if gAfter <= gBefore+10 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gAfter > gBefore+10 {
		t.Errorf("possible goroutine leak: baseline=%d, after close=%d", gBefore, gAfter)
	}
}

// 5. Stop() -> Start() -> новый туннель работает.
func TestTunnelClose_RestartWorks(t *testing.T) {
	echoL, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.DialTimeout("tcp", echoL.Addr().String(), 2*time.Second)
		},
	}

	// 1st Cycle
	if err := eng.Start(); err != nil {
		t.Fatalf("first Start error: %v", err)
	}
	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active tunnels after fresh Start, got %d", active)
	}

	c1, r1 := connectHTTP(t, eng.httpListener.Addr().String(), "target.upstream:443")
	defer c1.Close()

	if _, err := c1.Write([]byte("first-cycle\n")); err != nil {
		t.Fatalf("write c1: %v", err)
	}
	buf1 := make([]byte, len("first-cycle\n"))
	if _, err := io.ReadFull(r1, buf1); err != nil {
		t.Fatalf("read c1: %v", err)
	}
	if string(buf1) != "first-cycle\n" {
		t.Fatalf("got %q, want 'first-cycle\\n'", string(buf1))
	}
	if active := eng.ActiveTunnels(); active != 1 {
		t.Fatalf("expected 1 active tunnel, got %d", active)
	}

	if err := eng.Stop(); err != nil {
		t.Fatalf("first Stop error: %v", err)
	}
	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active tunnels after first Stop, got %d", active)
	}

	// 2nd Cycle: Start again with fresh empty registry
	if err := eng.Start(); err != nil {
		t.Fatalf("second Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active tunnels on repeated Start, got %d", active)
	}

	c2, r2 := connectHTTP(t, eng.httpListener.Addr().String(), "target.upstream:443")
	defer c2.Close()

	if _, err := c2.Write([]byte("second-cycle\n")); err != nil {
		t.Fatalf("write c2: %v", err)
	}
	buf2 := make([]byte, len("second-cycle\n"))
	if _, err := io.ReadFull(r2, buf2); err != nil {
		t.Fatalf("read c2: %v", err)
	}
	if string(buf2) != "second-cycle\n" {
		t.Fatalf("got %q, want 'second-cycle\\n'", string(buf2))
	}
	if active := eng.ActiveTunnels(); active != 1 {
		t.Fatalf("expected 1 active tunnel in second cycle, got %d", active)
	}

	if err := eng.Stop(); err != nil {
		t.Fatalf("second Stop error: %v", err)
	}
	if active := eng.ActiveTunnels(); active != 0 {
		t.Fatalf("expected 0 active tunnels after second Stop, got %d", active)
	}
}

// 6. Обычный HTTP через ReverseProxy уже закрывается http.Server.Close()
func TestTunnelClose_PlainHTTPReverseProxy(t *testing.T) {
	reqReceived := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reqReceived)
		// Keep connection open until server or client closes
		<-r.Context().Done()
	}))
	defer backend.Close()

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:0"
	cfg.Sysproxy.SOCKSListen = "127.0.0.1:0"
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 19999

	eng := newTestEngine(t, cfg, "")
	eng.dialer = &mockDialer{
		dialTargetFunc: func(ctx context.Context, host string, port int) (net.Conn, error) {
			return net.DialTimeout("tcp", backend.Listener.Addr().String(), 2*time.Second)
		},
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	clientConn, err := net.DialTimeout("tcp", eng.httpListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial httpListener: %v", err)
	}
	defer clientConn.Close()

	req := fmt.Sprintf("GET %s/slow HTTP/1.1\r\nHost: %s\r\n\r\n", backend.URL, backend.Listener.Addr().String())
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}

	select {
	case <-reqReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive HTTP request")
	}

	readErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		_, err := clientConn.Read(buf)
		readErrCh <- err
	}()

	// Stop engine
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("expected EOF or read error for plain HTTP after Stop(), got nil")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("plain HTTP connection was not closed within 1 second after Stop()")
	}
}
