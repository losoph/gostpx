package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/losoph/gostpx/internal/config"
)

// EventType represents the engine lifecycle or connection events.
type EventType string

const (
	EventConnected    EventType = "connected"
	EventDisconnected EventType = "disconnected"
	EventError        EventType = "error"
	EventNetworkDown  EventType = "network_down"
	EventNetworkUp    EventType = "network_up"
)

// Event represents an engine event notification.
type Event struct {
	Type      EventType
	Reason    string
	Timestamp time.Time
}

// Status represents the runtime status of the engine.
type Status struct {
	Connected            bool          `json:"connected"`
	Mode                 string        `json:"mode"`
	ProxyURL             string        `json:"proxy_url"`
	RTT                  time.Duration `json:"rtt"`
	SessionStart         time.Time     `json:"session_start"`
	LastDisconnectReason string        `json:"last_disconnect_reason,omitempty"`
	HTTPListen           string        `json:"http_listen"`
	SOCKSListen          string        `json:"socks_listen"`
}

const (
	defaultProbeRetries    = 3
	defaultProbeRetryDelay = 2 * time.Second
	defaultProbeTimeout    = 5 * time.Second
)

var (
	probeRetries       = defaultProbeRetries
	probeRetryDelay    = defaultProbeRetryDelay
	probeTimeout       = defaultProbeTimeout
	globalCheckProxyMu sync.RWMutex
	globalCheckProxyFn func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error)
)

// Engine manages local ingress proxies (HTTP & SOCKS5) and outbound TargetDialer.
type Engine struct {
	lifecycleMu sync.Mutex

	cfg       *config.Config
	dialer    TargetDialer
	maskedURL string

	httpListener  net.Listener
	socksListener net.Listener

	httpServer    *http.Server
	httpTransport *http.Transport
	plainSecret   string

	mu                sync.RWMutex
	running           bool
	status            Status
	consecutiveErrors atomic.Int32

	probeRetries    int
	probeRetryDelay time.Duration
	probeTimeout    time.Duration
	confirming      atomic.Bool

	checkProxyMu sync.RWMutex
	checkProxyFn func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error)

	netDownMu    sync.RWMutex
	netDownFn    func(lastErr error) bool
	netDownState atomic.Bool

	events chan Event
	stopCh chan struct{}
	wg     sync.WaitGroup

	tunnelsMu     sync.Mutex
	tunnels       map[*tunnelEntry]struct{}
	tunnelsClosed bool
	tunnelsWg     sync.WaitGroup
}

type tunnelEntry struct {
	client net.Conn
	target net.Conn
}

// New creates a new Engine instance.
func New(cfg *config.Config, plainSecret string) (*Engine, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	var dialer TargetDialer
	var masked string
	if cfg.Proxy.Host != "" {
		u, err := BuildProxyURL(cfg.Proxy, plainSecret)
		if err != nil {
			return nil, fmt.Errorf("build proxy URL: %w", err)
		}
		masked = MaskURL(u)

		d, err := NewDirectDialer(cfg.Proxy, plainSecret)
		if err != nil {
			return nil, fmt.Errorf("create direct dialer: %w", SanitizeError(err, plainSecret))
		}
		dialer = d
	}

	eng := &Engine{
		cfg:             cfg,
		dialer:          dialer,
		maskedURL:       masked,
		plainSecret:     plainSecret,
		events:          make(chan Event, 64),
		stopCh:          make(chan struct{}),
		probeRetries:    probeRetries,
		probeRetryDelay: probeRetryDelay,
		probeTimeout:    probeTimeout,
		status: Status{
			Connected:   false,
			Mode:        cfg.Mode,
			ProxyURL:    masked,
			HTTPListen:  cfg.Sysproxy.HTTPListen,
			SOCKSListen: cfg.Sysproxy.SOCKSListen,
		},
		tunnels: make(map[*tunnelEntry]struct{}),
	}

	return eng, nil
}

// Status returns a copy of current engine status.
func (e *Engine) Status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status
}

// Events returns the read-only channel of engine events.
func (e *Engine) Events() <-chan Event {
	return e.events
}

// Start launches the local HTTP and SOCKS5 listeners and health probe.
func (e *Engine) Start() error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()

	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("engine is already running")
	}

	// (Re)create stopCh for this session so engine survives restart (Point 3)
	e.stopCh = make(chan struct{})
	stopCh := e.stopCh
	e.consecutiveErrors.Store(0)
	e.running = true
	e.mu.Unlock()

	e.tunnelsMu.Lock()
	e.tunnels = make(map[*tunnelEntry]struct{})
	e.tunnelsClosed = false
	e.tunnelsMu.Unlock()

	// Initial health probe before opening listeners
	if e.cfg.Proxy.Host != "" && e.cfg.Proxy.Port > 0 {
		timeout := e.probeTimeout
		if timeout <= 0 {
			timeout = defaultProbeTimeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		rtt, err := e.doCheckProxy(ctx, e.cfg.Proxy.Host, e.cfg.Proxy.Port, timeout)
		cancel()
		if err != nil {
			e.mu.Lock()
			e.running = false
			e.mu.Unlock()
			return fmt.Errorf("upstream proxy check failed: %w", SanitizeError(err, ""))
		}
		e.mu.Lock()
		e.status.RTT = rtt
		e.mu.Unlock()
	}

	// Start HTTP CONNECT listener
	httpL, err := net.Listen("tcp", e.cfg.Sysproxy.HTTPListen)
	if err != nil {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
		return fmt.Errorf("listen http on %q: %w", e.cfg.Sysproxy.HTTPListen, err)
	}
	e.httpListener = httpL

	// Start SOCKS5 listener
	socksL, err := net.Listen("tcp", e.cfg.Sysproxy.SOCKSListen)
	if err != nil {
		_ = httpL.Close()
		e.mu.Lock()
		e.running = false
		e.httpListener = nil
		e.mu.Unlock()
		return fmt.Errorf("listen socks5 on %q: %w", e.cfg.Sysproxy.SOCKSListen, err)
	}
	e.socksListener = socksL

	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
				portStr = "80"
			}
			host = strings.TrimPrefix(host, "[")
			host = strings.TrimSuffix(host, "]")
			port, err := strconv.Atoi(portStr)
			if err != nil || port <= 0 || port > 65535 {
				port = 80
			}
			conn, err := e.dialTarget(ctx, host, port)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}

	server := &http.Server{
		Handler:           e.createHTTPHandler(tr),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	e.mu.Lock()
	e.httpTransport = tr
	e.httpServer = server
	e.status.Connected = true
	e.status.SessionStart = time.Now()
	e.status.LastDisconnectReason = ""
	e.mu.Unlock()

	e.emitEvent(Event{
		Type:      EventConnected,
		Timestamp: time.Now(),
	})

	e.wg.Add(2)
	go e.serveHTTP(httpL)
	go e.serveSOCKS5(socksL, stopCh)

	// Start background health probe loop (only with configured upstream)
	if e.cfg.Proxy.Host != "" && e.cfg.Proxy.Port > 0 {
		e.wg.Add(1)
		go e.probeLoop(stopCh)
	}

	return nil
}

// Stop shuts down listeners and background tasks.
func (e *Engine) Stop() error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()

	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false

	select {
	case <-e.stopCh:
	default:
		close(e.stopCh)
	}

	httpL := e.httpListener
	socksL := e.socksListener
	srv := e.httpServer
	tr := e.httpTransport
	e.httpListener = nil
	e.socksListener = nil
	e.httpServer = nil
	e.httpTransport = nil
	e.mu.Unlock()

	if srv != nil {
		_ = srv.Close()
	}
	if tr != nil {
		tr.CloseIdleConnections()
	}
	if httpL != nil {
		_ = httpL.Close()
	}
	if socksL != nil {
		_ = socksL.Close()
	}

	e.closeTunnels()

	e.wg.Wait()

	if e.dialer != nil {
		_ = e.dialer.Close()
	}

	e.mu.Lock()
	e.status.Connected = false
	e.status.LastDisconnectReason = "stopped"
	e.mu.Unlock()

	e.emitEvent(Event{
		Type:      EventDisconnected,
		Reason:    "stopped",
		Timestamp: time.Now(),
	})

	return nil
}

func (e *Engine) notifyDisconnected(reason string) {
	e.mu.Lock()
	wasConnected := e.status.Connected
	e.status.Connected = false
	e.status.LastDisconnectReason = reason
	e.mu.Unlock()

	if wasConnected {
		e.emitEvent(Event{
			Type:      EventDisconnected,
			Reason:    reason,
			Timestamp: time.Now(),
		})
	}
}

func (e *Engine) recordDialSuccess() {
	e.consecutiveErrors.Store(0)
}

func (e *Engine) recordDialFailure(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, ErrCredentialsRejected) {
		e.notifyDisconnected(fmt.Sprintf("отказ в авторизации: %v", err))
		return
	}
	if !errors.Is(err, ErrUpstreamUnreachable) {
		return
	}

	count := e.consecutiveErrors.Add(1)
	retries := e.probeRetries
	if retries <= 0 {
		retries = defaultProbeRetries
	}
	if count >= int32(retries) && e.cfg.Proxy.Host != "" && e.cfg.Proxy.Port > 0 {
		if !e.confirming.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer e.confirming.Store(false)
			_, lastErr := e.checkUpstreamWithRetries(e.stopCh)
			select {
			case <-e.stopCh:
				return
			default:
			}
			if lastErr != nil {
				if e.isLocalNetworkDown(lastErr) {
					e.handleNetworkDown(lastErr)
					return
				}
				e.handleNetworkUp()
				e.notifyDisconnected(formatProbeFailureReason(e.effectiveRetries(), lastErr))
			} else {
				e.handleNetworkUp()
				e.consecutiveErrors.Store(0)
			}
		}()
	}
}

func (e *Engine) emitEvent(evt Event) {
	select {
	case e.events <- evt:
	default:
		// Drop or non-blocking to prevent stalling
	}
}

// EmitEventForTest emits an event into the engine's event channel (for testing).
func (e *Engine) EmitEventForTest(evt Event) {
	e.emitEvent(evt)
}

func formatProbeFailureReason(retries int, lastErr error) string {
	var probeWord string
	switch retries % 10 {
	case 1:
		probeWord = "проверка"
		if retries%100 == 11 {
			probeWord = "проверок"
		}
	case 2, 3, 4:
		probeWord = "проверки"
		if retries%100 >= 12 && retries%100 <= 14 {
			probeWord = "проверок"
		}
	default:
		probeWord = "проверок"
	}
	return fmt.Sprintf("прокси не отвечает (%d %s подряд): %v", retries, probeWord, lastErr)
}

func (e *Engine) effectiveRetries() int {
	if e.probeRetries > 0 {
		return e.probeRetries
	}
	return defaultProbeRetries
}

func (e *Engine) handleNetworkDown(lastErr error) {
	if !e.netDownState.Swap(true) {
		e.emitEvent(Event{
			Type:      EventNetworkDown,
			Reason:    fmt.Sprintf("нет локальной сети: %v", lastErr),
			Timestamp: time.Now(),
		})
	}
}

func (e *Engine) handleNetworkUp() {
	if e.netDownState.Swap(false) {
		e.emitEvent(Event{
			Type:      EventNetworkUp,
			Timestamp: time.Now(),
		})
	}
}

func (e *Engine) checkUpstreamWithRetries(stopCh <-chan struct{}) (time.Duration, error) {
	var lastErr error
	retries := e.effectiveRetries()
	delay := e.probeRetryDelay
	if delay <= 0 {
		delay = defaultProbeRetryDelay
	}
	if interval := e.cfg.ProbeDuration(); interval > 0 && interval < delay {
		delay = interval
	}
	timeout := e.probeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}

	for attempt := 1; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		rtt, err := e.doCheckProxy(ctx, e.cfg.Proxy.Host, e.cfg.Proxy.Port, timeout)
		cancel()
		if err == nil {
			return rtt, nil
		}
		lastErr = err

		if attempt < retries {
			select {
			case <-stopCh:
				return 0, errors.New("engine stopped")
			case <-time.After(delay):
			}
		}
	}
	return 0, lastErr
}

// probeLoop periodically pings the upstream proxy to monitor basic TCP reachability and RTT.
// Note: probeLoop intentionally uses a lightweight TCP connect (CheckProxy) to cfg.Proxy.Host:Port
// rather than full CONNECT tunneling (VerifyUpstream) every probe_interval.
// Rationale:
//  1. Full protocol compliance, authentication credentials, and destination tunneling capability
//     are already verified with a real handshake during pre-flight (VerifyUpstream in session.Start/Restart).
//  2. Continuous full tunneling to an external destination (e.g. 1.1.1.1:443) every 10-30s generates
//     unwanted external traffic, risks target rate limits, and consumes billable quotas on metered proxies.
//  3. Real upstream breakage or auth revocation during active sessions is immediately caught on real user
//     traffic by serveHTTP/serveSOCKS5 and recordDialFailure.
func (e *Engine) probeLoop(stopCh <-chan struct{}) {
	defer e.wg.Done()
	if e.cfg.Proxy.Host == "" || e.cfg.Proxy.Port <= 0 {
		return
	}
	interval := e.cfg.ProbeDuration()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			rtt, lastErr := e.checkUpstreamWithRetries(stopCh)
			select {
			case <-stopCh:
				return
			default:
			}

			if lastErr != nil {
				if e.isLocalNetworkDown(lastErr) {
					e.handleNetworkDown(lastErr)
					continue
				}
				e.handleNetworkUp()
				e.notifyDisconnected(formatProbeFailureReason(e.effectiveRetries(), lastErr))
			} else {
				e.handleNetworkUp()
				e.consecutiveErrors.Store(0)
				e.mu.Lock()
				e.status.RTT = rtt
				wasDisconnected := !e.status.Connected
				if wasDisconnected && e.running && e.status.LastDisconnectReason != "stopped" {
					e.status.Connected = true
					e.status.LastDisconnectReason = ""
					e.emitEvent(Event{
						Type:      EventConnected,
						Timestamp: time.Now(),
					})
				}
				e.mu.Unlock()
			}
		}
	}
}

// serveHTTP handles HTTP requests on Sysproxy.HTTPListen using http.Server.
func (e *Engine) serveHTTP(l net.Listener) {
	defer e.wg.Done()
	e.mu.RLock()
	srv := e.httpServer
	e.mu.RUnlock()
	if srv == nil {
		return
	}
	// Result of Serve is ignored on shutdown; the listener is closed by Stop().
	_ = srv.Serve(l)
}

func (e *Engine) createHTTPHandler(transport *http.Transport) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Do NOT call pr.SetXForwarded(): upstream does not need client's real IP.
			if pr.Out.URL.Scheme == "" {
				pr.Out.URL.Scheme = "http"
			}
			if pr.Out.URL.Host == "" {
				pr.Out.URL.Host = pr.In.Host
			}
			if pr.Out.Host == "" {
				pr.Out.Host = pr.In.Host
			}
			if pr.Out.Host == "" {
				pr.Out.Host = pr.Out.URL.Host
			}
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			sanitized := SanitizeError(err, e.plainSecret)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(sanitized.Error() + "\n"))
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect {
			e.handleConnect(w, req)
			return
		}

		// Non-absolute form (e.g. "GET / HTTP/1.1" without scheme and host)
		// must return 400 with short text, without dialing.
		if req.URL.Scheme == "" || req.URL.Host == "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("400 Bad Request: absolute URL required for proxy\n"))
			return
		}

		proxy.ServeHTTP(w, req)
	})
}

// isLoopbackTarget reports whether host is a loopback destination.
// Loopback is either:
// - an IP literal whose unmapped address is loopback (e.g. 127.0.0.0/8, ::1, ::ffff:127.x)
// - the host name "localhost" or ending in ".localhost" (case-insensitive, trailing dot ignored)
func isLoopbackTarget(host string) bool {
	if host == "" {
		return false
	}
	clean := strings.TrimPrefix(host, "[")
	clean = strings.TrimSuffix(clean, "]")
	if addr, err := netip.ParseAddr(clean); err == nil {
		return addr.Unmap().IsLoopback()
	}
	h := strings.TrimSuffix(host, ".")
	h = strings.ToLower(h)
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

func loopbackDialAddr(host string, port int) string {
	clean := strings.TrimPrefix(host, "[")
	clean = strings.TrimSuffix(clean, "]")
	if _, err := netip.ParseAddr(clean); err == nil {
		return net.JoinHostPort(clean, strconv.Itoa(port))
	}
	return net.JoinHostPort("localhost", strconv.Itoa(port))
}

func (e *Engine) dialTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	if isLoopbackTarget(host) {
		d := net.Dialer{Timeout: 10 * time.Second}
		return d.DialContext(ctx, "tcp", loopbackDialAddr(host, port))
	}
	if e.dialer == nil {
		return nil, errors.New("dialer is not configured")
	}
	conn, err := e.dialer.DialTarget(ctx, host, port)
	if err != nil {
		e.recordDialFailure(err)
		return nil, err
	}
	e.recordDialSuccess()
	return conn, nil
}

func (e *Engine) handleConnect(w http.ResponseWriter, req *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	target := req.RequestURI
	if target == "" {
		target = req.Host
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = "443"
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		port = 443
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	ctx := req.Context()
	upConn, err := e.dialTarget(ctx, host, port)
	if err != nil {
		sanitized := SanitizeError(err, e.plainSecret)
		errMsg := sanitized.Error()
		resp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(errMsg), errMsg)
		_, _ = clientConn.Write([]byte(resp))
		return
	}
	defer upConn.Close()

	// Success response to client
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}

	// Bytes the client sent right after CONNECT (without waiting for 200)
	// are already in the reader's buffer; forward them before piping.
	if n := rw.Reader.Buffered(); n > 0 {
		early := make([]byte, n)
		if _, err := io.ReadFull(rw.Reader, early); err != nil {
			return
		}
		if _, err := upConn.Write(early); err != nil {
			return
		}
	}

	if !isLoopbackTarget(host) {
		unregister := e.registerTunnel(clientConn, upConn)
		defer unregister()
	}

	pipe(clientConn, upConn)
}

// serveSOCKS5 handles SOCKS5 requests on Sysproxy.SOCKSListen.
func (e *Engine) serveSOCKS5(l net.Listener, stopCh <-chan struct{}) {
	defer e.wg.Done()
	var tempDelay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-stopCh:
				return
			default:
			}
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 1 * time.Second; tempDelay > max {
				tempDelay = max
			}
			select {
			case <-stopCh:
				return
			case <-time.After(tempDelay):
				continue
			}
		}
		tempDelay = 0
		go e.handleSOCKS5Conn(conn)
	}
}

func (e *Engine) handleSOCKS5Conn(clientConn net.Conn) {
	defer clientConn.Close()

	buf := make([]byte, 256)

	// 1. Version & Method negotiation
	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 { // SOCKS5 version
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(clientConn, buf[:nMethods]); err != nil {
		return
	}

	hasNoAuth := false
	for _, m := range buf[:nMethods] {
		if m == 0x00 { // 0x00: NO AUTHENTICATION REQUIRED
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		// RFC 1928: 0xFF = NO ACCEPTABLE METHODS
		_, _ = clientConn.Write([]byte{0x05, 0xFF})
		return
	}

	// Reply: version 5, method 0 (No Auth)
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Client Request (VER, CMD, RSV, ATYP, ADDR, PORT)
	if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	cmd := buf[1]
	atyp := buf[3]

	if cmd != 0x01 { // Only CONNECT is supported in sysproxy mode
		_, _ = clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var dstHost string
	var dstIP netip.Addr

	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
			return
		}
		dstIP = netip.AddrFrom4([4]byte(buf[:4]))
		dstHost = dstIP.String()
	case 0x03: // Domain name
		if _, err := io.ReadFull(clientConn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(clientConn, buf[:domainLen]); err != nil {
			return
		}
		dstHost = string(buf[:domainLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(clientConn, buf[:16]); err != nil {
			return
		}
		dstIP = netip.AddrFrom16([16]byte(buf[:16]))
		dstHost = dstIP.String()
	default:
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	// Read Port
	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(buf[:2]))

	ctx := context.Background()
	upConn, err := e.dialTarget(ctx, dstHost, port)
	if err != nil {
		_, _ = clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connection refused
		return
	}
	defer upConn.Close()

	// Success response: VER 5, REP 0, RSV 0, ATYP 1 (IPv4 0.0.0.0:0)
	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	if !isLoopbackTarget(dstHost) {
		unregister := e.registerTunnel(clientConn, upConn)
		defer unregister()
	}

	pipe(clientConn, upConn)
}

const halfCloseTimeout = 2 * time.Minute

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) error {
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func pipe(c1, c2 net.Conn) {
	var once sync.Once
	setHalfCloseDeadline := func() {
		once.Do(func() {
			now := time.Now()
			_ = c1.SetDeadline(now.Add(halfCloseTimeout))
			_ = c2.SetDeadline(now.Add(halfCloseTimeout))
		})
	}

	done := make(chan struct{}, 2)

	cp := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			// Write error or abnormal read error: peer is gone or broken.
			// Terminate opposite direction immediately.
			_ = c1.Close()
			_ = c2.Close()
		} else {
			// Clean EOF from src: close write side on dst so peer sees EOF.
			_ = closeWrite(dst)
			// Start half-close timer for remaining direction.
			setHalfCloseDeadline()
		}
		done <- struct{}{}
	}

	go cp(c1, c2)
	go cp(c2, c1)

	<-done
	<-done

	_ = c1.Close()
	_ = c2.Close()
}

func (e *Engine) registerTunnel(client, target net.Conn) func() {
	e.tunnelsMu.Lock()
	if e.tunnelsClosed {
		e.tunnelsMu.Unlock()
		_ = client.Close()
		_ = target.Close()
		return func() {}
	}
	if e.tunnels == nil {
		e.tunnels = make(map[*tunnelEntry]struct{})
	}
	entry := &tunnelEntry{client: client, target: target}
	e.tunnels[entry] = struct{}{}
	e.tunnelsWg.Add(1)
	e.tunnelsMu.Unlock()

	return func() {
		e.tunnelsMu.Lock()
		delete(e.tunnels, entry)
		e.tunnelsMu.Unlock()
		e.tunnelsWg.Done()
	}
}

func (e *Engine) closeTunnels() {
	e.tunnelsMu.Lock()
	e.tunnelsClosed = true
	conns := make([]net.Conn, 0, len(e.tunnels)*2)
	for entry := range e.tunnels {
		conns = append(conns, entry.client, entry.target)
	}
	e.tunnelsMu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}

	e.tunnelsWg.Wait()
}

// ActiveTunnels returns the number of currently active registered tunnels.
func (e *Engine) ActiveTunnels() int {
	e.tunnelsMu.Lock()
	defer e.tunnelsMu.Unlock()
	return len(e.tunnels)
}

// SetProbeParams overrides probe parameters for this Engine instance.
func (e *Engine) SetProbeParams(retries int, delay, timeout time.Duration) {
	if retries > 0 {
		e.probeRetries = retries
	}
	if delay > 0 {
		e.probeRetryDelay = delay
	}
	if timeout > 0 {
		e.probeTimeout = timeout
	}
}

// SetGlobalProbeParamsForTest sets default probe parameters for new engines in tests.
func SetGlobalProbeParamsForTest(retries int, delay, timeout time.Duration) func() {
	prevRetries := probeRetries
	prevDelay := probeRetryDelay
	prevTimeout := probeTimeout
	if retries > 0 {
		probeRetries = retries
	}
	if delay > 0 {
		probeRetryDelay = delay
	}
	if timeout > 0 {
		probeTimeout = timeout
	}
	return func() {
		probeRetries = prevRetries
		probeRetryDelay = prevDelay
		probeTimeout = prevTimeout
	}
}

// SetCheckProxy sets a custom check function on this Engine instance (used in tests to stub CheckProxy).
func (e *Engine) SetCheckProxy(fn func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error)) {
	e.checkProxyMu.Lock()
	defer e.checkProxyMu.Unlock()
	e.checkProxyFn = fn
}

func (e *Engine) doCheckProxy(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
	e.checkProxyMu.RLock()
	fn := e.checkProxyFn
	e.checkProxyMu.RUnlock()
	if fn != nil {
		return fn(ctx, host, port, timeout)
	}

	globalCheckProxyMu.RLock()
	gFn := globalCheckProxyFn
	globalCheckProxyMu.RUnlock()
	if gFn != nil {
		return gFn(ctx, host, port, timeout)
	}

	return CheckProxy(ctx, host, port, timeout)
}

// SetCheckProxyForTest allows tests to stub CheckProxy globally.
func SetCheckProxyForTest(fn func(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error)) func() {
	globalCheckProxyMu.Lock()
	prev := globalCheckProxyFn
	globalCheckProxyFn = fn
	globalCheckProxyMu.Unlock()
	return func() {
		globalCheckProxyMu.Lock()
		globalCheckProxyFn = prev
		globalCheckProxyMu.Unlock()
	}
}

// SetLocalNetworkDown overrides local network down check for this Engine instance.
func (e *Engine) SetLocalNetworkDown(fn func(lastErr error) bool) {
	e.netDownMu.Lock()
	defer e.netDownMu.Unlock()
	e.netDownFn = fn
}

func (e *Engine) isLocalNetworkDown(lastErr error) bool {
	e.netDownMu.RLock()
	fn := e.netDownFn
	e.netDownMu.RUnlock()
	if fn != nil {
		return fn(lastErr)
	}

	globalLocalNetworkDownMu.RLock()
	gFn := globalLocalNetworkDownFn
	globalLocalNetworkDownMu.RUnlock()
	if gFn != nil {
		return gFn(lastErr)
	}

	return localNetworkDown(lastErr)
}

// SetGlobalLocalNetworkDownForTest sets global local network down check for tests.
func SetGlobalLocalNetworkDownForTest(fn func(lastErr error) bool) func() {
	globalLocalNetworkDownMu.Lock()
	prev := globalLocalNetworkDownFn
	globalLocalNetworkDownFn = fn
	globalLocalNetworkDownMu.Unlock()
	return func() {
		globalLocalNetworkDownMu.Lock()
		globalLocalNetworkDownFn = prev
		globalLocalNetworkDownMu.Unlock()
	}
}
