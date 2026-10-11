package engine

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type credentialsRejectedErr struct {
	msg string
}

func (e *credentialsRejectedErr) Error() string {
	return e.msg
}

func (e *credentialsRejectedErr) Is(target error) bool {
	return target == ErrCredentialsRejected || target == ErrAuthFailed
}

type protocolMismatchErr struct {
	msg string
}

func (e *protocolMismatchErr) Error() string {
	return e.msg
}

func (e *protocolMismatchErr) Is(target error) bool {
	return target == ErrProtocolMismatch || target == ErrInvalidProtocol
}

var (
	// ErrUpstreamUnreachable indicates TCP connection to the proxy host/port failed.
	ErrUpstreamUnreachable = errors.New("прокси-сервер недоступен")

	// ErrAuthFailed indicates proxy rejected authentication credentials or method.
	ErrAuthFailed = errors.New("отказ в авторизации на прокси")

	// ErrCredentialsRejected indicates proxy rejected authentication credentials specifically
	// (SOCKS5 subnegotiation auth failure, SOCKS5 0xFF, HTTP 407). It matches ErrAuthFailed as well.
	ErrCredentialsRejected error = &credentialsRejectedErr{msg: "прокси отклонил логин или пароль"}

	// ErrInvalidProtocol indicates the upstream does not speak the expected proxy protocol.
	ErrInvalidProtocol = errors.New("неверный протокол прокси")

	// ErrProtocolMismatch indicates the upstream proxy responded with a recognized protocol
	// different from the configured one (e.g. HTTP instead of SOCKS5). It matches ErrInvalidProtocol as well.
	ErrProtocolMismatch error = &protocolMismatchErr{msg: "выбран неверный протокол прокси"}

	// ErrTargetUnreachable indicates the upstream proxy failed to connect to the target.
	ErrTargetUnreachable = errors.New("прокси не смог соединиться с контрольным узлом")
)

// TargetDialer dials a destination host and port through an upstream proxy.
type TargetDialer interface {
	DialTarget(ctx context.Context, host string, port int) (net.Conn, error)
	Close() error
}

// DirectDialer connects to an upstream SOCKS5, HTTP, or SSH proxy and tunnels to target host:port.
// Resolves hostnames on the remote proxy server (no local DNS leak in sysproxy mode).
type DirectDialer struct {
	proxyType      string
	proxyAddr      string
	proxyHost      string
	user           string
	password       string
	timeout        time.Duration
	knownHostsFile string // optional override for tests; defaults to ~/.ssh/known_hosts

	mu        sync.Mutex
	sshClient *ssh.Client
}

// NewDirectDialer creates a new TargetDialer for SOCKS5, HTTP, or SSH upstream.
func NewDirectDialer(cfg config.ProxyConfig, plainSecret string) (*DirectDialer, error) {
	if cfg.Host == "" || cfg.Port <= 0 {
		return nil, errors.New("upstream proxy host and port required")
	}
	switch cfg.Type {
	case config.ProxyTypeSOCKS5, config.ProxyTypeHTTP, config.ProxyTypeSSH:
		// ok
	default:
		return nil, fmt.Errorf("unsupported direct dialer proxy type %q", cfg.Type)
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	return &DirectDialer{
		proxyType: cfg.Type,
		proxyAddr: addr,
		proxyHost: cfg.Host,
		user:      cfg.User,
		password:  plainSecret,
		timeout:   10 * time.Second,
	}, nil
}

func (d *DirectDialer) DialTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	switch d.proxyType {
	case "socks5":
		dialer := net.Dialer{
			Timeout: d.timeout,
		}
		conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("%w (%s): %v", ErrUpstreamUnreachable, d.proxyAddr, err)
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		} else if d.timeout > 0 {
			_ = conn.SetDeadline(time.Now().Add(d.timeout))
		}
		if err := d.handshakeSOCKS5(conn, host, port); err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil

	case "http":
		dialer := net.Dialer{
			Timeout: d.timeout,
		}
		conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("%w (%s): %v", ErrUpstreamUnreachable, d.proxyAddr, err)
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		} else if d.timeout > 0 {
			_ = conn.SetDeadline(time.Now().Add(d.timeout))
		}
		bufferedConn, err := d.handshakeHTTP(conn, host, port)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return bufferedConn, nil

	case "ssh":
		return d.dialSSH(ctx, host, port)

	default:
		return nil, fmt.Errorf("unsupported direct dialer proxy type %q", d.proxyType)
	}
}

func (d *DirectDialer) dialSSH(ctx context.Context, host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))

	d.mu.Lock()
	client := d.sshClient
	wasEstablished := (client != nil)
	d.mu.Unlock()

	var err error
	if client == nil {
		client, err = d.getOrCreateSSHClient(ctx)
		if err != nil {
			return nil, err
		}
	}

	conn, err := client.DialContext(ctx, "tcp", target)
	if err != nil && wasEstablished {
		// Connection failed on an already established client: reset and retry once
		d.resetSSHClient(client)

		var newClient *ssh.Client
		newClient, err = d.getOrCreateSSHClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("ssh reconnect %s: %w", d.proxyAddr, err)
		}
		conn, err = newClient.DialContext(ctx, "tcp", target)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: ssh dial target %s: %v", ErrTargetUnreachable, target, err)
	}
	return conn, nil
}

func (d *DirectDialer) getOrCreateSSHClient(ctx context.Context) (*ssh.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sshClient != nil {
		return d.sshClient, nil
	}

	client, err := d.connectSSH(ctx)
	if err != nil {
		return nil, err
	}
	d.sshClient = client
	return client, nil
}

func (d *DirectDialer) resetSSHClient(c *ssh.Client) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sshClient == c {
		d.sshClient = nil
		if c != nil {
			_ = c.Close()
		}
	}
}

func (d *DirectDialer) getKnownHostsCallback() (ssh.HostKeyCallback, error) {
	khPath := d.knownHostsFile
	if khPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("ошибка определения домашней директории для known_hosts: %w", err)
		}
		khPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	khCallback, err := knownhosts.New(khPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("файл known_hosts не найден (%s): подключитесь к серверу через 'ssh %s' один раз, чтобы ключ попал в known_hosts: %w", khPath, d.proxyHost, err)
		}
		return nil, fmt.Errorf("чтение known_hosts (%s): %w", khPath, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := khCallback(hostname, remote, key); err != nil {
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) {
				if len(keyErr.Want) == 0 {
					return fmt.Errorf("хост %s не найден в known_hosts (%s): подключитесь к серверу через 'ssh %s' один раз, чтобы ключ попал в known_hosts: %w", hostname, khPath, d.proxyHost, err)
				}
				return fmt.Errorf("ключ хоста %s не совпадает с записью в %s (возможна атака MITM): %w", hostname, khPath, err)
			}
			return err
		}
		return nil
	}, nil
}

func (d *DirectDialer) connectSSH(ctx context.Context) (*ssh.Client, error) {
	hkCallback, err := d.getKnownHostsCallback()
	if err != nil {
		return nil, err
	}

	sshConfig := &ssh.ClientConfig{
		User: d.user,
		Auth: []ssh.AuthMethod{
			ssh.Password(d.password),
		},
		HostKeyCallback: hkCallback,
		Timeout:         d.timeout,
	}

	dialer := net.Dialer{
		Timeout: d.timeout,
	}
	conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %v", ErrUpstreamUnreachable, d.proxyAddr, err)
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, d.proxyAddr, sshConfig)
	if err != nil {
		_ = conn.Close()
		errMsg := err.Error()
		if strings.Contains(errMsg, "unable to authenticate") || strings.Contains(errMsg, "auth failed") {
			return nil, fmt.Errorf("%w: %w: ssh авторизация не удалась: %v", ErrAuthFailed, ErrCredentialsRejected, err)
		}
		if strings.Contains(errMsg, "known_hosts") || strings.Contains(errMsg, "knownhosts") {
			return nil, err
		}
		return nil, fmt.Errorf("%w: ssh рукопожатие не удалось: %v", ErrInvalidProtocol, err)
	}

	return ssh.NewClient(ncc, chans, reqs), nil
}

// Close closes the SSH client connection if open.
func (d *DirectDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sshClient != nil {
		err := d.sshClient.Close()
		d.sshClient = nil
		return err
	}
	return nil
}

func (d *DirectDialer) handshakeSOCKS5(conn net.Conn, host string, port int) error {
	// 1. Version & Method negotiation
	var greeting []byte
	if d.user != "" || d.password != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02} // 0x00: No Auth, 0x02: User/Pass
	} else {
		greeting = []byte{0x05, 0x01, 0x00} // 0x00: No Auth
	}

	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("%w: ошибка отправки приветствия SOCKS5: %v", ErrInvalidProtocol, err)
	}

	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodReply); err != nil {
		return fmt.Errorf("%w: ошибка чтения ответа SOCKS5: %v", ErrInvalidProtocol, err)
	}
	if methodReply[0] != 0x05 {
		return fmt.Errorf("%w: сервер ответил версией 0x%02x вместо SOCKS5 (0x05)", ErrInvalidProtocol, methodReply[0])
	}

	switch methodReply[1] {
	case 0x00:
		// No authentication required
	case 0x02:
		// Username/Password authentication (RFC 1929)
		uLen := len(d.user)
		pLen := len(d.password)
		if uLen > 255 || pLen > 255 {
			return errors.New("socks5 username or password exceeds 255 bytes")
		}
		authReq := make([]byte, 0, 3+uLen+pLen)
		authReq = append(authReq, 0x01, byte(uLen))
		authReq = append(authReq, []byte(d.user)...)
		authReq = append(authReq, byte(pLen))
		authReq = append(authReq, []byte(d.password)...)

		if _, err := conn.Write(authReq); err != nil {
			return fmt.Errorf("%w: ошибка отправки учётных данных SOCKS5: %v", ErrAuthFailed, err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("%w: ошибка чтения ответа авторизации SOCKS5: %v", ErrInvalidProtocol, err)
		}
		if authResp[0] != 0x01 {
			return fmt.Errorf("%w: неверная версия ответа субсогласования авторизации SOCKS5: 0x%02x", ErrInvalidProtocol, authResp[0])
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("%w: %w: неверный логин или пароль (код отказа 0x%02x)", ErrAuthFailed, ErrCredentialsRejected, authResp[1])
		}
	case 0xFF:
		return fmt.Errorf("%w: %w: прокси требует аутентификацию (код 0xFF, нет подходящего метода)", ErrAuthFailed, ErrCredentialsRejected)
	default:
		return fmt.Errorf("%w: %w: прокси отклонил метод аутентификации (код 0x%02x)", ErrAuthFailed, ErrCredentialsRejected, methodReply[1])
	}

	// 2. SOCKS5 CONNECT Request
	// VER 5, CMD 1 (CONNECT), RSV 0, ATYP
	req := []byte{0x05, 0x01, 0x00}

	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			req = append(req, 0x01)
			req = append(req, ip.AsSlice()...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.AsSlice()...)
		}
	} else {
		// Domain name (ATYP = 0x03) - remote DNS resolution!
		hLen := len(host)
		if hLen > 255 {
			return fmt.Errorf("host length %d exceeds 255 bytes", hLen)
		}
		req = append(req, 0x03, byte(hLen))
		req = append(req, []byte(host)...)
	}

	portBytes := []byte{byte(port >> 8), byte(port & 0xFF)}
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("%w: ошибка отправки запроса SOCKS5 CONNECT: %v", ErrTargetUnreachable, err)
	}

	// 3. SOCKS5 CONNECT Response
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return fmt.Errorf("%w: ошибка чтения ответа SOCKS5 CONNECT: %v", ErrInvalidProtocol, err)
	}
	if respHeader[0] != 0x05 {
		return fmt.Errorf("%w: неверная версия ответа SOCKS5 CONNECT: 0x%02x", ErrInvalidProtocol, respHeader[0])
	}
	if respHeader[1] != 0x00 {
		return socks5ConnectReplyError(respHeader[1])
	}

	// Read remaining bound address bytes according to ATYP
	switch respHeader[3] {
	case 0x01: // IPv4 (4 bytes) + port (2 bytes)
		discard := make([]byte, 6)
		if _, err := io.ReadFull(conn, discard); err != nil {
			return fmt.Errorf("%w: ошибка чтения bnd.addr: %v", ErrInvalidProtocol, err)
		}
	case 0x03: // Domain (1 byte len + N bytes) + port (2 bytes)
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("%w: ошибка чтения bnd.addr len: %v", ErrInvalidProtocol, err)
		}
		discard := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, discard); err != nil {
			return fmt.Errorf("%w: ошибка чтения bnd.addr domain: %v", ErrInvalidProtocol, err)
		}
	case 0x04: // IPv6 (16 bytes) + port (2 bytes)
		discard := make([]byte, 18)
		if _, err := io.ReadFull(conn, discard); err != nil {
			return fmt.Errorf("%w: ошибка чтения bnd.addr ipv6: %v", ErrInvalidProtocol, err)
		}
	default:
		return fmt.Errorf("%w: неизвестный тип адреса SOCKS5 bnd.addr (0x%02x)", ErrInvalidProtocol, respHeader[3])
	}

	return nil
}

func (d *DirectDialer) handshakeHTTP(conn net.Conn, host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if d.user != "" || d.password != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(d.user + ":" + d.password))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", cred)
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("%w: ошибка отправки HTTP CONNECT: %v", ErrTargetUnreachable, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("%w: сервер не ответил корректным HTTP-ответом: %v", ErrInvalidProtocol, err)
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return nil, fmt.Errorf("%w: %w: HTTP 407 Proxy Authentication Required (требуется авторизация или неверный логин/пароль)", ErrAuthFailed, ErrCredentialsRejected)
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: HTTP 403 Forbidden (доступ к прокси запрещён)", ErrAuthFailed)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: прокси вернул статус %s", ErrTargetUnreachable, resp.Status)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{
			Conn: conn,
			r:    io.MultiReader(br, conn),
		}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// socks5ConnectReplyError decodes RFC 1928 SOCKS5 reply codes.
// Specifically, code 0x02 is wrapped as ErrAuthFailed per D2 (as many upstreams reject
// invalid credentials during CONNECT rather than during initial handshake).
func socks5ConnectReplyError(code byte) error {
	switch code {
	case 0x01:
		return fmt.Errorf("%w: общий сбой сервера (0x01)", ErrTargetUnreachable)
	case 0x02:
		return fmt.Errorf("%w: соединение запрещено правилами прокси (0x02) — проверьте логин и пароль", ErrAuthFailed)
	case 0x03:
		return fmt.Errorf("%w: сеть недоступна (0x03)", ErrTargetUnreachable)
	case 0x04:
		return fmt.Errorf("%w: узел недоступен (0x04)", ErrTargetUnreachable)
	case 0x05:
		return fmt.Errorf("%w: соединение отклонено (0x05)", ErrTargetUnreachable)
	case 0x06:
		return fmt.Errorf("%w: истёк TTL (0x06)", ErrTargetUnreachable)
	case 0x07:
		return fmt.Errorf("%w: команда не поддерживается (0x07)", ErrTargetUnreachable)
	case 0x08:
		return fmt.Errorf("%w: тип адреса не поддерживается (0x08)", ErrTargetUnreachable)
	default:
		return fmt.Errorf("%w: SOCKS5 ошибка соединения с целевым узлом (код 0x%02x)", ErrTargetUnreachable, code)
	}
}
