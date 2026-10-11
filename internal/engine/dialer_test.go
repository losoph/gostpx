package engine

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestDirectDialerSOCKS5Domain(t *testing.T) {
	// Verify that SOCKS5 client passes domain name using ATYP=0x03 without local DNS resolution
	socksServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer socksServer.Close()

	var (
		receivedAtyp byte
		receivedHost string
		receivedPort int
	)

	go func() {
		conn, err := socksServer.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		// 1. Version negotiation: VER 5, NMETHODS 1, 0x00
		if _, err := io.ReadFull(conn, buf[:3]); err != nil {
			return
		}
		// Reply VER 5, METHOD 0x00
		_, _ = conn.Write([]byte{0x05, 0x00})

		// 2. Request: VER 5, CMD 1, RSV 0, ATYP
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		receivedAtyp = buf[3]
		if receivedAtyp == 0x03 {
			// Domain
			if _, err := io.ReadFull(conn, buf[:1]); err != nil {
				return
			}
			domainLen := int(buf[0])
			if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
				return
			}
			receivedHost = string(buf[:domainLen])
		}

		// Read port (2 bytes)
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return
		}
		receivedPort = int(binary.BigEndian.Uint16(buf[:2]))

		// Reply success: VER 5, REP 0, RSV 0, ATYP 1, 0.0.0.0:0
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

		// Echo test
		_, _ = io.Copy(conn, conn)
	}()

	proxyPort := socksServer.Addr().(*net.TCPAddr).Port
	dialer, err := NewDirectDialer(config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: proxyPort,
	}, "")
	if err != nil {
		t.Fatalf("NewDirectDialer error: %v", err)
	}

	targetDomain := "blocked-site-example.org"
	targetPort := 8443
	conn, err := dialer.DialTarget(context.Background(), targetDomain, targetPort)
	if err != nil {
		t.Fatalf("DialTarget error: %v", err)
	}
	defer conn.Close()

	if receivedAtyp != 0x03 {
		t.Errorf("expected ATYP 0x03 (domain name), got 0x%02x", receivedAtyp)
	}
	if receivedHost != targetDomain {
		t.Errorf("expected target domain %q, got %q", targetDomain, receivedHost)
	}
	if receivedPort != targetPort {
		t.Errorf("expected target port %d, got %d", targetPort, receivedPort)
	}

	// Verify data transmission
	msg := []byte("ping-pong")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write error: %v", err)
	}
	resp := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(resp) != string(msg) {
		t.Errorf("echo mismatch: got %q, want %q", string(resp), string(msg))
	}
}

func TestDirectDialerSOCKS5Auth(t *testing.T) {
	// Verify that SOCKS5 client correctly performs RFC 1929 username/password handshake
	socksServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer socksServer.Close()

	var (
		receivedUser string
		receivedPass string
	)

	go func() {
		conn, err := socksServer.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		// 1. Version negotiation: VER 5, NMETHODS 2, [0x00, 0x02]
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		// Server selects 0x02 (User/Pass)
		_, _ = conn.Write([]byte{0x05, 0x02})

		// 2. Auth: VER 1, ULEN, USER, PLEN, PASS
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return
		}
		uLen := int(buf[1])
		if _, err := io.ReadFull(conn, buf[:uLen]); err != nil {
			return
		}
		receivedUser = string(buf[:uLen])

		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		pLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:pLen]); err != nil {
			return
		}
		receivedPass = string(buf[:pLen])

		// Auth success: VER 1, STATUS 0
		_, _ = conn.Write([]byte{0x01, 0x00})

		// 3. Connect: VER 5, CMD 1, RSV 0, ATYP 1, 127.0.0.1:80
		if _, err := io.ReadFull(conn, buf[:10]); err != nil {
			return
		}
		// Connect success
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
	}()

	proxyPort := socksServer.Addr().(*net.TCPAddr).Port
	dialer, err := NewDirectDialer(config.ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: proxyPort,
		User: "myuser",
	}, "mypassword")
	if err != nil {
		t.Fatalf("NewDirectDialer error: %v", err)
	}

	conn, err := dialer.DialTarget(context.Background(), "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("DialTarget error: %v", err)
	}
	defer conn.Close()

	if receivedUser != "myuser" || receivedPass != "mypassword" {
		t.Errorf("auth mismatch: user=%q, pass=%q", receivedUser, receivedPass)
	}
}

func TestDirectDialerHTTPConnect(t *testing.T) {
	// Verify that HTTP CONNECT upstream sends Host and Proxy-Authorization headers
	httpProxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer httpProxy.Close()

	var (
		receivedMethod string
		receivedTarget string
		receivedAuth   string
	)

	go func() {
		conn, err := httpProxy.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		receivedMethod = req.Method
		receivedTarget = req.RequestURI
		receivedAuth = req.Header.Get("Proxy-Authorization")

		// Reply 200 Connection established
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		_, _ = io.Copy(conn, conn) // echo
	}()

	proxyPort := httpProxy.Addr().(*net.TCPAddr).Port
	dialer, err := NewDirectDialer(config.ProxyConfig{
		Type: "http",
		Host: "127.0.0.1",
		Port: proxyPort,
		User: "httpuser",
	}, "httppass")
	if err != nil {
		t.Fatalf("NewDirectDialer error: %v", err)
	}

	target := "api.upstream-domain.com"
	targetPort := 443
	conn, err := dialer.DialTarget(context.Background(), target, targetPort)
	if err != nil {
		t.Fatalf("DialTarget error: %v", err)
	}
	defer conn.Close()

	if receivedMethod != "CONNECT" {
		t.Errorf("expected method CONNECT, got %s", receivedMethod)
	}
	expectedTarget := fmt.Sprintf("%s:%d", target, targetPort)
	if receivedTarget != expectedTarget {
		t.Errorf("expected target %s, got %s", expectedTarget, receivedTarget)
	}
	if receivedAuth == "" {
		t.Error("expected Proxy-Authorization header, got empty")
	}

	// Verify tunnel communication
	if _, err := conn.Write([]byte("hello-tunnel")); err != nil {
		t.Fatalf("write error: %v", err)
	}
	respBuf := make([]byte, 12)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(respBuf) != "hello-tunnel" {
		t.Errorf("tunnel echo mismatch: got %q", string(respBuf))
	}
}

type directTCPIPPayload struct {
	Addr       string
	Rport      uint32
	Originator string
	Oport      uint32
}

func startTestSSHServer(t *testing.T, expectedUser, expectedPass string) (net.Listener, *ssh.ServerConfig, ssh.PublicKey) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == expectedUser && string(password) == expectedPass {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for user %q", conn.User())
		},
	}
	sshConfig.AddHostKey(signer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}

	return l, sshConfig, signer.PublicKey()
}

func TestDirectDialerSSHDomainAndEcho(t *testing.T) {
	l, sshConfig, pubKey := startTestSSHServer(t, "sshuser", "sshpass")
	defer l.Close()

	var (
		receivedHost string
		receivedPort uint32
	)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		sConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
		if err != nil {
			return
		}
		defer sConn.Close()
		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "direct-tcpip" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel")
				continue
			}
			var p directTCPIPPayload
			if err := ssh.Unmarshal(newChannel.ExtraData(), &p); err != nil {
				_ = newChannel.Reject(ssh.ConnectionFailed, "bad extra data")
				continue
			}
			receivedHost = p.Addr
			receivedPort = p.Rport

			channel, requests, err := newChannel.Accept()
			if err != nil {
				return
			}
			go ssh.DiscardRequests(requests)
			go func(c ssh.Channel) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}(channel)
		}
	}()

	// Setup temporary known_hosts file
	tmpDir := t.TempDir()
	khFile := filepath.Join(tmpDir, "known_hosts")
	khLine := knownhosts.Line([]string{l.Addr().String()}, pubKey)
	if err := os.WriteFile(khFile, []byte(khLine+"\n"), 0600); err != nil {
		t.Fatalf("write known_hosts error: %v", err)
	}

	proxyPort := l.Addr().(*net.TCPAddr).Port
	dialer, err := NewDirectDialer(config.ProxyConfig{
		Type: "ssh",
		Host: "127.0.0.1",
		Port: proxyPort,
		User: "sshuser",
	}, "sshpass")
	if err != nil {
		t.Fatalf("NewDirectDialer error: %v", err)
	}
	dialer.knownHostsFile = khFile
	defer dialer.Close()

	targetDomain := "internal.service.lan"
	targetPort := 9090
	conn, err := dialer.DialTarget(context.Background(), targetDomain, targetPort)
	if err != nil {
		t.Fatalf("DialTarget error: %v", err)
	}
	defer conn.Close()

	// Verify domain was passed as-is to SSH server (no local DNS resolution)
	if receivedHost != targetDomain {
		t.Errorf("expected SSH server to receive host %q, got %q", targetDomain, receivedHost)
	}
	if int(receivedPort) != targetPort {
		t.Errorf("expected SSH server to receive port %d, got %d", targetPort, receivedPort)
	}

	// Verify data transmission through SSH tunnel
	msg := []byte("ssh tunnel echo test\n")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("conn write error: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("conn read error: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("got %q, want %q", string(buf), string(msg))
	}
}

func TestDirectDialerSSHKnownHostsRejection(t *testing.T) {
	l, sshConfig, _ := startTestSSHServer(t, "sshuser", "sshpass")
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _, _ = ssh.NewServerConn(conn, sshConfig)
	}()

	// Create empty known_hosts file (host key not found)
	tmpDir := t.TempDir()
	khFile := filepath.Join(tmpDir, "known_hosts")
	if err := os.WriteFile(khFile, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts error: %v", err)
	}

	proxyPort := l.Addr().(*net.TCPAddr).Port
	dialer, err := NewDirectDialer(config.ProxyConfig{
		Type: "ssh",
		Host: "127.0.0.1",
		Port: proxyPort,
		User: "sshuser",
	}, "sshpass")
	if err != nil {
		t.Fatalf("NewDirectDialer error: %v", err)
	}
	dialer.knownHostsFile = khFile
	defer dialer.Close()

	_, err = dialer.DialTarget(context.Background(), "example.com", 80)
	if err == nil {
		t.Fatal("expected error due to unknown host key, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "не найден в known_hosts") {
		t.Errorf("expected error to contain 'не найден в known_hosts', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "подключитесь к серверу через 'ssh") {
		t.Errorf("expected error to contain hint 'подключитесь к серверу через 'ssh', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "один раз, чтобы ключ попал в known_hosts") {
		t.Errorf("expected error to contain 'один раз, чтобы ключ попал в known_hosts', got: %s", errMsg)
	}
}

func TestDirectDialerSSHBrokenConnectionRetry(t *testing.T) {
	l, sshConfig, pubKey := startTestSSHServer(t, "sshuser", "sshpass")
	defer l.Close()

	var firstConn net.Conn
	var firstConnCloseCh = make(chan struct{})

	go func() {
		// First connection
		c1, err := l.Accept()
		if err != nil {
			return
		}
		firstConn = c1
		sConn1, chans1, reqs1, err := ssh.NewServerConn(c1, sshConfig)
		if err != nil {
			c1.Close()
			return
		}
		go ssh.DiscardRequests(reqs1)
		go func() {
			for newChannel := range chans1 {
				ch, reqs, err := newChannel.Accept()
				if err != nil {
					continue
				}
				go ssh.DiscardRequests(reqs)
				go func(c ssh.Channel) {
					defer c.Close()
					_, _ = io.Copy(c, c)
				}(ch)
			}
		}()

		<-firstConnCloseCh
		_ = sConn1.Close()
		_ = firstConn.Close()

		// Second connection (after retry)
		c2, err := l.Accept()
		if err != nil {
			return
		}
		defer c2.Close()
		sConn2, chans2, reqs2, err := ssh.NewServerConn(c2, sshConfig)
		if err != nil {
			return
		}
		defer sConn2.Close()
		go ssh.DiscardRequests(reqs2)
		for newChannel := range chans2 {
			ch, reqs, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func(c ssh.Channel) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(ch)
		}
	}()

	tmpDir := t.TempDir()
	khFile := filepath.Join(tmpDir, "known_hosts")
	khLine := knownhosts.Line([]string{l.Addr().String()}, pubKey)
	if err := os.WriteFile(khFile, []byte(khLine+"\n"), 0600); err != nil {
		t.Fatalf("write known_hosts error: %v", err)
	}

	proxyPort := l.Addr().(*net.TCPAddr).Port
	dialer, err := NewDirectDialer(config.ProxyConfig{
		Type: "ssh",
		Host: "127.0.0.1",
		Port: proxyPort,
		User: "sshuser",
	}, "sshpass")
	if err != nil {
		t.Fatalf("NewDirectDialer error: %v", err)
	}
	dialer.knownHostsFile = khFile
	defer dialer.Close()

	// 1. First dial succeeds on established connection
	conn1, err := dialer.DialTarget(context.Background(), "first.lan", 80)
	if err != nil {
		t.Fatalf("first DialTarget error: %v", err)
	}
	_ = conn1.Close()

	// 2. Break the first connection from server side
	close(firstConnCloseCh)
	time.Sleep(50 * time.Millisecond)

	// 3. Second dial on already established connection should detect failure, reset client and retry once
	conn2, err := dialer.DialTarget(context.Background(), "second.lan", 80)
	if err != nil {
		t.Fatalf("second DialTarget (with retry) failed: %v", err)
	}
	defer conn2.Close()

	msg := []byte("ping after reconnect")
	if _, err := conn2.Write(msg); err != nil {
		t.Fatalf("write after reconnect error: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn2, buf); err != nil {
		t.Fatalf("read after reconnect error: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("got %q, want %q", string(buf), string(msg))
	}
}
