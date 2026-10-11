package testupstream

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Options defines configuration for testupstream Server.
type Options struct {
	Type     string // "socks5" (default) or "http"
	Username string
	Password string
}

// Server is a lightweight in-memory SOCKS5 or HTTP proxy server for testing.
type Server struct {
	l         net.Listener
	addr      string
	port      int
	quit      chan struct{}
	wg        sync.WaitGroup
	once      sync.Once
	proxyType string
	username  string
	password  string
}

// Start launches a minimal no-auth SOCKS5 server on a random free port on 127.0.0.1.
func Start() (*Server, error) {
	return StartWithOptions(Options{Type: "socks5"})
}

// StartWithOptions launches a mock SOCKS5 or HTTP proxy server with optional credentials.
func StartWithOptions(opts Options) (*Server, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen testupstream: %w", err)
	}
	pType := opts.Type
	if pType == "" {
		pType = "socks5"
	}
	s := &Server{
		l:         l,
		addr:      l.Addr().String(),
		port:      l.Addr().(*net.TCPAddr).Port,
		quit:      make(chan struct{}),
		proxyType: pType,
		username:  opts.Username,
		password:  opts.Password,
	}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr returns the "127.0.0.1:port" string.
func (s *Server) Addr() string {
	return s.addr
}

// Port returns the listening TCP port.
func (s *Server) Port() int {
	return s.port
}

// Close stops the server and closes all listeners.
func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		close(s.quit)
		err = s.l.Close()
	})
	s.wg.Wait()
	return err
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.l.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				return
			}
		}
		if s.proxyType == "http" {
			go s.handleHTTPConn(conn)
		} else {
			go s.handleSOCKS5Conn(conn)
		}
	}
}

func (s *Server) handleHTTPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	peek, err := br.Peek(1)
	if err != nil || len(peek) == 0 || peek[0] < 0x20 || peek[0] > 0x7E {
		return
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if s.username != "" || s.password != "" {
		auth := req.Header.Get("Proxy-Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.username+":"+s.password))
		if auth != expected {
			resp := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"testupstream\"\r\nContent-Length: 0\r\n\r\n"
			_, _ = conn.Write([]byte(resp))
			return
		}
	}

	if req.Method == http.MethodConnect {
		resp := "HTTP/1.1 200 Connection established\r\n\r\n"
		if _, err := conn.Write([]byte(resp)); err != nil {
			return
		}
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_, _ = conn.Write(buf[:n])
		}
	}

	// Plain HTTP response
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\n127.0.0.1"
	_, _ = conn.Write([]byte(resp))
}

func (s *Server) handleSOCKS5Conn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)

	// 1. Version negotiation: VER 5, NMETHODS, METHODS...
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	if nmethods <= 0 {
		return
	}
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return
	}

	hasAuthMethod := false
	hasNoAuth := false
	for _, m := range buf[:nmethods] {
		if m == 0x02 {
			hasAuthMethod = true
		}
		if m == 0x00 {
			hasNoAuth = true
		}
	}

	if s.username != "" || s.password != "" {
		if !hasAuthMethod {
			// RFC 1928: 0xFF = No acceptable methods
			_, _ = conn.Write([]byte{0x05, 0xFF})
			return
		}
		// Select method 0x02 (Username/Password)
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}

		// RFC 1929 subnegotiation:
		// VER 0x01, ULEN, USER, PLEN, PASS
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return
		}
		if buf[0] != 0x01 {
			return
		}
		ulen := int(buf[1])
		if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
			return
		}
		user := string(buf[:ulen])

		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		plen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
			return
		}
		pass := string(buf[:plen])

		if user != s.username || pass != s.password {
			// Auth failed: status 0x01
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		// Auth success: status 0x00
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else {
		if !hasNoAuth {
			_, _ = conn.Write([]byte{0x05, 0xFF})
			return
		}
		// Method 0x00 (No auth)
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}

	// 2. Request: VER 5, CMD, RSV 0x00, ATYP, ADDR, PORT
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	atyp := buf[3]
	switch atyp {
	case 0x01: // IPv4 (4 bytes)
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
	case 0x03: // Domain name
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return
		}
	case 0x04: // IPv6 (16 bytes)
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
	default:
		return
	}
	// Port (2 bytes)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}

	// Reply: VER 5, REP 0 (Success), RSV 0, ATYP 1 (IPv4), BND.ADDR 0.0.0.0, BND.PORT 0
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Read initial data (if any)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if n >= 4 && string(buf[:4]) == "GET " {
		resp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\n127.0.0.1"
		_, _ = conn.Write([]byte(resp))
		return
	}
	_, _ = conn.Write(buf[:n])
	_, _ = io.Copy(conn, conn)
}
