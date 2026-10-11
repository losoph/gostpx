package testupstream

import (
	"io"
	"net"
	"testing"
)

func TestSOCKS5Server(t *testing.T) {
	srv, err := Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Close()

	if srv.Port() <= 0 {
		t.Errorf("invalid port: %d", srv.Port())
	}

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// 1. Version negotiation
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write version: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read version reply: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected version reply: %x", resp)
	}

	// 2. CONNECT to 127.0.0.1:80 (IPv4)
	req := []byte{
		0x05, 0x01, 0x00, 0x01,
		127, 0, 0, 1,
		0x00, 0x50,
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect req: %v", err)
	}
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, connResp); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if connResp[0] != 0x05 || connResp[1] != 0x00 {
		t.Fatalf("unexpected connect reply: %x", connResp)
	}

	// 3. Echo test
	payload := []byte("hello upstream")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("expected %q, got %q", string(payload), string(echo))
	}
}
