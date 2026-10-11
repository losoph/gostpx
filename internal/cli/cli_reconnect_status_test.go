package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/state"
)

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestCLI_Status_NetworkDown(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "1.2.3.4"
	cfg.Proxy.Port = 1080

	st := state.DefaultState()
	st.ActiveSession = true
	st.PID = os.Getpid()
	st.NetworkDown = true

	out := captureStdout(func() {
		printTextStatus(true, cfg, st, "", "", " 10 ms")
	})

	if !strings.Contains(out, "Сеть: нет локального подключения (ожидание)") {
		t.Errorf("expected output to contain 'Сеть: нет локального подключения (ожидание)', got:\n%s", out)
	}
}

func TestCLI_Status_Reconnecting(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "1.2.3.4"
	cfg.Proxy.Port = 1080

	st := state.DefaultState()
	st.ActiveSession = false
	st.PID = os.Getpid()
	st.Reconnecting = true
	st.ReconnectAttempt = 2
	st.NextReconnect = time.Now().Add(15 * time.Second)
	st.LastDisconnectReason = "upstream timeout"

	out := captureStdout(func() {
		printTextStatus(false, cfg, st, "", "", "")
	})

	if !strings.Contains(out, "Переподключение: попытка 2") {
		t.Errorf("expected output to contain 'Переподключение: попытка 2', got:\n%s", out)
	}
	if !strings.Contains(out, "причина: upstream timeout") {
		t.Errorf("expected output to contain reason, got:\n%s", out)
	}
}

func TestCLI_Status_JSON(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "1.2.3.4"
	cfg.Proxy.Port = 1080

	st := state.DefaultState()
	st.ActiveSession = false
	st.PID = os.Getpid()
	st.Reconnecting = true
	st.ReconnectAttempt = 3
	st.NextReconnect = time.Now().Add(25 * time.Second).Truncate(time.Second)
	st.LastDisconnectReason = "probe failure"

	out := captureStdout(func() {
		_ = printJSONStatus(false, cfg, st, "", "")
	})

	var sj statusJSON
	if err := json.Unmarshal([]byte(out), &sj); err != nil {
		t.Fatalf("failed to parse JSON status: %v\nOutput was: %s", err, out)
	}

	if sj.State != "reconnecting" {
		t.Errorf("expected state 'reconnecting', got %q", sj.State)
	}
	if !sj.Reconnecting {
		t.Errorf("expected Reconnecting=true")
	}
	if sj.ReconnectAttempt != 3 {
		t.Errorf("expected ReconnectAttempt=3, got %d", sj.ReconnectAttempt)
	}
	if sj.NextReconnect == "" {
		t.Errorf("expected NextReconnect non-empty RFC3339 string")
	}
	if sj.Reason != "probe failure" {
		t.Errorf("expected Reason 'probe failure', got %q", sj.Reason)
	}
}
