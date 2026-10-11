package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/session"
	"github.com/losoph/gostpx/internal/state"
)

func TestHandleOnEvent(t *testing.T) {
	now := time.Date(2026, 9, 29, 15, 4, 5, 0, time.Local)

	tests := []struct {
		name         string
		evt          session.Event
		phase        session.Phase
		wantAction   OnEventAction
		wantContains string
	}{
		{
			name: "EventDisconnected with PhaseReconnecting continues and prints reconnecting",
			evt: session.Event{
				Type:   session.EventDisconnected,
				Reason: "upstream connection dropped",
			},
			phase:        session.PhaseReconnecting,
			wantAction:   OnActionContinue,
			wantContains: "○ обрыв: upstream connection dropped — переподключение…",
		},
		{
			name: "EventDisconnected with PhaseNetworkDown continues and prints reconnecting",
			evt: session.Event{
				Type:   session.EventDisconnected,
				Reason: "no network route",
			},
			phase:        session.PhaseNetworkDown,
			wantAction:   OnActionContinue,
			wantContains: "🟡 нет сети…",
		},
		{
			name: "EventDisconnected with PhaseOff exits and prints direct connection",
			evt: session.Event{
				Type:   session.EventDisconnected,
				Reason: "stopped by user",
			},
			phase:        session.PhaseOff,
			wantAction:   OnActionExit,
			wantContains: "○ прямое подключение        причина: stopped by user",
		},
		{
			name: "EventReconnected continues and prints restored time",
			evt: session.Event{
				Type:   session.EventReconnected,
				Reason: "reconnected",
			},
			phase:        session.PhaseConnected,
			wantAction:   OnActionContinue,
			wantContains: "● восстановлено 15:04:05",
		},
		{
			name: "EventNetworkDown continues and prints no network",
			evt: session.Event{
				Type:   session.EventNetworkDown,
				Reason: "interface down",
			},
			phase:        session.PhaseNetworkDown,
			wantAction:   OnActionContinue,
			wantContains: "🟡 нет сети…",
		},
		{
			name: "EventNetworkUp continues and prints restored",
			evt: session.Event{
				Type:   session.EventNetworkUp,
				Reason: "interface up",
			},
			phase:        session.PhaseConnected,
			wantAction:   OnActionContinue,
			wantContains: "● восстановлено 15:04:05",
		},
		{
			name: "EventConnected continues",
			evt: session.Event{
				Type: session.EventConnected,
			},
			phase:        session.PhaseConnected,
			wantAction:   OnActionContinue,
			wantContains: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			action, msg := HandleOnEvent(tc.evt, tc.phase, now)
			if action != tc.wantAction {
				t.Fatalf("HandleOnEvent() action = %v, want %v", action, tc.wantAction)
			}
			if tc.wantContains != "" && !strings.Contains(msg, tc.wantContains) {
				t.Fatalf("HandleOnEvent() msg = %q, want substring %q", msg, tc.wantContains)
			}
		})
	}
}

func TestCLI_Status_DeadPID(t *testing.T) {
	deadPID := 99999999
	if session.IsPIDAlive(deadPID) {
		t.Skipf("PID %d surprisingly alive, skipping test", deadPID)
	}

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "1.2.3.4"
	cfg.Proxy.Port = 1080

	st := state.DefaultState()
	st.ActiveSession = false
	st.PID = deadPID
	st.Reconnecting = true
	st.NetworkDown = true
	st.ReconnectAttempt = 3
	st.NextReconnect = time.Now().Add(25 * time.Second)
	st.LastDisconnectReason = "remote host unreachable"

	// 1. Text status should print "○ прямое подключение", not "Переподключение" or "нет сети"
	out := captureStdout(func() {
		printTextStatus(false, cfg, st, "", "", "")
	})

	if !strings.Contains(out, "○ прямое подключение") {
		t.Errorf("expected text status to contain '○ прямое подключение', got:\n%s", out)
	}
	if strings.Contains(out, "Переподключение:") {
		t.Errorf("expected text status NOT to contain 'Переподключение:', got:\n%s", out)
	}
	if strings.Contains(out, "Сеть: нет локального подключения") {
		t.Errorf("expected text status NOT to contain 'Сеть: нет локального подключения', got:\n%s", out)
	}
	if !strings.Contains(out, "причина: remote host unreachable") {
		t.Errorf("expected text status to contain disconnect reason, got:\n%s", out)
	}

	// 2. JSON status should show state="disconnected", Reconnecting=false, NetworkDown=false
	jsonOut := captureStdout(func() {
		_ = printJSONStatus(false, cfg, st, "", "")
	})

	var sj statusJSON
	if err := json.Unmarshal([]byte(jsonOut), &sj); err != nil {
		t.Fatalf("failed to unmarshal JSON status: %v, output was:\n%s", err, jsonOut)
	}

	if sj.State != "disconnected" {
		t.Errorf("expected JSON State 'disconnected', got %q", sj.State)
	}
	if sj.Reconnecting {
		t.Errorf("expected JSON Reconnecting=false for dead PID")
	}
	if sj.NetworkDown {
		t.Errorf("expected JSON NetworkDown=false for dead PID")
	}
}

func TestCLI_RunStatus_DeadPID_RepairsState(t *testing.T) {
	deadPID := 99999999
	if session.IsPIDAlive(deadPID) {
		t.Skipf("PID %d surprisingly alive, skipping test", deadPID)
	}

	tmpDir := t.TempDir()
	t.Setenv("GOSTPX_CONFIG_DIR", tmpDir)

	configPath := filepath.Join(tmpDir, "config.toml")
	statePath := filepath.Join(tmpDir, "state.json")

	cfg := config.DefaultConfig()
	_ = config.Save(configPath, cfg)
	_ = config.SavePassword(config.CredentialsPath(configPath), "")

	st := state.DefaultState()
	st.ActiveSession = false
	st.PID = deadPID
	st.Reconnecting = true
	st.NetworkDown = true
	st.ReconnectAttempt = 5
	st.NextReconnect = time.Now().Add(60 * time.Second)
	st.LastDisconnectReason = "stale dead process"
	if err := state.Save(statePath, st); err != nil {
		t.Fatalf("failed to save initial state: %v", err)
	}

	// Run statusCmd
	captureStdout(func() {
		_ = runStatus(statusCmd, nil)
	})

	// Check that state.json was repaired
	loaded, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state after runStatus: %v", err)
	}
	if loaded.Reconnecting {
		t.Errorf("expected repaired state.Reconnecting == false")
	}
	if loaded.NetworkDown {
		t.Errorf("expected repaired state.NetworkDown == false")
	}
	if loaded.ReconnectAttempt != 0 {
		t.Errorf("expected repaired state.ReconnectAttempt == 0")
	}
	if loaded.PID != 0 {
		t.Errorf("expected repaired state.PID == 0, got %d", loaded.PID)
	}
}
