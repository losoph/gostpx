package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/connwatch"
	"github.com/losoph/gostpx/internal/state"
)

func setupDoctorTestConfigDir(t *testing.T) string {
	tmpDir := t.TempDir()
	t.Setenv("GOSTPX_CONFIG_DIR", tmpDir)

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 8080
	if err := config.Save(filepath.Join(tmpDir, "config.toml"), cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}
	return tmpDir
}

func TestDoctorNoFlags(t *testing.T) {
	setupDoctorTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"doctor"})

	doctorConnections = false
	doctorJSON = false

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "--connections") {
		t.Errorf("expected hint about --connections, got: %s", out)
	}
}

func TestDoctorInactiveSession(t *testing.T) {
	tmpDir := setupDoctorTestConfigDir(t)
	st := state.DefaultState()
	st.ActiveSession = false
	_ = state.Save(filepath.Join(tmpDir, "state.json"), st)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"doctor", "--connections"})

	doctorConnections = false
	doctorJSON = false

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "не активна") {
		t.Errorf("expected message about inactive session, got: %s", out)
	}
}

func TestDoctorConnectionsJSON(t *testing.T) {
	tmpDir := setupDoctorTestConfigDir(t)

	// Save active session
	st := state.DefaultState()
	st.ActiveSession = true
	st.PID = os.Getpid()
	if err := state.Save(filepath.Join(tmpDir, "state.json"), st); err != nil {
		t.Fatalf("failed to save test state: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Sysproxy.HTTPListen = "127.0.0.1:8080"
	cfg.Proxy.Host = "203.0.113.1"
	cfg.Proxy.Port = 1080
	if err := config.Save(filepath.Join(tmpDir, "config.toml"), cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}

	// Substitute connwatchTake
	origTake := connwatchTake
	defer func() { connwatchTake = origTake }()

	connwatchTake = func(ctx context.Context) ([]connwatch.Conn, error) {
		return []connwatch.Conn{
			// Bypass connection from curl
			{
				PID:     555,
				Process: "curl",
				Local:   netip.MustParseAddrPort("192.168.1.5:54321"),
				Remote:  netip.MustParseAddrPort("93.184.216.34:80"),
			},
			// Ignored: connection to listener
			{
				PID:     666,
				Process: "browser",
				Local:   netip.MustParseAddrPort("127.0.0.1:51234"),
				Remote:  netip.MustParseAddrPort("127.0.0.1:8080"),
			},
			// Ignored: connection to upstream proxy server
			{
				PID:     os.Getpid(),
				Process: "gostpx",
				Local:   netip.MustParseAddrPort("192.168.1.5:51235"),
				Remote:  netip.MustParseAddrPort("203.0.113.1:1080"),
			},
		}, nil
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"doctor", "--connections", "--json"})

	doctorConnections = false
	doctorJSON = false

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running doctor --connections --json: %v", err)
	}

	doctorConnections = false
	doctorJSON = false

	var report connwatch.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse JSON report: %v, raw output: %s", err, buf.String())
	}

	if len(report.Bypass) != 1 {
		t.Fatalf("expected 1 bypass group, got %d", len(report.Bypass))
	}

	group := report.Bypass[0]
	if group.Process != "curl" {
		t.Errorf("expected process 'curl', got %q", group.Process)
	}
	if group.Count != 1 {
		t.Errorf("expected count 1, got %d", group.Count)
	}
	if len(group.Samples) != 1 || group.Samples[0] != netip.MustParseAddrPort("93.184.216.34:80") {
		t.Errorf("expected sample 93.184.216.34:80, got %v", group.Samples)
	}
}

func TestDoctorConnectionsText(t *testing.T) {
	tmpDir := setupDoctorTestConfigDir(t)

	st := state.DefaultState()
	st.ActiveSession = true
	st.PID = os.Getpid()
	_ = state.Save(filepath.Join(tmpDir, "state.json"), st)

	origTake := connwatchTake
	defer func() { connwatchTake = origTake }()

	connwatchTake = func(ctx context.Context) ([]connwatch.Conn, error) {
		return []connwatch.Conn{
			{
				PID:     777,
				Process: "testcli",
				Local:   netip.MustParseAddrPort("192.168.1.10:50000"),
				Remote:  netip.MustParseAddrPort("198.51.100.2:443"),
			},
		}, nil
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"doctor", "--connections"})

	doctorConnections = false
	doctorJSON = false

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	doctorConnections = false
	doctorJSON = false

	out := buf.String()
	if !strings.Contains(out, "эвристика: соединение мимо слушателей gostpx и не в локальную сеть") {
		t.Errorf("expected heuristic header in output, got: %s", out)
	}
	if !strings.Contains(out, "testcli (PID 777): 1 соединение, напр. 198.51.100.2:443") {
		t.Errorf("expected process details line in output, got: %s", out)
	}
}

func TestDoctorConnectionsEmpty(t *testing.T) {
	tmpDir := setupDoctorTestConfigDir(t)

	st := state.DefaultState()
	st.ActiveSession = true
	st.PID = os.Getpid()
	_ = state.Save(filepath.Join(tmpDir, "state.json"), st)

	origTake := connwatchTake
	defer func() { connwatchTake = origTake }()

	connwatchTake = func(ctx context.Context) ([]connwatch.Conn, error) {
		return []connwatch.Conn{}, nil
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"doctor", "--connections"})

	doctorConnections = false
	doctorJSON = false

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	doctorConnections = false
	doctorJSON = false

	out := buf.String()
	if !strings.Contains(out, "мимо прокси соединений не видно") {
		t.Errorf("expected 'мимо прокси соединений не видно', got: %s", out)
	}
}
