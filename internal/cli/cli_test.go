//go:build gostpxtest

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/session"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
)

func setupTestConfigDir(t *testing.T) string {
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

func TestRootCommand(t *testing.T) {
	setupTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("expected nil error on --help, got: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "gostpx") {
		t.Errorf("expected help output to contain 'gostpx', got: %s", out)
	}
}

func TestConfigPathCommand(t *testing.T) {
	tmpDir := setupTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"config", "path"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'config path': %v", err)
	}
	_ = tmpDir
}

func TestStatusCommand(t *testing.T) {
	setupTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"status"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'status': %v", err)
	}
}

func TestStatusJSONCommand(t *testing.T) {
	setupTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"status", "--json"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'status --json': %v", err)
	}
	jsonOutput = false // reset flag
}

func TestConfigShowCommand(t *testing.T) {
	setupTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"config", "show"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'config show': %v", err)
	}
}

func TestConfigValidateCommand(t *testing.T) {
	tmpDir := setupTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"config", "validate"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'config validate': %v", err)
	}

	// Now corrupt config
	badPath := filepath.Join(tmpDir, "config.toml")
	_ = os.WriteFile(badPath, []byte("broken = ["), 0600)
	RootCmd.SetArgs([]string{"config", "validate"})
	err = RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error validating corrupted config, got nil")
	}
}

func TestSetShowCommand(t *testing.T) {
	setupTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"set", "--show"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'set --show': %v", err)
	}
	showFlag = false // reset flag
}

func TestModeCommand(t *testing.T) {
	setupTestConfigDir(t)
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"mode", "sysproxy"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'mode sysproxy': %v", err)
	}
}

func TestStatusCheckIPJSON(t *testing.T) {
	sj := statusJSON{
		State:           "connected",
		Mode:            "sysproxy",
		Proxy:           "socks5://127.0.0.1:8080",
		ExternalIP:      "198.51.100.20",
		ExternalCountry: "US",
	}
	data, err := json.Marshal(sj)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	jsonStr := string(data)
	if !strings.Contains(jsonStr, `"external_ip":"198.51.100.20"`) {
		t.Errorf("expected JSON to contain external_ip, got: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"external_country":"US"`) {
		t.Errorf("expected JSON to contain external_country, got: %s", jsonStr)
	}
}

func TestOffCommand_ProcessNotTerminated(t *testing.T) {
	tmpDir := setupTestConfigDir(t)
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	statePath := filepath.Join(tmpDir, "state.json")
	st := &state.State{
		ActiveSession: true,
		PID:           77777,
		Mode:          config.ModeSysproxy,
	}
	if err := state.Save(statePath, st); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	reset := session.SetProcessHooksForTest(
		func(pid int) bool { return pid == 77777 },
		func(pid int) error { return nil },
	)
	defer reset()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"off"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error from 'gostpx off' when process does not terminate, got nil")
	}

	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected CLIError, got: %T (%v)", err, err)
	}
	if cliErr.Code != ExitGeneralError {
		t.Errorf("expected exit code %d (ExitGeneralError), got %d", ExitGeneralError, cliErr.Code)
	}
	if !strings.Contains(err.Error(), "процесс PID 77777 не завершился") {
		t.Errorf("expected error message to contain 'процесс PID 77777 не завершился', got: %v", err)
	}
}

func TestStatusCommand_PreservesSnapshotOnUnsetFailure(t *testing.T) {
	tmpDir := setupTestConfigDir(t)
	// Point dry path to a directory so sysproxy.Unset fails
	t.Setenv("GOSTPX_SYSPROXY_DRY", tmpDir)

	statePath := filepath.Join(tmpDir, "state.json")
	snap := &sysproxy.Snapshot{
		Dry: &sysproxy.Status{
			Enabled:  true,
			HTTPHost: "1.2.3.4",
			HTTPPort: 8888,
		},
	}
	st := &state.State{
		ActiveSession:    true,
		PID:              999999, // Dead PID
		Mode:             config.ModeSysproxy,
		SysproxySnapshot: snap,
	}
	if err := state.Save(statePath, st); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"status"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error from 'gostpx status' when Unset fails, got nil")
	}

	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected CLIError, got: %T (%v)", err, err)
	}
	if cliErr.Code != ExitGeneralError {
		t.Errorf("expected exit code %d (ExitGeneralError), got %d", ExitGeneralError, cliErr.Code)
	}

	// Verify state in state.json is NOT cleared
	savedSt, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if !savedSt.ActiveSession {
		t.Errorf("expected ActiveSession to remain true when Unset fails")
	}
	if savedSt.PID != 999999 {
		t.Errorf("expected PID to remain 999999, got: %d", savedSt.PID)
	}
	if savedSt.SysproxySnapshot == nil {
		t.Errorf("expected SysproxySnapshot to be preserved when Unset fails")
	}
	if !strings.Contains(savedSt.LastDisconnectReason, "ошибка снятия прокси") {
		t.Errorf("expected LastDisconnectReason to mention unset error, got: %s", savedSt.LastDisconnectReason)
	}
}

func TestStatusCommand_RecoversCrashedProcessOnUnsetSuccess(t *testing.T) {
	tmpDir := setupTestConfigDir(t)
	dryFile := filepath.Join(tmpDir, "dry.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryFile)

	statePath := filepath.Join(tmpDir, "state.json")
	snap := &sysproxy.Snapshot{
		Dry: &sysproxy.Status{
			Enabled: false,
		},
	}
	st := &state.State{
		ActiveSession:    true,
		PID:              999999, // Dead PID
		Mode:             config.ModeSysproxy,
		SysproxySnapshot: snap,
	}
	if err := state.Save(statePath, st); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"status"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'status': %v", err)
	}

	// Verify state in state.json IS updated and cleared
	savedSt, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if savedSt.ActiveSession {
		t.Errorf("expected ActiveSession to be false after recovery")
	}
	if savedSt.PID != 0 {
		t.Errorf("expected PID to be 0 after recovery, got: %d", savedSt.PID)
	}
	if savedSt.SysproxySnapshot != nil {
		t.Errorf("expected SysproxySnapshot to be nil after recovery")
	}
	if savedSt.LastDisconnectReason != "процесс завершился аварийно, прокси сброшен" {
		t.Errorf("unexpected LastDisconnectReason: %s", savedSt.LastDisconnectReason)
	}
}
