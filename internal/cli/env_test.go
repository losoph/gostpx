package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/state"
)

func resetEnvFlags() {
	envUnset = false
	envShell = defaultEnvShell
}

func setupEnvTestConfig(t *testing.T, httpListen, socksListen string) string {
	tmpDir := t.TempDir()
	t.Setenv("GOSTPX_CONFIG_DIR", tmpDir)

	cfg := config.DefaultConfig()
	cfg.Proxy.Host = "127.0.0.1"
	cfg.Proxy.Port = 8080
	if httpListen != "" {
		cfg.Sysproxy.HTTPListen = httpListen
	}
	if socksListen != "" {
		cfg.Sysproxy.SOCKSListen = socksListen
	}
	if err := config.Save(filepath.Join(tmpDir, "config.toml"), cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}
	return tmpDir
}

// 1. posix-вывод с портами из конфига
func TestEnv_PosixConfigPorts(t *testing.T) {
	defer resetEnvFlags()
	resetEnvFlags()

	setupEnvTestConfig(t, "127.0.0.1:9090", "127.0.0.1:2080")

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	RootCmd.SetOut(stdout)
	RootCmd.SetErr(stderr)
	RootCmd.SetArgs([]string{"env", "--shell", "posix"})

	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	expectedStdout := "export HTTP_PROXY=http://127.0.0.1:9090 http_proxy=http://127.0.0.1:9090\n" +
		"export HTTPS_PROXY=http://127.0.0.1:9090 https_proxy=http://127.0.0.1:9090\n" +
		"export ALL_PROXY=socks5h://127.0.0.1:2080 all_proxy=socks5h://127.0.0.1:2080\n" +
		"export NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1\n"

	if stdout.String() != expectedStdout {
		t.Errorf("stdout mismatch:\ngot:\n%s\nwant:\n%s", stdout.String(), expectedStdout)
	}
}

// 2. --unset
func TestEnv_Unset(t *testing.T) {
	defer resetEnvFlags()

	// POSIX unset
	t.Run("POSIX", func(t *testing.T) {
		resetEnvFlags()
		setupEnvTestConfig(t, "127.0.0.1:8080", "127.0.0.1:1080")

		stdout := new(bytes.Buffer)
		stderr := new(bytes.Buffer)
		RootCmd.SetOut(stdout)
		RootCmd.SetErr(stderr)
		RootCmd.SetArgs([]string{"env", "--unset", "--shell", "posix"})

		if err := RootCmd.Execute(); err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}

		expectedStdout := "unset HTTP_PROXY http_proxy\n" +
			"unset HTTPS_PROXY https_proxy\n" +
			"unset ALL_PROXY all_proxy\n" +
			"unset NO_PROXY no_proxy\n"

		if stdout.String() != expectedStdout {
			t.Errorf("stdout mismatch:\ngot:\n%s\nwant:\n%s", stdout.String(), expectedStdout)
		}
	})

	// PowerShell unset
	t.Run("PowerShell", func(t *testing.T) {
		resetEnvFlags()
		setupEnvTestConfig(t, "127.0.0.1:8080", "127.0.0.1:1080")

		stdout := new(bytes.Buffer)
		stderr := new(bytes.Buffer)
		RootCmd.SetOut(stdout)
		RootCmd.SetErr(stderr)
		RootCmd.SetArgs([]string{"env", "--unset", "--shell", "powershell"})

		if err := RootCmd.Execute(); err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}

		expectedStdout := "Remove-Item Env:HTTP_PROXY -ErrorAction SilentlyContinue\n" +
			"Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue\n" +
			"Remove-Item Env:ALL_PROXY -ErrorAction SilentlyContinue\n" +
			"Remove-Item Env:NO_PROXY -ErrorAction SilentlyContinue\n"

		if stdout.String() != expectedStdout {
			t.Errorf("stdout mismatch:\ngot:\n%s\nwant:\n%s", stdout.String(), expectedStdout)
		}
	})
}

// 3. --shell powershell
func TestEnv_PowerShell(t *testing.T) {
	defer resetEnvFlags()
	resetEnvFlags()

	setupEnvTestConfig(t, "127.0.0.1:8080", "127.0.0.1:1080")

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	RootCmd.SetOut(stdout)
	RootCmd.SetErr(stderr)
	RootCmd.SetArgs([]string{"env", "--shell", "powershell"})

	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	expectedStdout := "$env:HTTP_PROXY = 'http://127.0.0.1:8080'\n" +
		"$env:HTTPS_PROXY = 'http://127.0.0.1:8080'\n" +
		"$env:ALL_PROXY = 'socks5h://127.0.0.1:1080'\n" +
		"$env:NO_PROXY = 'localhost,127.0.0.1,::1'\n"

	if stdout.String() != expectedStdout {
		t.Errorf("stdout mismatch:\ngot:\n%s\nwant:\n%s", stdout.String(), expectedStdout)
	}
}

// 4. экранирование адреса с пробелом
func TestEnv_AddressWithSpaceEscaped(t *testing.T) {
	defer resetEnvFlags()
	resetEnvFlags()

	setupEnvTestConfig(t, "127.0.0.1:8080 with space", "127.0.0.1:1080")

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	RootCmd.SetOut(stdout)
	RootCmd.SetErr(stderr)
	RootCmd.SetArgs([]string{"env", "--shell", "posix"})

	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	expectedHTTP := "'http://127.0.0.1:8080 with space'"
	if !strings.Contains(stdout.String(), "export HTTP_PROXY="+expectedHTTP+" http_proxy="+expectedHTTP) {
		t.Errorf("expected quoted HTTP_PROXY in stdout, got:\n%s", stdout.String())
	}
}

// 5. предупреждение в stderr при неактивной сессии, а stdout при этом только строки export
func TestEnv_InactiveSessionWarning(t *testing.T) {
	defer resetEnvFlags()
	resetEnvFlags()

	tmpDir := setupEnvTestConfig(t, "127.0.0.1:8080", "127.0.0.1:1080")

	// Explicitly create an inactive state
	st := state.DefaultState()
	st.ActiveSession = false
	st.PID = 0
	if err := state.Save(filepath.Join(tmpDir, "state.json"), st); err != nil {
		t.Fatalf("save state: %v", err)
	}

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	RootCmd.SetOut(stdout)
	RootCmd.SetErr(stderr)
	RootCmd.SetArgs([]string{"env", "--shell", "posix"})

	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	// Stderr must have warning in Russian
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "⚠ gostpx сейчас выключен") {
		t.Errorf("expected warning in stderr, got: %q", stderrStr)
	}
	if !strings.Contains(stderrStr, "консоль через эти адреса не выйдет") {
		t.Errorf("expected warning details in stderr, got: %q", stderrStr)
	}

	// Stdout must contain ONLY export lines
	expectedStdout := "export HTTP_PROXY=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080\n" +
		"export HTTPS_PROXY=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080\n" +
		"export ALL_PROXY=socks5h://127.0.0.1:1080 all_proxy=socks5h://127.0.0.1:1080\n" +
		"export NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1\n"

	if stdout.String() != expectedStdout {
		t.Errorf("stdout mismatch:\ngot:\n%s\nwant:\n%s", stdout.String(), expectedStdout)
	}

	// Active session test: no stderr warning
	t.Run("ActiveSession_NoWarning", func(t *testing.T) {
		resetEnvFlags()
		st.ActiveSession = true
		st.PID = os.Getpid() // current running test process PID
		if err := state.Save(filepath.Join(tmpDir, "state.json"), st); err != nil {
			t.Fatalf("save state: %v", err)
		}

		stdout2 := new(bytes.Buffer)
		stderr2 := new(bytes.Buffer)
		RootCmd.SetOut(stdout2)
		RootCmd.SetErr(stderr2)
		RootCmd.SetArgs([]string{"env", "--shell", "posix"})

		if err := RootCmd.Execute(); err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}

		if stderr2.Len() != 0 {
			t.Errorf("expected empty stderr for active session, got: %q", stderr2.String())
		}
		if stdout2.String() != expectedStdout {
			t.Errorf("stdout mismatch for active session:\ngot:\n%s\nwant:\n%s", stdout2.String(), expectedStdout)
		}
	})
}

// 6. Битый конфиг — ошибка ExitConfigError
func TestEnv_CorruptedConfig_ReturnsExitConfigError(t *testing.T) {
	defer resetEnvFlags()
	resetEnvFlags()

	tmpDir := t.TempDir()
	t.Setenv("GOSTPX_CONFIG_DIR", tmpDir)

	badPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(badPath, []byte("broken toml [[["), 0600); err != nil {
		t.Fatalf("write bad config: %v", err)
	}

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	RootCmd.SetOut(stdout)
	RootCmd.SetErr(stderr)
	RootCmd.SetArgs([]string{"env", "--shell", "posix"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error on broken config, got nil")
	}

	var cliErr *CLIError
	if !strings.Contains(err.Error(), "decode toml") && !strings.Contains(err.Error(), "line ") {
		t.Errorf("expected toml decode error, got: %v", err)
	}
	if ok := errors.As(err, &cliErr); !ok || cliErr.Code != ExitConfigError {
		t.Errorf("expected exit code ExitConfigError (%d), got: %v", ExitConfigError, err)
	}
}

// 7. Отсутствие файла конфига — используются дефолты
func TestEnv_MissingConfigFile_UsesDefaults(t *testing.T) {
	defer resetEnvFlags()
	resetEnvFlags()

	tmpDir := t.TempDir()
	t.Setenv("GOSTPX_CONFIG_DIR", tmpDir)

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	RootCmd.SetOut(stdout)
	RootCmd.SetErr(stderr)
	RootCmd.SetArgs([]string{"env", "--shell", "posix"})

	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("expected nil error on missing config, got: %v", err)
	}

	expectedStdout := "export HTTP_PROXY=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080\n" +
		"export HTTPS_PROXY=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080\n" +
		"export ALL_PROXY=socks5h://127.0.0.1:1080 all_proxy=socks5h://127.0.0.1:1080\n" +
		"export NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1\n"

	if stdout.String() != expectedStdout {
		t.Errorf("stdout mismatch:\ngot:\n%s\nwant:\n%s", stdout.String(), expectedStdout)
	}
}
