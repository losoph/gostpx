//go:build windows && gostpxtest

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/session"
	"github.com/losoph/gostpx/internal/state"
	"github.com/losoph/gostpx/internal/sysproxy"
	"github.com/losoph/gostpx/internal/testupstream"
	"github.com/wailsapp/wails/v3/pkg/application"
)

func isSelftest() bool {
	return os.Getenv("GOSTPX_SELFTEST") == "1"
}

func setupSelftestEnvironment(configPath string) {
	srv, err := testupstream.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "selftest: start upstream: %v\n", err)
		os.Exit(1)
	}

	getFreePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}

	httpPort := getFreePort()
	socksPort := getFreePort()

	dir := filepath.Dir(configPath)
	_ = os.MkdirAll(dir, 0755)

	cfgContent := fmt.Sprintf(`version = 1
mode = "sysproxy"

[proxy]
type = "socks5"
host = "127.0.0.1"
port = %d

[sysproxy]
http_listen = "127.0.0.1:%d"
socks_listen = "127.0.0.1:%d"
`, srv.Port(), httpPort, socksPort)

	if err := os.WriteFile(configPath, []byte(cfgContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "selftest: write config: %v\n", err)
		os.Exit(1)
	}

	credPath := config.CredentialsPath(configPath)
	_ = os.WriteFile(credPath, []byte(""), 0600)
}

func runSelftest(
	app *application.App,
	getTrayTooltip func() string,
	sess *session.Session,
	toggleHandler func(),
	refreshHandler func(),
	systrayClickHandler func(),
	openSettingsWindow func(),
) {
	fmt.Println("[SELFTEST] Starting Windows tray selftest scenario...")
	time.Sleep(300 * time.Millisecond)

	pingMainThread := func(stepName string) {
		done := make(chan struct{})
		application.InvokeAsync(func() {
			close(done)
		})
		select {
		case <-done:
			// Main thread responded
		case <-time.After(2 * time.Second):
			buf := make([]byte, 1024*1024)
			n := runtime.Stack(buf, true)
			fmt.Fprintf(os.Stderr, "\n=======================================================\n")
			fmt.Fprintf(os.Stderr, "=== SELFTEST WATCHDOG TIMEOUT (2s) ON STEP: %s ===\n", stepName)
			fmt.Fprintf(os.Stderr, "Main thread is FROZEN / DEADLOCKED. All goroutines stack dump:\n")
			fmt.Fprintf(os.Stderr, "=======================================================\n%s\n", buf[:n])
			os.Exit(1)
		}
	}

	pingMainThread("initial main thread ping")

	// 0. Verify external CLI session detection via state.json fsnotify
	fmt.Println("[SELFTEST] Testing external CLI session detection via state.json fsnotify...")
	statePath, err := state.DefaultStatePath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SELFTEST] state path error: %v\n", err)
		os.Exit(1)
	}

	cliState := &state.State{
		Mode:          "sysproxy",
		ActiveSession: true,
		PID:           os.Getppid(), // living parent process PID
	}
	if err := state.Save(statePath, cliState); err != nil {
		fmt.Fprintf(os.Stderr, "[SELFTEST] write external state: %v\n", err)
		os.Exit(1)
	}

	cliDeadline := time.Now().Add(2 * time.Second)
	cliDetected := false
	for time.Now().Before(cliDeadline) {
		pingMainThread("waiting for CLI session tooltip")
		if strings.Contains(getTrayTooltip(), "CLI") {
			cliDetected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !cliDetected {
		fmt.Fprintf(os.Stderr, "[SELFTEST] FAILED: tray tooltip did not show 'CLI' within 2s, tooltip: %q\n", getTrayTooltip())
		os.Exit(1)
	}
	fmt.Println("[SELFTEST] External CLI session successfully detected in tray tooltip")

	cliState.ActiveSession = false
	cliState.PID = 0
	_ = state.Save(statePath, cliState)

	resetDeadline := time.Now().Add(2 * time.Second)
	resetDetected := false
	for time.Now().Before(resetDeadline) {
		pingMainThread("waiting for revert after CLI session")
		if !strings.Contains(getTrayTooltip(), "CLI") {
			resetDetected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !resetDetected {
		fmt.Fprintf(os.Stderr, "[SELFTEST] FAILED: tray did not revert from CLI session within 2s, tooltip: %q\n", getTrayTooltip())
		os.Exit(1)
	}
	fmt.Println("[SELFTEST] External CLI session clean revert confirmed")

	for iter := 1; iter <= 5; iter++ {
		fmt.Printf("[SELFTEST] Iteration %d/5 starting...\n", iter)

		// 1. «Включить»
		fmt.Printf("[SELFTEST] [%d/5] Triggering 'Включить'...\n", iter)
		toggleHandler()
		pingMainThread(fmt.Sprintf("iter %d: toggle On start", iter))

		waitStart := time.Now()
		for !sess.IsActive() {
			if time.Since(waitStart) > 4*time.Second {
				fmt.Fprintf(os.Stderr, "[SELFTEST] Timed out waiting for session active in iter %d\n", iter)
				buf := make([]byte, 1024*1024)
				n := runtime.Stack(buf, true)
				fmt.Fprintf(os.Stderr, "%s\n", buf[:n])
				os.Exit(1)
			}
			pingMainThread(fmt.Sprintf("iter %d: waiting active", iter))
			time.Sleep(50 * time.Millisecond)
		}
		pingMainThread(fmt.Sprintf("iter %d: active confirmed", iter))

		// 2. Открыть меню (systray click)
		fmt.Printf("[SELFTEST] [%d/5] Triggering open menu (systray click)...\n", iter)
		application.InvokeAsync(func() {
			systrayClickHandler()
		})
		pingMainThread(fmt.Sprintf("iter %d: open menu", iter))
		time.Sleep(100 * time.Millisecond)

		// 3. «Обновить»
		fmt.Printf("[SELFTEST] [%d/5] Triggering 'Обновить'...\n", iter)
		refreshHandler()
		pingMainThread(fmt.Sprintf("iter %d: refresh", iter))
		time.Sleep(100 * time.Millisecond)

		// 4. Двойной быстрый «Включить»
		time.Sleep(550 * time.Millisecond)
		fmt.Printf("[SELFTEST] [%d/5] Stopping session before double toggle...\n", iter)
		toggleHandler()
		pingMainThread(fmt.Sprintf("iter %d: stop before double toggle", iter))
		waitStop := time.Now()
		for sess.IsActive() {
			if time.Since(waitStop) > 4*time.Second {
				fmt.Fprintf(os.Stderr, "[SELFTEST] Timed out waiting for session stop in iter %d\n", iter)
				os.Exit(1)
			}
			pingMainThread(fmt.Sprintf("iter %d: waiting stop before double toggle", iter))
			time.Sleep(50 * time.Millisecond)
		}
		pingMainThread(fmt.Sprintf("iter %d: stopped before double toggle", iter))
		time.Sleep(300 * time.Millisecond)

		fmt.Printf("[SELFTEST] [%d/5] Triggering double fast 'Включить'...\n", iter)
		toggleHandler()
		time.Sleep(20 * time.Millisecond)
		toggleHandler()
		pingMainThread(fmt.Sprintf("iter %d: double toggle", iter))

		waitActive := time.Now()
		for !sess.IsActive() {
			if time.Since(waitActive) > 4*time.Second {
				fmt.Fprintf(os.Stderr, "[SELFTEST] Timed out waiting for active after double toggle in iter %d\n", iter)
				os.Exit(1)
			}
			pingMainThread(fmt.Sprintf("iter %d: waiting active after double toggle", iter))
			time.Sleep(50 * time.Millisecond)
		}
		pingMainThread(fmt.Sprintf("iter %d: active confirmed after double toggle", iter))
		time.Sleep(550 * time.Millisecond)

		// 5. «Выключить»
		fmt.Printf("[SELFTEST] [%d/5] Triggering 'Выключить'...\n", iter)
		toggleHandler()
		pingMainThread(fmt.Sprintf("iter %d: toggle Off", iter))
		waitOff := time.Now()
		for sess.IsActive() {
			if time.Since(waitOff) > 4*time.Second {
				fmt.Fprintf(os.Stderr, "[SELFTEST] Timed out waiting for session inactive in iter %d\n", iter)
				os.Exit(1)
			}
			pingMainThread(fmt.Sprintf("iter %d: waiting inactive", iter))
			time.Sleep(50 * time.Millisecond)
		}
		pingMainThread(fmt.Sprintf("iter %d: inactive confirmed", iter))
		time.Sleep(350 * time.Millisecond)
	}

	cur, err := sysproxy.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SELFTEST] Failed to read current sysproxy: %v\n", err)
		os.Exit(1)
	}
	if cur.Enabled {
		fmt.Fprintf(os.Stderr, "[SELFTEST] Dry sysproxy is still enabled: %+v\n", cur)
		os.Exit(1)
	}

	fmt.Println("[SELFTEST] All 5 iterations PASSED successfully. Dry sysproxy is cleanly unset.")

	// Test opening settings window and verifying responsiveness
	fmt.Println("[SELFTEST] Testing settings window opening and responsiveness...")
	openSettingsWindow()
	pingMainThread("settings window opened")
	time.Sleep(300 * time.Millisecond)
	pingMainThread("settings window active ping")
	fmt.Println("[SELFTEST] Settings window opened and main thread remained responsive")

	// Test closing settings window and verifying that it closed (B2)
	fmt.Println("[SELFTEST] Testing settings window close...")
	w, exists := app.Window.GetByName("settings")
	if !exists || w == nil {
		fmt.Fprintf(os.Stderr, "[SELFTEST] FAILED: settings window not found by name 'settings'\n")
		os.Exit(1)
	}
	application.InvokeAsync(func() {
		w.Close()
	})
	pingMainThread("settings window close requested")

	closed := false
	closeDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(closeDeadline) {
		pingMainThread("waiting for settings window to close")
		if _, stillExists := app.Window.GetByName("settings"); !stillExists {
			closed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !closed {
		fmt.Fprintf(os.Stderr, "[SELFTEST] FAILED: settings window did not close within 2s\n")
		os.Exit(1)
	}
	fmt.Println("[SELFTEST] Settings window closed successfully")

	app.Quit()
	os.Exit(0)
}
