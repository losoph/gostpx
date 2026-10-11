//go:build (darwin || windows) && gostpxtest

package sysproxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDrySysproxy(t *testing.T) {
	tmpDir := t.TempDir()
	dryPath := filepath.Join(tmpDir, "sysproxy.json")

	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	// 1. Initial status should be disabled
	cur, err := Current()
	if err != nil {
		t.Fatalf("Current() error: %v", err)
	}
	if cur.Enabled {
		t.Errorf("expected Enabled=false initially, got true")
	}

	// 2. Set proxy
	if err := Set("127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	cur, err = Current()
	if err != nil {
		t.Fatalf("Current() after Set error: %v", err)
	}
	if !cur.Enabled {
		t.Errorf("expected Enabled=true after Set, got false")
	}
	if cur.HTTPHost != "127.0.0.1" || cur.HTTPPort != 8080 {
		t.Errorf("unexpected HTTP host:port %s:%d", cur.HTTPHost, cur.HTTPPort)
	}
	if cur.SOCKSHost != "127.0.0.1" || cur.SOCKSPort != 1080 {
		t.Errorf("unexpected SOCKS host:port %s:%d", cur.SOCKSHost, cur.SOCKSPort)
	}

	// Verify file was written
	if _, err := os.Stat(dryPath); err != nil {
		t.Fatalf("dry file not created: %v", err)
	}

	// 3. Unset proxy
	if err := Unset(nil, "", ""); err != nil {
		t.Fatalf("Unset() error: %v", err)
	}

	cur, err = Current()
	if err != nil {
		t.Fatalf("Current() after Unset error: %v", err)
	}
	if cur.Enabled {
		t.Errorf("expected Enabled=false after Unset, got true")
	}
}

func TestDrySysproxy_SnapshotProxyDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	// 1. Initial snapshot when proxy is disabled
	snap, err := TakeSnapshot()
	if err != nil {
		t.Fatalf("TakeSnapshot error: %v", err)
	}
	if snap == nil || snap.Dry == nil {
		t.Fatalf("expected non-nil snap.Dry")
	}
	if snap.Dry.Enabled {
		t.Errorf("expected snap.Dry.Enabled=false initially")
	}

	// 2. Set our proxy
	if err := Set("127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	cur, _ := Current()
	if !cur.Enabled || cur.HTTPHost != "127.0.0.1" || cur.HTTPPort != 8080 {
		t.Fatalf("unexpected proxy state after Set: %+v", cur)
	}

	// 3. Unset should restore disabled state
	if err := Unset(snap, "127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Unset error: %v", err)
	}
	restored, err := Current()
	if err != nil {
		t.Fatalf("Current error after Unset: %v", err)
	}
	if restored.Enabled {
		t.Errorf("expected Enabled=false after restoring disabled snapshot, got true")
	}
}

func TestDrySysproxy_SnapshotForeignProxy(t *testing.T) {
	tmpDir := t.TempDir()
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	// 1. Set pre-existing foreign proxy
	if err := Set("10.0.0.1:3128", "10.0.0.1:1080"); err != nil {
		t.Fatalf("failed to set foreign proxy: %v", err)
	}

	// 2. Take snapshot before gostpx starts
	snap, err := TakeSnapshot()
	if err != nil {
		t.Fatalf("TakeSnapshot error: %v", err)
	}
	if snap == nil || snap.Dry == nil || !snap.Dry.Enabled || snap.Dry.HTTPHost != "10.0.0.1" || snap.Dry.HTTPPort != 3128 {
		t.Fatalf("unexpected snapshot of foreign proxy: %+v", snap)
	}

	// 3. Gostpx sets its own proxy
	if err := Set("127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	cur, _ := Current()
	if cur.HTTPHost != "127.0.0.1" || cur.HTTPPort != 8080 {
		t.Fatalf("gostpx proxy not active: %+v", cur)
	}

	// 4. Gostpx stops and unsets: should restore original foreign proxy
	if err := Unset(snap, "127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Unset error: %v", err)
	}
	restored, err := Current()
	if err != nil {
		t.Fatalf("Current error after Unset: %v", err)
	}
	if !restored.Enabled {
		t.Errorf("expected foreign proxy to be restored (Enabled=true), got false")
	}
	if restored.HTTPHost != "10.0.0.1" || restored.HTTPPort != 3128 {
		t.Errorf("expected foreign proxy 10.0.0.1:3128 restored, got %s:%d", restored.HTTPHost, restored.HTTPPort)
	}
}

func TestDrySysproxy_ChangedBySomeoneElseNotTouched(t *testing.T) {
	tmpDir := t.TempDir()
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	// Snapshot with proxy disabled
	snap, err := TakeSnapshot()
	if err != nil {
		t.Fatalf("TakeSnapshot error: %v", err)
	}

	// Gostpx sets proxy
	if err := Set("127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// While gostpx is running, a third party changes settings to another proxy
	if err := Set("192.168.1.1:8888", "192.168.1.1:1080"); err != nil {
		t.Fatalf("failed to simulate third-party change: %v", err)
	}

	// Gostpx unsets: current settings do NOT match 127.0.0.1:8080, so must NOT touch them
	if err := Unset(snap, "127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Unset error: %v", err)
	}

	cur, err := Current()
	if err != nil {
		t.Fatalf("Current error: %v", err)
	}
	if !cur.Enabled || cur.HTTPHost != "192.168.1.1" || cur.HTTPPort != 8888 {
		t.Errorf("expected third-party proxy 192.168.1.1:8888 to remain untouched, got: %+v", cur)
	}
}

func TestDrySysproxy_PartialThirdPartyChange(t *testing.T) {
	tmpDir := t.TempDir()
	dryPath := filepath.Join(tmpDir, "sysproxy.json")
	t.Setenv("GOSTPX_SYSPROXY_DRY", dryPath)

	// 1. Initial snapshot with proxy disabled
	snap, err := TakeSnapshot()
	if err != nil {
		t.Fatalf("TakeSnapshot error: %v", err)
	}

	// 2. Gostpx sets HTTP and SOCKS
	if err := Set("127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// 3. Simulate third party changing SOCKS to 10.0.0.1:1080, but keeping HTTP as 127.0.0.1:8080
	if err := Set("127.0.0.1:8080", "10.0.0.1:1080"); err != nil {
		t.Fatalf("Set third party socks error: %v", err)
	}

	// 4. Gostpx unsets with snapshot
	if err := Unset(snap, "127.0.0.1:8080", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Unset error: %v", err)
	}

	// 5. Verify HTTP was restored (cleared), but third party SOCKS was preserved!
	cur, err := Current()
	if err != nil {
		t.Fatalf("Current error: %v", err)
	}
	if cur.HTTPHost != "" || cur.HTTPPort != 0 {
		t.Errorf("expected HTTP proxy cleared, got %s:%d", cur.HTTPHost, cur.HTTPPort)
	}
	if cur.SOCKSHost != "10.0.0.1" || cur.SOCKSPort != 1080 {
		t.Errorf("expected third-party SOCKS proxy preserved as 10.0.0.1:1080, got %s:%d", cur.SOCKSHost, cur.SOCKSPort)
	}
	if !cur.Enabled {
		t.Errorf("expected Enabled=true because third-party SOCKS is still active, got false")
	}
}

func TestDrySysproxy_SnapshotFailureOnInvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	// Set dry path to a directory instead of a file so ReadFile fails
	t.Setenv("GOSTPX_SYSPROXY_DRY", tmpDir)

	snap, err := TakeSnapshot()
	if err == nil {
		t.Errorf("expected error from TakeSnapshot on directory path, got nil (snap: %+v)", snap)
	}
}
