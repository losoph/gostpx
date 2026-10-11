//go:build darwin || windows

package sysproxy

import (
	"errors"
	"testing"
)

// TestGuardRefusesRealChangeInTests checks that a test binary without
// GOSTPX_SYSPROXY_DRY cannot reach networksetup / the registry. Unset gets a
// TEST-NET listen address (RFC 5737), so even a broken guard changes nothing:
// Unset only touches entries that match the listen address.
func TestGuardRefusesRealChangeInTests(t *testing.T) {
	t.Setenv("GOSTPX_SYSPROXY_DRY", "")
	err := Unset(nil, "203.0.113.1:9", "203.0.113.1:9")
	if !errors.Is(err, errRealChangeFromTest) {
		t.Fatalf("Unset from a test without dry mode: got %v, want errRealChangeFromTest", err)
	}
}
