//go:build !gostpxtest

package autostart

func testLaunchAgentsDir() string {
	return ""
}

func testAllowNonAppAutostart() bool {
	return false
}
