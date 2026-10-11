//go:build gostpxtest

package autostart

import "os"

func testLaunchAgentsDir() string {
	return os.Getenv("GOSTPX_LAUNCH_AGENTS_DIR")
}

func testAllowNonAppAutostart() bool {
	return os.Getenv("GOSTPX_ALLOW_NON_APP_AUTOSTART") == "1"
}
