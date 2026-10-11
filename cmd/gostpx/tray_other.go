//go:build !darwin

package main

import (
	"github.com/losoph/gostpx/internal/cli"
)

func runTray() {
	// Windows GUI tray is scheduled for later in Phase 2.
	// Running without arguments executes the default CLI action.
	cli.Execute()
}
