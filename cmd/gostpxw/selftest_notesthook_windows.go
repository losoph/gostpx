//go:build windows && !gostpxtest

package main

import (
	"github.com/losoph/gostpx/internal/session"
	"github.com/wailsapp/wails/v3/pkg/application"
)

func isSelftest() bool {
	return false
}

func setupSelftestEnvironment(configPath string) {}

func runSelftest(
	app *application.App,
	getTrayTooltip func() string,
	sess *session.Session,
	toggleHandler func(),
	refreshHandler func(),
	systrayClickHandler func(),
	openSettingsWindow func(),
) {
}
