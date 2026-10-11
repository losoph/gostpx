//go:build !gostpxtest

package session

import (
	"context"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/engine"
)

func checkPIDAlive(pid int) bool {
	return IsPIDAlive(pid)
}

func terminatePID(pid int) error {
	return TerminateProcess(pid)
}

func hookRestartBeforeStart() {}

func hookBeforeVerifyUpstream() {}

func doVerifyUpstream(ctx context.Context, cfg config.ProxyConfig, plainSecret string, timeout time.Duration) (time.Duration, error) {
	return engine.VerifyUpstream(ctx, cfg, plainSecret, timeout)
}
