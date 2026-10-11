//go:build gostpxtest

package session

import (
	"context"
	"time"

	"github.com/losoph/gostpx/internal/config"
	"github.com/losoph/gostpx/internal/engine"
)

var (
	isPIDAliveFn       = IsPIDAlive
	terminateProcessFn = TerminateProcess
	restartHookFn      func()
)

// SetProcessHooksForTest allows tests to stub process lifecycle checks.
func SetProcessHooksForTest(isAlive func(int) bool, term func(int) error) func() {
	prevAlive := isPIDAliveFn
	prevTerm := terminateProcessFn
	if isAlive != nil {
		isPIDAliveFn = isAlive
	}
	if term != nil {
		terminateProcessFn = term
	}
	return func() {
		isPIDAliveFn = prevAlive
		terminateProcessFn = prevTerm
	}
}

// SetRestartHookForTest allows tests to intercept Restart after stopping the old engine.
func SetRestartHookForTest(fn func()) func() {
	prev := restartHookFn
	restartHookFn = fn
	return func() {
		restartHookFn = prev
	}
}

func hookRestartBeforeStart() {
	if restartHookFn != nil {
		restartHookFn()
	}
}

var beforeVerifyUpstreamFn func()

// SetBeforeVerifyUpstreamHookForTest allows tests to intercept before VerifyUpstream while s.mu is unlocked.
func SetBeforeVerifyUpstreamHookForTest(fn func()) func() {
	prev := beforeVerifyUpstreamFn
	beforeVerifyUpstreamFn = fn
	return func() {
		beforeVerifyUpstreamFn = prev
	}
}

func hookBeforeVerifyUpstream() {
	if beforeVerifyUpstreamFn != nil {
		beforeVerifyUpstreamFn()
	}
}

func checkPIDAlive(pid int) bool {
	return isPIDAliveFn(pid)
}

func terminatePID(pid int) error {
	return terminateProcessFn(pid)
}

var verifyUpstreamFn func(ctx context.Context, cfg config.ProxyConfig, plainSecret string, timeout time.Duration) (time.Duration, error)

func doVerifyUpstream(ctx context.Context, cfg config.ProxyConfig, plainSecret string, timeout time.Duration) (time.Duration, error) {
	if verifyUpstreamFn != nil {
		return verifyUpstreamFn(ctx, cfg, plainSecret, timeout)
	}
	return engine.VerifyUpstream(ctx, cfg, plainSecret, timeout)
}

// SetVerifyUpstreamForTest allows tests to stub VerifyUpstream in session.
func SetVerifyUpstreamForTest(fn func(ctx context.Context, cfg config.ProxyConfig, plainSecret string, timeout time.Duration) (time.Duration, error)) func() {
	prev := verifyUpstreamFn
	verifyUpstreamFn = fn
	return func() {
		verifyUpstreamFn = prev
	}
}
