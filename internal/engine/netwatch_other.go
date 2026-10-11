//go:build !darwin && !windows

package engine

import (
	"errors"
	"syscall"
)

func isNetworkDownError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) {
		return true
	}
	return false
}

func hasDefaultRoute() bool {
	return true
}
