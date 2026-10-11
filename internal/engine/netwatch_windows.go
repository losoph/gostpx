//go:build windows

package engine

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isNetworkDownError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.WSAENETUNREACH) ||
		errors.Is(err, windows.WSAEHOSTUNREACH) ||
		errors.Is(err, windows.WSAENETDOWN) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) {
		return true
	}
	return false
}

func hasDefaultRoute() bool {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return true // on error, avoid false positives
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength == 0 {
			return true
		}
	}
	return false
}
