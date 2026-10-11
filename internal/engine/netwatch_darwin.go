//go:build darwin

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
	rib, err := syscall.RouteRIB(syscall.NET_RT_DUMP, 0)
	if err != nil {
		return true // on error, avoid false positives
	}

	b := rib
	for len(b) >= 4 {
		msgLen := int(b[0]) | int(b[1])<<8
		if msgLen <= 0 || msgLen > len(b) {
			break
		}

		// Copy into an aligned buffer to satisfy checkptr in race mode on darwin arm64
		single := make([]byte, msgLen)
		copy(single, b[:msgLen])

		msgs, err := syscall.ParseRoutingMessage(single)
		if err == nil {
			for _, m := range msgs {
				rm, ok := m.(*syscall.RouteMessage)
				if !ok {
					continue
				}
				if rm.Header.Flags&(syscall.RTF_UP|syscall.RTF_GATEWAY) != (syscall.RTF_UP | syscall.RTF_GATEWAY) {
					continue
				}
				addrs, err := syscall.ParseRoutingSockaddr(rm)
				if err != nil || len(addrs) == 0 {
					continue
				}
				dst := addrs[syscall.RTAX_DST]
				if dst == nil {
					return true
				}
				if sa4, ok := dst.(*syscall.SockaddrInet4); ok && sa4.Addr == [4]byte{0, 0, 0, 0} {
					return true
				}
			}
		}
		b = b[msgLen:]
	}
	return false
}
