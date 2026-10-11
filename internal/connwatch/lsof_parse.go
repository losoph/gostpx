package connwatch

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ParseLsof parses output from `lsof -F pcn` and extracts established TCP connections.
func ParseLsof(r io.Reader) ([]Conn, error) {
	scanner := bufio.NewScanner(r)
	var (
		conns   []Conn
		curPID  int
		curProc string
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		field := line[0]
		val := line[1:]

		switch field {
		case 'p':
			if pid, err := strconv.Atoi(val); err == nil {
				curPID = pid
			}
			curProc = ""
		case 'c':
			curProc = val
		case 'n':
			arrowIdx := strings.Index(val, "->")
			if arrowIdx == -1 {
				// Skip lines without '->' (e.g. listening sockets or state tokens)
				continue
			}
			localStr := val[:arrowIdx]
			remoteStr := val[arrowIdx+2:]

			localAP, err := parseAddrPortString(localStr)
			if err != nil {
				continue
			}
			remoteAP, err := parseAddrPortString(remoteStr)
			if err != nil {
				continue
			}

			conns = append(conns, Conn{
				PID:     curPID,
				Process: curProc,
				Local:   localAP,
				Remote:  remoteAP,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan lsof output: %w", err)
	}

	return conns, nil
}

// ParseLsofBytes is a convenience helper parsing byte slice output.
func ParseLsofBytes(data []byte) ([]Conn, error) {
	return ParseLsof(bytes.NewReader(data))
}

func parseAddrPortString(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}

	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}

	// Remove zone identifier if present (e.g. fe80::1%en0)
	if idx := strings.Index(host, "%"); idx != -1 {
		host = host[:idx]
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port %q", portStr)
	}

	return netip.AddrPortFrom(addr, uint16(port)), nil
}
