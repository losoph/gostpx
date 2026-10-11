//go:build windows

package connwatch

import (
	"context"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	afInet  = 2
	afInet6 = 23

	tcpTableOwnerPIDConnections = 4

	mibTcpStateEstab = 5

	processQueryLimitedInformation = 0x1000
)

var (
	iphlpapi                       = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable        = iphlpapi.NewProc("GetExtendedTcpTable")
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
)

type mibTcpRowOwnerPid struct {
	dwState      uint32
	dwLocalAddr  uint32
	dwLocalPort  uint32
	dwRemoteAddr uint32
	dwRemotePort uint32
	dwOwningPid  uint32
}

type mibTcp6RowOwnerPid struct {
	ucLocalAddr     [16]byte
	dwLocalScopeId  uint32
	dwLocalPort     uint32
	ucRemoteAddr    [16]byte
	dwRemoteScopeId uint32
	dwRemotePort    uint32
	dwState         uint32
	dwOwningPid     uint32
}

// Take captures established TCP connections for the current user on Windows.
func Take(ctx context.Context) ([]Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	procCache := make(map[int]string)
	var conns []Conn

	// 1. IPv4 table
	buf4, err := getTcpTable(afInet)
	if err != nil {
		return nil, err
	}
	if len(buf4) >= 4 {
		numEntries := *(*uint32)(unsafe.Pointer(&buf4[0]))
		rowSize := int(unsafe.Sizeof(mibTcpRowOwnerPid{}))
		for i := 0; i < int(numEntries); i++ {
			offset := 4 + i*rowSize
			if offset+rowSize > len(buf4) {
				break
			}
			row := (*mibTcpRowOwnerPid)(unsafe.Pointer(&buf4[offset]))
			if row.dwState != mibTcpStateEstab {
				continue
			}

			procName := getProcessName(int(row.dwOwningPid), procCache)
			if procName == "" {
				// Inaccessible process (another user or system service); skip
				continue
			}

			localAddr := netip.AddrFrom4([4]byte{
				byte(row.dwLocalAddr),
				byte(row.dwLocalAddr >> 8),
				byte(row.dwLocalAddr >> 16),
				byte(row.dwLocalAddr >> 24),
			})
			remoteAddr := netip.AddrFrom4([4]byte{
				byte(row.dwRemoteAddr),
				byte(row.dwRemoteAddr >> 8),
				byte(row.dwRemoteAddr >> 16),
				byte(row.dwRemoteAddr >> 24),
			})

			localPort := decodePort(row.dwLocalPort)
			remotePort := decodePort(row.dwRemotePort)

			conns = append(conns, Conn{
				PID:     int(row.dwOwningPid),
				Process: procName,
				Local:   netip.AddrPortFrom(localAddr, localPort),
				Remote:  netip.AddrPortFrom(remoteAddr, remotePort),
			})
		}
	}

	// 2. IPv6 table
	buf6, err := getTcpTable(afInet6)
	if err == nil && len(buf6) >= 4 {
		numEntries := *(*uint32)(unsafe.Pointer(&buf6[0]))
		rowSize := int(unsafe.Sizeof(mibTcp6RowOwnerPid{}))
		for i := 0; i < int(numEntries); i++ {
			offset := 4 + i*rowSize
			if offset+rowSize > len(buf6) {
				break
			}
			row := (*mibTcp6RowOwnerPid)(unsafe.Pointer(&buf6[offset]))
			if row.dwState != mibTcpStateEstab {
				continue
			}

			procName := getProcessName(int(row.dwOwningPid), procCache)
			if procName == "" {
				continue
			}

			localAddr := netip.AddrFrom16(row.ucLocalAddr)
			remoteAddr := netip.AddrFrom16(row.ucRemoteAddr)

			localPort := decodePort(row.dwLocalPort)
			remotePort := decodePort(row.dwRemotePort)

			conns = append(conns, Conn{
				PID:     int(row.dwOwningPid),
				Process: procName,
				Local:   netip.AddrPortFrom(localAddr, localPort),
				Remote:  netip.AddrPortFrom(remoteAddr, remotePort),
			})
		}
	}

	return conns, nil
}

func getTcpTable(family uint32) ([]byte, error) {
	var size uint32
	r, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0, // bOrder = FALSE
		uintptr(family),
		uintptr(tcpTableOwnerPIDConnections),
		0,
	)
	if r != 0 && r != 122 { // 122 = ERROR_INSUFFICIENT_BUFFER
		return nil, syscall.Errno(r)
	}
	if size == 0 {
		return nil, nil
	}

	// The table can grow between the size query and the read: retry with the
	// size Windows reports, a few times, instead of failing on the first race.
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, size)
		r, _, _ = procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder = FALSE
			uintptr(family),
			uintptr(tcpTableOwnerPIDConnections),
			0,
		)
		if r == 0 {
			return buf, nil
		}
		if r != 122 { // 122 = ERROR_INSUFFICIENT_BUFFER
			return nil, syscall.Errno(r)
		}
	}
	return nil, syscall.Errno(r)
}

func getProcessName(pid int, cache map[int]string) string {
	if name, ok := cache[pid]; ok {
		return name
	}
	if pid == 0 {
		return ""
	}

	handle, _, _ := procOpenProcess.Call(
		processQueryLimitedInformation,
		0,
		uintptr(pid),
	)
	if handle == 0 {
		cache[pid] = ""
		return ""
	}
	defer procCloseHandle.Call(handle)

	var buf [1024]uint16
	size := uint32(len(buf))
	r, _, _ := procQueryFullProcessImageNameW.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 || size == 0 {
		cache[pid] = ""
		return ""
	}

	name := filepath.Base(syscall.UTF16ToString(buf[:size]))
	cache[pid] = name
	return name
}

func decodePort(dwPort uint32) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(dwPort), byte(dwPort >> 8)})
}
