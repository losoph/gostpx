//go:build windows

package sysproxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

// WinINET system proxy lives in the current user's hive. Only the HTTP proxy
// is set: Windows has no system-level SOCKS5, so socksAddr is not published
// (see docs/PLATFORM-NOTES.md). ProxyOverride is left untouched (ADR-008).
const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

const serviceName = `WinINET (HKCU\` + internetSettingsKey + `)`

const (
	internetOptionRefresh              = 37
	internetOptionSettingsChanged      = 39
	internetOptionProxySettingsChanged = 95
)

var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	procRegSetValueExW  = advapi32.NewProc("RegSetValueExW")
	wininet             = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptW = wininet.NewProc("InternetSetOptionW")
)

// Set points WinINET at the local HTTP listener and enables it.
func Set(httpAddr, socksAddr string) error {
	if path := dryFile(); path != "" {
		return drySet(path, httpAddr, socksAddr)
	}
	if err := guardRealChange(); err != nil {
		return err
	}
	host, port, err := parseHostPort(httpAddr)
	if err != nil {
		return fmt.Errorf("invalid httpAddr %q: %w", httpAddr, err)
	}
	server := net.JoinHostPort(host, strconv.Itoa(port))

	k, err := openSettings(syscall.KEY_SET_VALUE)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)

	if err := setString(k, "ProxyServer", server); err != nil {
		return fmt.Errorf("write ProxyServer: %w", err)
	}
	if err := setDWORD(k, "ProxyEnable", 1); err != nil {
		return fmt.Errorf("write ProxyEnable: %w", err)
	}
	if err := notifyWinINET(); err != nil {
		// The caller does not call Unset when Set fails: roll back here so the
		// system is not left pointing at a listener that is about to stop.
		_ = setDWORD(k, "ProxyEnable", 0)
		_ = notifyWinINET()
		return fmt.Errorf("notify WinINET: %w", err)
	}
	return nil
}

// TakeSnapshot captures the current WinINET proxy configuration before gostpx modifies it (ADR-015).
func TakeSnapshot() (*Snapshot, error) {
	if path := dryFile(); path != "" {
		return takeSnapshotDry(path)
	}
	k, err := openSettings(syscall.KEY_QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer syscall.RegCloseKey(k)

	winSnap := &WindowsSnapshot{}
	enable, err := getDWORD(k, "ProxyEnable")
	if err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, fmt.Errorf("read ProxyEnable: %w", err)
	}
	if err == nil {
		winSnap.ProxyEnable = enable
	}

	server, err := getString(k, "ProxyServer")
	if err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, fmt.Errorf("read ProxyServer: %w", err)
	}
	if err == nil {
		winSnap.ProxyServer = server
	}

	override, err := getString(k, "ProxyOverride")
	if err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, fmt.Errorf("read ProxyOverride: %w", err)
	}
	if err == nil {
		winSnap.ProxyOverride = override
	}

	return &Snapshot{
		Windows: winSnap,
	}, nil
}

// Unset restores WinINET proxy settings from snapshot if current settings still point
// to our proxy (httpListen). If current settings do not match our proxy (e.g. modified
// by another program), they are left untouched (ADR-015).
func Unset(snap *Snapshot, httpListen, socksListen string) error {
	if path := dryFile(); path != "" {
		return dryUnset(path, snap, httpListen, socksListen)
	}
	if err := guardRealChange(); err != nil {
		return err
	}
	k, err := openSettings(syscall.KEY_SET_VALUE | syscall.KEY_QUERY_VALUE)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)

	// If httpListen is specified, verify current settings still point to our proxy
	if httpListen != "" {
		enable, _ := getDWORD(k, "ProxyEnable")
		server, _ := getString(k, "ProxyServer")
		if enable != 0 {
			host, port, ok := parseProxyServer(server)
			if !ok || !matchesListenAddr(host, port, httpListen) {
				// Settings do not point to our proxy, leave untouched
				return nil
			}
		} else {
			host, port, ok := parseProxyServer(server)
			if ok && !matchesListenAddr(host, port, httpListen) {
				return nil
			}
		}
	}

	if snap != nil && snap.Windows != nil {
		if snap.Windows.ProxyServer != "" {
			if err := setString(k, "ProxyServer", snap.Windows.ProxyServer); err != nil {
				return fmt.Errorf("restore ProxyServer: %w", err)
			}
		}
		if snap.Windows.ProxyOverride != "" {
			if err := setString(k, "ProxyOverride", snap.Windows.ProxyOverride); err != nil {
				return fmt.Errorf("restore ProxyOverride: %w", err)
			}
		}
		if err := setDWORD(k, "ProxyEnable", snap.Windows.ProxyEnable); err != nil {
			return fmt.Errorf("restore ProxyEnable: %w", err)
		}
	} else {
		if err := setDWORD(k, "ProxyEnable", 0); err != nil {
			return fmt.Errorf("write ProxyEnable: %w", err)
		}
	}

	if err := notifyWinINET(); err != nil {
		return fmt.Errorf("notify WinINET: %w", err)
	}
	return nil
}

// Current reads the WinINET proxy settings of the current user.
func Current() (*Status, error) {
	if path := dryFile(); path != "" {
		return dryCurrent(path)
	}
	k, err := openSettings(syscall.KEY_QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer syscall.RegCloseKey(k)

	st := &Status{Service: serviceName}

	enable, err := getDWORD(k, "ProxyEnable")
	if err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, fmt.Errorf("read ProxyEnable: %w", err)
	}
	server, err := getString(k, "ProxyServer")
	if err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, fmt.Errorf("read ProxyServer: %w", err)
	}

	if host, port, ok := parseProxyServer(server); ok {
		st.HTTPHost = host
		st.HTTPPort = port
	}
	st.Enabled = enable != 0 && st.HTTPHost != ""
	return st, nil
}

func openSettings(access uint32) (syscall.Handle, error) {
	path, err := syscall.UTF16PtrFromString(internetSettingsKey)
	if err != nil {
		return 0, fmt.Errorf("encode registry path: %w", err)
	}
	var k syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, path, 0, access, &k); err != nil {
		return 0, fmt.Errorf("open HKCU\\%s: %w", internetSettingsKey, err)
	}
	return k, nil
}

func setValue(k syscall.Handle, name string, typ uint32, data []byte) error {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var p *byte
	if len(data) > 0 {
		p = &data[0]
	}
	r, _, _ := procRegSetValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(n)), 0,
		uintptr(typ), uintptr(unsafe.Pointer(p)), uintptr(len(data)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func setDWORD(k syscall.Handle, name string, v uint32) error {
	b := (*[4]byte)(unsafe.Pointer(&v))[:]
	return setValue(k, name, syscall.REG_DWORD, b)
}

func setString(k syscall.Handle, name, v string) error {
	u, err := syscall.UTF16FromString(v)
	if err != nil {
		return err
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2)
	return setValue(k, name, syscall.REG_SZ, b)
}

func queryValue(k syscall.Handle, name string) (uint32, []byte, error) {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, nil, err
	}
	var typ, size uint32
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, nil, &size); err != nil {
		return 0, nil, err
	}
	if size == 0 {
		return typ, nil, nil
	}
	buf := make([]byte, size)
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, &buf[0], &size); err != nil {
		return 0, nil, err
	}
	return typ, buf[:size], nil
}

func getDWORD(k syscall.Handle, name string) (uint32, error) {
	typ, b, err := queryValue(k, name)
	if err != nil {
		return 0, err
	}
	if typ != syscall.REG_DWORD || len(b) < 4 {
		return 0, fmt.Errorf("%s: unexpected registry type %d", name, typ)
	}
	return *(*uint32)(unsafe.Pointer(&b[0])), nil
}

func getString(k syscall.Handle, name string) (string, error) {
	typ, b, err := queryValue(k, name)
	if err != nil {
		return "", err
	}
	if typ != syscall.REG_SZ && typ != syscall.REG_EXPAND_SZ {
		return "", fmt.Errorf("%s: unexpected registry type %d", name, typ)
	}
	if len(b) < 2 {
		return "", nil
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	return syscall.UTF16ToString(u), nil
}

// notifyWinINET makes running WinINET consumers re-read the registry.
// PROXY_SETTINGS_CHANGED is best-effort; the other two are required.
func notifyWinINET() error {
	_, _, _ = procInternetSetOptW.Call(0, internetOptionProxySettingsChanged, 0, 0)
	for _, opt := range []uintptr{
		internetOptionSettingsChanged,
		internetOptionRefresh,
	} {
		r, _, err := procInternetSetOptW.Call(0, opt, 0, 0)
		if r == 0 {
			return fmt.Errorf("InternetSetOption(%d): %w", opt, err)
		}
	}
	return nil
}
