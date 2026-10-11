//go:build windows

package main

import (
	"fmt"
	"os"
	"reflect"
	"runtime/debug"
	"sync"
	"syscall"
	"unsafe"

	"github.com/losoph/gostpx/internal/notify"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/w32"
)

const (
	expectedWailsModule  = "github.com/wailsapp/wails/v3"
	expectedWailsVersion = "v3.0.0-beta.25"
)

var (
	trayInstance *application.SystemTray

	notifyMu       sync.Mutex
	notifyDisabled bool
	notifyErrOnce  sync.Once

	cachedHwnd w32.HWND
	cachedUID  uint32
	cachedInit bool
)

func initNotifications(tray *application.SystemTray) {
	if isSelftest() {
		return
	}
	notifyMu.Lock()
	defer notifyMu.Unlock()
	trayInstance = tray
}

func disableNotifications(reason string) {
	notifyDisabled = true
	notifyErrOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "gostpxw: уведомления трея отключены: %s\n", reason)
	})
}

func verifyWailsVersion() error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("информация о сборке (BuildInfo) недоступна")
	}
	for _, dep := range info.Deps {
		if dep.Path == expectedWailsModule {
			if dep.Version != expectedWailsVersion {
				return fmt.Errorf("версия %s (%s) не совпадает с %s", expectedWailsModule, dep.Version, expectedWailsVersion)
			}
			return nil
		}
	}
	return fmt.Errorf("модуль %s не найден в BuildInfo", expectedWailsModule)
}

func extractTrayHandles(tray *application.SystemTray) (w32.HWND, uint32, error) {
	if tray == nil {
		return 0, 0, fmt.Errorf("экземпляр SystemTray равен nil")
	}

	trayVal := reflect.ValueOf(tray)
	if trayVal.Kind() != reflect.Pointer || trayVal.IsNil() {
		return 0, 0, fmt.Errorf("tray не является валидным указателем")
	}

	trayElem := trayVal.Elem()
	if trayElem.Kind() != reflect.Struct {
		return 0, 0, fmt.Errorf("tray не указывает на структуру")
	}

	implField := trayElem.FieldByName("impl")
	if !implField.IsValid() {
		return 0, 0, fmt.Errorf("поле impl не найдено в SystemTray")
	}
	if implField.Kind() != reflect.Interface || implField.IsNil() {
		return 0, 0, fmt.Errorf("поле impl не является непустым интерфейсом")
	}

	implVal := implField.Elem()
	if !implVal.IsValid() || implVal.Kind() != reflect.Pointer || implVal.IsNil() {
		return 0, 0, fmt.Errorf("значение impl не является валидным указателем на структуру")
	}

	structVal := implVal.Elem()
	if !structVal.IsValid() || structVal.Kind() != reflect.Struct {
		return 0, 0, fmt.Errorf("impl не указывает на структуру windowsSystemTray")
	}
	structType := structVal.Type()

	hwndField, hasHwnd := structType.FieldByName("hwnd")
	if !hasHwnd {
		return 0, 0, fmt.Errorf("поле hwnd не найдено в структуре трея")
	}
	if hwndField.Type.Kind() != reflect.Uintptr {
		return 0, 0, fmt.Errorf("поле hwnd имеет тип %s, ожидался uintptr", hwndField.Type.Kind())
	}

	uidField, hasUid := structType.FieldByName("uid")
	if !hasUid {
		return 0, 0, fmt.Errorf("поле uid не найдено в структуре трея")
	}
	if uidField.Type.Kind() != reflect.Uint32 {
		return 0, 0, fmt.Errorf("поле uid имеет тип %s, ожидался uint32", uidField.Type.Kind())
	}

	basePtr := implVal.UnsafePointer()
	if basePtr == nil {
		return 0, 0, fmt.Errorf("базовый указатель структуры трея равен nil")
	}

	hwndRaw := *(*uintptr)(unsafe.Pointer(uintptr(basePtr) + hwndField.Offset))
	uidRaw := *(*uint32)(unsafe.Pointer(uintptr(basePtr) + uidField.Offset))

	if hwndRaw == 0 {
		return 0, 0, fmt.Errorf("hwnd == 0 (окно трея ещё не инициализировано)")
	}

	return w32.HWND(hwndRaw), uidRaw, nil
}

func getTrayHandles() (w32.HWND, uint32, bool) {
	notifyMu.Lock()
	defer notifyMu.Unlock()

	if notifyDisabled {
		return 0, 0, false
	}

	if cachedInit {
		return cachedHwnd, cachedUID, true
	}

	defer func() {
		if r := recover(); r != nil {
			disableNotifications(fmt.Sprintf("паника при получении дескрипторов трея: %v", r))
		}
	}()

	if err := verifyWailsVersion(); err != nil {
		disableNotifications(err.Error())
		return 0, 0, false
	}

	hwnd, uid, err := extractTrayHandles(trayInstance)
	if err != nil {
		disableNotifications(err.Error())
		return 0, 0, false
	}

	cachedHwnd = hwnd
	cachedUID = uid
	cachedInit = true
	return hwnd, uid, true
}

func showTrayBalloon(hwnd w32.HWND, uid uint32, title, body string) {
	truncTitle := notify.TruncateUTF16(title, 63)
	truncBody := notify.TruncateUTF16(body, 255)

	titleUnits, err := w32.StringToUTF16(truncTitle)
	if err != nil {
		titleUnits, _ = syscall.UTF16FromString(truncTitle)
	}
	bodyUnits, err := w32.StringToUTF16(truncBody)
	if err != nil {
		bodyUnits, _ = syscall.UTF16FromString(truncBody)
	}

	var dwInfoFlags uint32
	if title == notify.TitleReconnected {
		dwInfoFlags = uint32(w32.NIIF_INFO | w32.NIIF_RESPECT_QUIET_TIME)
	} else {
		dwInfoFlags = uint32(w32.NIIF_WARNING | w32.NIIF_RESPECT_QUIET_TIME)
	}

	nid := w32.NOTIFYICONDATA{
		HWnd:        hwnd,
		UID:         uid,
		UFlags:      w32.NIF_INFO,
		DwInfoFlags: dwInfoFlags,
	}
	nid.CbSize = uint32(unsafe.Sizeof(nid))

	copy(nid.SzInfoTitle[:], titleUnits)
	copy(nid.SzInfo[:], bodyUnits)

	w32.ShellNotifyIcon(uintptr(w32.NIM_MODIFY), &nid)
}

func sendNotification(title, body string) {
	if isSelftest() {
		return
	}

	hwnd, uid, ok := getTrayHandles()
	if !ok {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			disableNotifications(fmt.Sprintf("паника при отправке уведомления: %v", r))
		}
	}()

	showTrayBalloon(hwnd, uid, title, body)
}
