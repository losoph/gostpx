//go:build windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

func guiHint(dir string) string {
	guiPath := filepath.Join(dir, "gostpxw.exe")
	if _, err := os.Stat(guiPath); err == nil {
		return "Для запуска в графическом режиме (трей): gostpxw.exe"
	}
	return ""
}

func printGuiHint() {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	if hint := guiHint(filepath.Dir(execPath)); hint != "" {
		fmt.Println(hint)
	}
}
