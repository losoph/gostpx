package main

import (
	"os"

	"github.com/losoph/gostpx/internal/cli"
)

func main() {
	if len(os.Args) > 1 {
		cli.Execute()
		return
	}
	runTray()
}
