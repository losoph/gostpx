//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "gostpxw is only supported on Windows")
	os.Exit(1)
}
