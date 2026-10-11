//go:build darwin

package connwatch

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Take captures the current established TCP connections for the current user using lsof.
func Take(ctx context.Context) ([]Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	uid := strconv.Itoa(os.Getuid())
	cmd := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-a", "-u", uid, "-F", "pcn")
	out, err := cmd.Output()
	if err != nil {
		// When lsof finds 0 matching connections, it exits with exit code 1.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 && len(out) == 0 {
			return []Conn{}, nil
		}
		return nil, err
	}

	return ParseLsofBytes(out)
}
