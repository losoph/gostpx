//go:build !darwin && !windows

package connwatch

import (
	"context"
	"errors"
)

// Take is unsupported on non-darwin non-windows platforms.
func Take(ctx context.Context) ([]Conn, error) {
	return nil, errors.New("не поддерживается")
}
