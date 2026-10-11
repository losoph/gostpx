package autostart

import (
	"testing"
)

func TestCurrentExecutable(t *testing.T) {
	exe, err := CurrentExecutable()
	if err != nil {
		t.Fatalf("CurrentExecutable failed: %v", err)
	}
	if exe == "" {
		t.Fatalf("CurrentExecutable returned empty path")
	}
}
