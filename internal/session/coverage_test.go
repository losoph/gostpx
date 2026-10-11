package session

import (
	"strings"
	"testing"
)

func TestSysproxyCoverageLines(t *testing.T) {
	lines := SysproxyCoverageLines()
	if len(lines) != 4 {
		t.Fatalf("expected 4 coverage lines, got %d", len(lines))
	}

	expectedPrefixes := []string{
		"  охват           только приложения, уважающие системный прокси",
		"  имена           резолвит апстрим, локально не резолвим",
		"  ⚠ не в прокси   программы со своим стеком (curl, git), UDP/QUIC, чужие резолверы",
		"  ⚠ DoH           не применяется в этом режиме",
	}

	for i, expected := range expectedPrefixes {
		if lines[i] != expected {
			t.Errorf("line %d mismatch:\nexpected: %q\ngot:      %q", i, expected, lines[i])
		}
	}
}

func TestSysproxyCoverageItems(t *testing.T) {
	items := SysproxyCoverageItems()
	if len(items) != 4 {
		t.Fatalf("expected 4 coverage items, got %d", len(items))
	}

	if items[0].Warning || items[1].Warning {
		t.Errorf("first two items must not be warnings")
	}
	if !items[2].Warning || !items[3].Warning {
		t.Errorf("last two items must be warnings")
	}

	if !strings.Contains(items[2].Text, "чужие резолверы") {
		t.Errorf("expected 'чужие резолверы' in item 2, got: %s", items[2].Text)
	}
}
