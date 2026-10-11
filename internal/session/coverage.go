package session

// SysproxyCoverageLines returns the exact normative coverage lines from docs/LIMITATIONS.md.
// Invariant 2: LIMITATIONS.md is normative; these strings must not diverge.
func SysproxyCoverageLines() []string {
	return []string{
		"  охват           только приложения, уважающие системный прокси",
		"  имена           резолвит апстрим, локально не резолвим",
		"  ⚠ не в прокси   программы со своим стеком (curl, git), UDP/QUIC, чужие резолверы",
		"  ⚠ DoH           не применяется в этом режиме",
	}
}

// CoverageItem represents an individual line of coverage information with its warning status.
type CoverageItem struct {
	Label   string
	Text    string
	Warning bool
}

// SysproxyCoverageItems returns structured coverage entries for UI/tray display.
func SysproxyCoverageItems() []CoverageItem {
	return []CoverageItem{
		{Label: "охват", Text: "только приложения, уважающие системный прокси", Warning: false},
		{Label: "имена", Text: "резолвит апстрим, локально не резолвим", Warning: false},
		{Label: "⚠ не в прокси", Text: "программы со своим стеком (curl, git), UDP/QUIC, чужие резолверы", Warning: true},
		{Label: "⚠ DoH", Text: "не применяется в этом режиме", Warning: true},
	}
}
