package notify

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/losoph/gostpx/internal/session"
)

func TestPolicy_ReconnectedDurationAndTime(t *testing.T) {
	tests := []struct {
		name         string
		disconnectAt time.Time
		reconnectAt  time.Time
		wantTime     string
		wantDur      string
	}{
		{
			name:         "45 seconds disconnect",
			disconnectAt: time.Date(2026, 10, 11, 14, 30, 0, 0, time.UTC),
			reconnectAt:  time.Date(2026, 10, 11, 14, 30, 45, 0, time.UTC),
			wantTime:     "14:30",
			wantDur:      "45 с",
		},
		{
			name:         "300 seconds disconnect (5 min)",
			disconnectAt: time.Date(2026, 10, 11, 14, 30, 0, 0, time.UTC),
			reconnectAt:  time.Date(2026, 10, 11, 14, 35, 0, 0, time.UTC),
			wantTime:     "14:30",
			wantDur:      "5 мин",
		},
		{
			name:         "119 seconds disconnect",
			disconnectAt: time.Date(2026, 10, 11, 9, 15, 0, 0, time.UTC),
			reconnectAt:  time.Date(2026, 10, 11, 9, 16, 59, 0, time.UTC),
			wantTime:     "09:15",
			wantDur:      "119 с",
		},
		{
			name:         "120 seconds disconnect (2 min)",
			disconnectAt: time.Date(2026, 10, 11, 9, 15, 0, 0, time.UTC),
			reconnectAt:  time.Date(2026, 10, 11, 9, 17, 0, 0, time.UTC),
			wantTime:     "09:15",
			wantDur:      "2 мин",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPolicy()

			// 1. Disconnect event
			discEvt := session.Event{
				Type:   session.EventDisconnected,
				Reason: "connection reset by peer",
			}
			msg, ok := p.Next(discEvt, tc.disconnectAt)
			if !ok {
				t.Fatalf("expected notification on disconnect, got none")
			}
			if msg.Title != TitleDisconnected {
				t.Fatalf("unexpected disconnect title: got %q, want %q", msg.Title, TitleDisconnected)
			}

			// 2. Reconnect event
			recEvt := session.Event{
				Type:   session.EventReconnected,
				Reason: "reconnected",
				RTT:    15 * time.Millisecond,
			}
			recMsg, recOK := p.Next(recEvt, tc.reconnectAt)
			if !recOK {
				t.Fatalf("expected notification on reconnected, got none")
			}
			if recMsg.Title != TitleReconnected {
				t.Fatalf("unexpected reconnected title: got %q, want %q", recMsg.Title, TitleReconnected)
			}

			expectedTimeSub := "Обрыв в " + tc.wantTime
			if !strings.Contains(recMsg.Body, expectedTimeSub) {
				t.Errorf("expected body to contain %q, got: %s", expectedTimeSub, recMsg.Body)
			}

			expectedDurSub := "напрямую " + tc.wantDur
			if !strings.Contains(recMsg.Body, expectedDurSub) {
				t.Errorf("expected body to contain %q, got: %s", expectedDurSub, recMsg.Body)
			}
		})
	}
}

func TestPolicy_EventTable(t *testing.T) {
	baseTime := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)

	t.Run("single disconnect notification per episode", func(t *testing.T) {
		p := NewPolicy()
		evt := session.Event{Type: session.EventDisconnected, Reason: "network unreachable"}

		// First disconnect: should notify
		msg, ok := p.Next(evt, baseTime)
		if !ok {
			t.Fatalf("expected notification on first disconnect")
		}
		if msg.Title != TitleDisconnected {
			t.Errorf("expected title %q, got %q", TitleDisconnected, msg.Title)
		}
		if !strings.Contains(msg.Body, "Трафик идёт напрямую.") {
			t.Errorf("unexpected body: %s", msg.Body)
		}

		// Second disconnect without reconnect: should NOT notify
		msg2, ok2 := p.Next(evt, baseTime.Add(10*time.Second))
		if ok2 {
			t.Errorf("expected no notification on repeated disconnect, got: %+v", msg2)
		}
	})

	t.Run("reconnect without preceding disconnect yields no notification", func(t *testing.T) {
		p := NewPolicy()
		evt := session.Event{Type: session.EventReconnected, Reason: "reconnected", RTT: 10 * time.Millisecond}

		msg, ok := p.Next(evt, baseTime)
		if ok {
			t.Errorf("expected no notification on reconnect without prior disconnect, got: %+v", msg)
		}
	})

	t.Run("all user reasons yield no notification", func(t *testing.T) {
		for _, userReason := range UserReasons {
			t.Run(userReason, func(t *testing.T) {
				p := NewPolicy()
				evt := session.Event{Type: session.EventDisconnected, Reason: userReason}

				msg, ok := p.Next(evt, baseTime)
				if ok {
					t.Errorf("expected no notification for user reason %q, got: %+v", userReason, msg)
				}
				if p.InEpisode() {
					t.Errorf("policy should not be in episode after user disconnect")
				}
			})
		}
	})

	t.Run("auth rejection notification", func(t *testing.T) {
		p := NewPolicy()
		evt := session.Event{
			Type:   session.EventDisconnected,
			Reason: "отказ в авторизации: 407 Proxy Authentication Required",
		}

		msg, ok := p.Next(evt, baseTime)
		if !ok {
			t.Fatalf("expected notification on auth failure")
		}
		if msg.Title != TitleAuthFailed {
			t.Errorf("expected title %q, got %q", TitleAuthFailed, msg.Title)
		}
		expectedSub := "отказ в авторизации: 407 Proxy Authentication Required. Переподключения не будет — проверьте логин и пароль в Настройках."
		if msg.Body != expectedSub {
			t.Errorf("expected body %q, got %q", expectedSub, msg.Body)
		}
	})

	t.Run("long reason rune truncation preserves valid UTF-8", func(t *testing.T) {
		p := NewPolicy()
		// 250 multi-byte Cyrillic characters (2 bytes each in UTF-8)
		longCyrillic := strings.Repeat("ш", 250)
		evt := session.Event{
			Type:   session.EventDisconnected,
			Reason: longCyrillic,
		}

		msg, ok := p.Next(evt, baseTime)
		if !ok {
			t.Fatalf("expected notification")
		}
		if !utf8.ValidString(msg.Body) {
			t.Fatalf("body contains invalid UTF-8")
		}

		// Truncated reason should have exactly 200 'ш' runes
		expectedPrefix := strings.Repeat("ш", 200) + ". Трафик идёт напрямую."
		if msg.Body != expectedPrefix {
			t.Errorf("body truncation mismatch: rune count of body = %d", utf8.RuneCountInString(msg.Body))
		}
	})

	t.Run("RTT formatting: 500 us yields <1 ms, 42 ms yields 42 ms", func(t *testing.T) {
		p := NewPolicy()
		// Disconnect first to start episode
		p.Next(session.Event{Type: session.EventDisconnected, Reason: "error"}, baseTime)

		// 500 microseconds
		recEvt500us := session.Event{
			Type:   session.EventReconnected,
			Reason: "reconnected",
			RTT:    500 * time.Microsecond,
		}
		msg500us, ok := p.Next(recEvt500us, baseTime.Add(10*time.Second))
		if !ok {
			t.Fatalf("expected notification")
		}
		if !strings.Contains(msg500us.Body, "<1 мс") {
			t.Errorf("expected body to contain '<1 мс', got: %s", msg500us.Body)
		}

		// Disconnect again for second test
		p.Next(session.Event{Type: session.EventDisconnected, Reason: "error"}, baseTime.Add(20*time.Second))

		// 42 milliseconds
		recEvt42ms := session.Event{
			Type:   session.EventReconnected,
			Reason: "reconnected",
			RTT:    42 * time.Millisecond,
		}
		msg42ms, ok := p.Next(recEvt42ms, baseTime.Add(30*time.Second))
		if !ok {
			t.Fatalf("expected notification")
		}
		if !strings.Contains(msg42ms.Body, "42 мс") {
			t.Errorf("expected body to contain '42 мс', got: %s", msg42ms.Body)
		}
	})

	t.Run("EventConnected closes episode without notification", func(t *testing.T) {
		p := NewPolicy()
		// Start episode with abnormal disconnect
		p.Next(session.Event{Type: session.EventDisconnected, Reason: "connection reset"}, baseTime)
		if !p.InEpisode() {
			t.Fatalf("expected episode to be active")
		}

		// Manual connect closes episode without notification
		msg, ok := p.Next(session.Event{Type: session.EventConnected}, baseTime.Add(5*time.Second))
		if ok {
			t.Errorf("expected no notification on EventConnected, got: %+v", msg)
		}
		if p.InEpisode() {
			t.Errorf("expected episode to be closed after EventConnected")
		}

		// Subsequent reconnected should not notify because episode was closed
		msgRec, okRec := p.Next(session.Event{Type: session.EventReconnected, RTT: 10 * time.Millisecond}, baseTime.Add(10*time.Second))
		if okRec {
			t.Errorf("expected no notification on reconnected after closed episode, got: %+v", msgRec)
		}
	})

	t.Run("ignorable events yield no notifications and do not alter episode", func(t *testing.T) {
		p := NewPolicy()
		p.Next(session.Event{Type: session.EventDisconnected, Reason: "upstream drop"}, baseTime)

		ignorable := []session.EventType{
			session.EventNetworkDown,
			session.EventNetworkUp,
			session.EventConfigReload,
		}

		for _, evtType := range ignorable {
			msg, ok := p.Next(session.Event{Type: evtType}, baseTime.Add(5*time.Second))
			if ok {
				t.Errorf("expected no notification for event %s, got: %+v", evtType, msg)
			}
			if !p.InEpisode() {
				t.Errorf("expected episode to stay active after event %s", evtType)
			}
		}
	})
}

func TestFormatRTTUnknownIsEmpty(t *testing.T) {
	if got := FormatRTT(0); got != "" {
		t.Errorf("FormatRTT(0) = %q, want empty", got)
	}
}

func TestTruncateUTF16(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxUnits int
		want     string
	}{
		// 1. Empty string
		{name: "empty string with positive maxUnits", input: "", maxUnits: 10, want: ""},
		{name: "empty string with zero maxUnits", input: "", maxUnits: 0, want: ""},
		{name: "empty string with negative maxUnits", input: "", maxUnits: -1, want: ""},

		// 2. Zero or negative maxUnits
		{name: "non-empty with zero maxUnits", input: "hello", maxUnits: 0, want: ""},
		{name: "non-empty with negative maxUnits", input: "hello", maxUnits: -3, want: ""},

		// 3. ASCII
		{name: "ASCII truncate partial", input: "hello world", maxUnits: 5, want: "hello"},
		{name: "ASCII exact fit", input: "hello", maxUnits: 5, want: "hello"},
		{name: "ASCII larger maxUnits", input: "hello", maxUnits: 10, want: "hello"},

		// 4. Cyrillic (multibyte UTF-8, single UTF-16 code units)
		{name: "Cyrillic truncate partial", input: "привет, мир!", maxUnits: 6, want: "привет"},
		{name: "Cyrillic exact fit", input: "привет", maxUnits: 6, want: "привет"},
		{name: "Cyrillic larger maxUnits", input: "соединение оборвано", maxUnits: 50, want: "соединение оборвано"},

		// 5. Emoji (surrogate pairs outside BMP, 2 UTF-16 units each)
		{name: "single emoji maxUnits 1 does not break surrogate pair", input: "😀", maxUnits: 1, want: ""},
		{name: "single emoji exact fit 2 units", input: "😀", maxUnits: 2, want: "😀"},
		{name: "two emojis maxUnits 2 takes first", input: "👋🌍", maxUnits: 2, want: "👋"},
		{name: "two emojis maxUnits 3 does not split second surrogate pair", input: "👋🌍", maxUnits: 3, want: "👋"},
		{name: "two emojis exact fit 4 units", input: "👋🌍", maxUnits: 4, want: "👋🌍"},

		// 6. Mixed strings
		{name: "mixed ASCII and emoji maxUnits odd", input: "Hi 👋!", maxUnits: 4, want: "Hi "},
		{name: "mixed ASCII and emoji maxUnits includes emoji", input: "Hi 👋!", maxUnits: 5, want: "Hi 👋"},
		{name: "mixed ASCII and emoji full", input: "Hi 👋!", maxUnits: 6, want: "Hi 👋!"},
		{name: "mixed Cyrillic and emoji maxUnits odd does not break emoji", input: "Сеть 🌐 упала", maxUnits: 6, want: "Сеть "},
		{name: "mixed Cyrillic and emoji maxUnits even includes emoji", input: "Сеть 🌐 упала", maxUnits: 7, want: "Сеть 🌐"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TruncateUTF16(tc.input, tc.maxUnits)
			if got != tc.want {
				t.Errorf("TruncateUTF16(%q, %d) = %q, want %q", tc.input, tc.maxUnits, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("TruncateUTF16 produced invalid UTF-8 string: %q", got)
			}
		})
	}
}
