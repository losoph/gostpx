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
