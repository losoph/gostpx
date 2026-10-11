package notify

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/losoph/gostpx/internal/session"
)

// User-initiated disconnect reasons that should not trigger OS notifications.
const (
	ReasonUserDisabled   = "user disabled"
	ReasonStopped        = "stopped"
	ReasonQuit           = "quit"
	ReasonShutdown       = "shutdown"
	ReasonSignal         = "signal"
	ReasonSessionClosing = "session closing"
)

// UserReasons contains all reasons considered user-initiated.
var UserReasons = []string{
	ReasonUserDisabled,
	ReasonStopped,
	ReasonQuit,
	ReasonShutdown,
	ReasonSignal,
	ReasonSessionClosing,
}

// Notification titles.
const (
	TitleAuthFailed   = "gostpx: прокси отклонил вход"
	TitleDisconnected = "gostpx: соединение оборвано"
	TitleReconnected  = "gostpx: соединение восстановлено"
)

// Message represents a notification to present to the user.
type Message struct {
	Title string
	Body  string
}

// Policy manages notification episodes and rules across session events.
type Policy struct {
	mu             sync.Mutex
	inEpisode      bool
	disconnectedAt time.Time
}

// NewPolicy creates a new notification policy.
func NewPolicy() *Policy {
	return &Policy{}
}

// InEpisode returns whether a disconnected episode is currently active.
func (p *Policy) InEpisode() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inEpisode
}

// IsUserReason checks whether the given reason was initiated by the user.
func IsUserReason(reason string) bool {
	trimmed := strings.TrimSpace(reason)
	for _, r := range UserReasons {
		if trimmed == r {
			return true
		}
	}
	return false
}

// Next evaluates a session event against notification policy at time `now`.
// Returns the notification message and true if a notification should be presented.
func (p *Policy) Next(evt session.Event, now time.Time) (Message, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch evt.Type {
	case session.EventDisconnected:
		if IsUserReason(evt.Reason) {
			p.inEpisode = false
			p.disconnectedAt = time.Time{}
			return Message{}, false
		}

		if p.inEpisode {
			return Message{}, false
		}

		p.inEpisode = true
		p.disconnectedAt = now

		reason := truncateRunes(evt.Reason, 200)
		if strings.Contains(reason, "отказ в авторизации") {
			return Message{
				Title: TitleAuthFailed,
				Body:  fmt.Sprintf("%s. Переподключения не будет — проверьте логин и пароль в Настройках.", reason),
			}, true
		}

		return Message{
			Title: TitleDisconnected,
			// Not "reconnecting": a failed Restart from Settings disconnects without a
			// reconnect loop. The menu shows the actual phase.
			Body: fmt.Sprintf("%s. Трафик идёт напрямую.", reason),
		}, true

	case session.EventReconnected:
		if !p.inEpisode {
			return Message{}, false
		}

		discAt := p.disconnectedAt
		p.inEpisode = false
		p.disconnectedAt = time.Time{}

		durStr := FormatDuration(now.Sub(discAt))
		timeStr := discAt.Format("15:04")
		rttStr := FormatRTT(evt.RTT)

		return Message{
			Title: TitleReconnected,
			Body:  fmt.Sprintf("Трафик снова идёт через прокси. Обрыв в %s, напрямую %s.%s", timeStr, durStr, rttStr),
		}, true

	case session.EventConnected:
		p.inEpisode = false
		p.disconnectedAt = time.Time{}
		return Message{}, false

	default:
		// EventNetworkDown, EventNetworkUp, EventConfigReload, etc.
		return Message{}, false
	}
}

// FormatDuration formats elapsed time for disconnect notification.
// Displays in seconds (<120s) as "N с", or in minutes (>=120s) as "N мин".
func FormatDuration(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 0 {
		secs = 0
	}
	if secs >= 120 {
		return fmt.Sprintf("%d мин", secs/60)
	}
	return fmt.Sprintf("%d с", secs)
}

// FormatRTT formats RTT for reconnection notifications.
// Returns " Задержка N мс." for RTT >= 1ms, " Задержка <1 мс." for lower,
// and "" when RTT is unknown (zero).
func FormatRTT(rtt time.Duration) string {
	if rtt <= 0 {
		return ""
	}
	if rtt >= time.Millisecond {
		return fmt.Sprintf(" Задержка %d мс.", rtt.Milliseconds())
	}
	return " Задержка <1 мс."
}

// truncateRunes limits a string to maxRunes Unicode runes without breaking UTF-8 encoding.
func truncateRunes(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return s
}

// TruncateUTF16 limits s to at most maxUnits UTF-16 code units (16-bit words)
// without breaking surrogate pairs. If maxUnits <= 0 or s is empty, it returns "".
func TruncateUTF16(s string, maxUnits int) string {
	if maxUnits <= 0 || s == "" {
		return ""
	}
	units := 0
	for i, r := range s {
		rlen := utf16.RuneLen(r)
		if rlen <= 0 {
			rlen = 1
		}
		if units+rlen > maxUnits {
			return s[:i]
		}
		units += rlen
	}
	return s
}
