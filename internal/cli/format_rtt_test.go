package cli

import (
	"testing"
	"time"
)

func TestFormatRTT(t *testing.T) {
	tests := []struct {
		name string
		rtt  time.Duration
		want string
	}{
		{
			name: "500 microseconds",
			rtt:  500 * time.Microsecond,
			want: "<1 ms",
		},
		{
			name: "42 milliseconds",
			rtt:  42 * time.Millisecond,
			want: "42 ms",
		},
		{
			name: "1 millisecond",
			rtt:  1 * time.Millisecond,
			want: "1 ms",
		},
		{
			name: "999 microseconds",
			rtt:  999 * time.Microsecond,
			want: "<1 ms",
		},
		{
			name: "100 microseconds",
			rtt:  100 * time.Microsecond,
			want: "<1 ms",
		},
		{
			name: "0 duration",
			rtt:  0,
			want: "0 ms",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatRTT(tc.rtt)
			if got != tc.want {
				t.Errorf("FormatRTT(%v) = %q, want %q", tc.rtt, got, tc.want)
			}
		})
	}
}
