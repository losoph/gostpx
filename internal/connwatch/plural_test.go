package connwatch

import "testing"

func TestConnectionsWord(t *testing.T) {
	cases := map[int]string{0: "соединений", 1: "соединение", 2: "соединения", 4: "соединения", 5: "соединений",
		11: "соединений", 12: "соединений", 14: "соединений", 21: "соединение", 22: "соединения", 111: "соединений", 101: "соединение"}
	for n, want := range cases {
		if got := ConnectionsWord(n); got != want {
			t.Errorf("ConnectionsWord(%d) = %q, want %q", n, got, want)
		}
	}
}
