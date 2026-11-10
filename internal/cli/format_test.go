package cli

import "testing"

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "-"},
		{512, "512.0 BiB"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{8 << 20, "8.0 MiB"},
		{10603484383, "9.9 GiB"},
		{1 << 40, "1.0 TiB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
