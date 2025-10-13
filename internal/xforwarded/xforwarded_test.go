package xforwarded

import (
	"net"
	"testing"
)

func TestFromXFF(t *testing.T) {
	tests := []struct {
		name         string
		src          string
		xff          string
		trusted      []string
		want         net.IP
		wantStripped int
	}{
		{
			name:         "no xff",
			src:          "198.51.100.10",
			xff:          "",
			trusted:      nil,
			want:         net.ParseIP("198.51.100.10"),
			wantStripped: 0,
		},
		{
			name:         "xff ignored when peer not trusted",
			src:          "198.51.100.10",
			xff:          "203.0.113.9, 198.51.100.10",
			trusted:      nil,
			want:         net.ParseIP("198.51.100.10"),
			wantStripped: 0,
		},
		{
			name:         "single trusted proxy stripped",
			src:          "192.0.2.5",
			xff:          "203.0.113.44, 192.0.2.5",
			trusted:      []string{"192.0.2.5"},
			want:         net.ParseIP("203.0.113.44"),
			wantStripped: 1,
		},
		{
			name:         "multiple trusted proxies stripped",
			src:          "192.0.2.5",
			xff:          "198.51.100.61, 203.0.113.10, 192.0.2.5",
			trusted:      []string{"192.0.2.5", "203.0.113.10"},
			want:         net.ParseIP("198.51.100.61"),
			wantStripped: 2,
		},
		{
			name:         "ipv6 canonical comparison",
			src:          "2001:db8::5",
			xff:          "2001:db8::1, 2001:db8::5",
			trusted:      []string{"2001:0db8:0000:0000:0000:0000:0000:0005"},
			want:         net.ParseIP("2001:db8::1"),
			wantStripped: 1,
		},
		{
			name:         "trusted network",
			src:          "192.0.2.10",
			xff:          "198.51.100.22, 203.0.113.45, 192.0.2.10",
			trusted:      []string{"192.0.2.0/24", "203.0.113.45"},
			want:         net.ParseIP("198.51.100.22"),
			wantStripped: 2,
		},
		{
			name:         "untrusted src despite trusted entries",
			src:          "198.51.100.10",
			xff:          "203.0.113.44, 198.51.100.10",
			trusted:      []string{"192.0.2.5"},
			want:         net.ParseIP("198.51.100.10"),
			wantStripped: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trusted := NewTrusted(tt.trusted)
			got, stripped := FromXFF(tt.src, tt.xff, trusted)
			if (got == nil) != (tt.want == nil) {
				t.Fatalf("FromXFF() = %v, want %v", got, tt.want)
			}
			if got != nil && !got.Equal(tt.want) {
				t.Fatalf("FromXFF() = %v, want %v", got, tt.want)
			}
			if stripped != tt.wantStripped {
				t.Fatalf("FromXFF() stripped=%d, want %d", stripped, tt.wantStripped)
			}
		})
	}
}
