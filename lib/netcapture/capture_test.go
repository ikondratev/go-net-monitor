package netcapture

import "testing"

func TestBuildPacketFilter(t *testing.T) {
	tests := []struct {
		name string
		port int
		want string
	}{
		{
			name: "default",
			port: 0,
			want: "ip and (tcp or udp or icmp)",
		},
		{
			name: "port",
			port: 443,
			want: "ip and (tcp or udp) and port 443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildPacketFilter(tt.port); got != tt.want {
				t.Fatalf("buildPacketFilter(%d) = %q, want %q", tt.port, got, tt.want)
			}
		})
	}
}
