package netcapture

import "testing"

func TestBuildPacketFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter Filter
		want   string
	}{
		{
			name:   "default",
			filter: Filter{},
			want:   "ip and (tcp or udp or icmp)",
		},
		{
			name:   "port",
			filter: Filter{Port: 443},
			want:   "ip and (tcp or udp) and port 443",
		},
		{
			name:   "proto",
			filter: Filter{Proto: "tcp"},
			want:   "ip and tcp",
		},
		{
			name:   "host",
			filter: Filter{Host: "192.0.2.10"},
			want:   "ip and (tcp or udp or icmp) and host 192.0.2.10",
		},
		{
			name:   "custom bpf",
			filter: Filter{BPF: "tcp and dst port 443"},
			want:   "tcp and dst port 443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildPacketFilter(tt.filter); got != tt.want {
				t.Fatalf("buildPacketFilter(%+v) = %q, want %q", tt.filter, got, tt.want)
			}
		})
	}
}
