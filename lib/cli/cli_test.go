package cli

import "testing"

func TestParseFlagsShowInterfaces(t *testing.T) {
	cfg, err := parseFlags([]string{"-si"})
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}

	if !cfg.ShowInterfaces {
		t.Fatal("expected ShowInterfaces to be true")
	}
	if cfg.Device != "" {
		t.Fatalf("expected empty device, got %q", cfg.Device)
	}
}

func TestParseFlagsDeviceAliases(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "short", args: []string{"-i", "en0"}},
		{name: "long", args: []string{"--interface", "en0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseFlags(tt.args)
			if err != nil {
				t.Fatalf("parseFlags returned error: %v", err)
			}
			if cfg.Device != "en0" {
				t.Fatalf("expected device en0, got %q", cfg.Device)
			}
		})
	}
}

func TestParseFlagsPort(t *testing.T) {
	cfg, err := parseFlags([]string{"-p", "443"})
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}

	if cfg.Port != 443 {
		t.Fatalf("expected port 443, got %d", cfg.Port)
	}
}

func TestParseFlagsFilters(t *testing.T) {
	cfg, err := parseFlags([]string{"--proto", "TCP", "--host", "192.0.2.10", "--bpf", "tcp and dst port 443"})
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}

	if cfg.Proto != "tcp" {
		t.Fatalf("expected proto tcp, got %q", cfg.Proto)
	}
	if cfg.Host != "192.0.2.10" {
		t.Fatalf("expected host 192.0.2.10, got %q", cfg.Host)
	}
	if cfg.BPF != "tcp and dst port 443" {
		t.Fatalf("expected custom BPF filter, got %q", cfg.BPF)
	}
}

func TestParseFlagsDump(t *testing.T) {
	cfg, err := parseFlags([]string{"--dump", "PCAP", "--limit", "100"})
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}

	if cfg.Dump != "pcap" {
		t.Fatalf("expected dump pcap, got %q", cfg.Dump)
	}
	if cfg.Limit != 100 {
		t.Fatalf("expected limit 100, got %d", cfg.Limit)
	}
}

func TestParseFlagsRejectsInvalidPort(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "negative", args: []string{"-p", "-1"}},
		{name: "too high", args: []string{"-p", "65536"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseFlags(tt.args); err == nil {
				t.Fatal("expected invalid port error")
			}
		})
	}
}

func TestParseFlagsRejectsInvalidDump(t *testing.T) {
	if _, err := parseFlags([]string{"--dump", "txt"}); err == nil {
		t.Fatal("expected invalid dump error")
	}
}

func TestParseFlagsRejectsNegativeLimit(t *testing.T) {
	if _, err := parseFlags([]string{"--limit", "-1"}); err == nil {
		t.Fatal("expected negative limit error")
	}
}

func TestParseFlagsRejectsInvalidProto(t *testing.T) {
	if _, err := parseFlags([]string{"--proto", "gre"}); err == nil {
		t.Fatal("expected invalid proto error")
	}
}

func TestParseFlagsRejectsICMPWithPort(t *testing.T) {
	if _, err := parseFlags([]string{"--proto", "icmp", "-p", "443"}); err == nil {
		t.Fatal("expected icmp with port error")
	}
}

func TestParseFlagsRejectsUnknownFlag(t *testing.T) {
	if _, err := parseFlags([]string{"--unknown"}); err == nil {
		t.Fatal("expected unknown flag error")
	}
}
