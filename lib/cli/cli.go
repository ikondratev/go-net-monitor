package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/ikondratev/net-monitor/lib/app"
	"github.com/ikondratev/net-monitor/lib/consoleui"
	"github.com/ikondratev/net-monitor/lib/netcapture"
	"github.com/ikondratev/net-monitor/lib/netdevice"
	"github.com/ikondratev/net-monitor/lib/netdump"
	"github.com/ikondratev/net-monitor/lib/netstats"
)

type Config struct {
	ShowInterfaces bool
	Device         string
	Port           int
	Proto          string
	Host           string
	BPF            string
	Dump           string
	Limit          int
}

func Run(args []string, stdout io.Writer, stderr io.Writer) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	if cfg.ShowInterfaces {
		return printInterfaces(stdout)
	}

	device := cfg.Device
	if device == "" {
		device, err = netdevice.FindActiveDevice()
		if err != nil {
			return err
		}
	}

	filter := netcapture.Filter{
		Port:  cfg.Port,
		Proto: cfg.Proto,
		Host:  cfg.Host,
		BPF:   cfg.BPF,
	}

	capture, err := netcapture.Open(device, filter)
	if err != nil {
		return fmt.Errorf("failed to open interface %q: %w", device, err)
	}
	defer capture.Close()

	if cfg.Dump != "" {
		return netdump.Run(
			stdout,
			stderr,
			capture,
			cfg.Dump,
			cfg.Limit,
			device,
		)
	}

	aggregator := netstats.NewAggregator()
	application := app.New(cfg.Port, device, capture, aggregator)
	if err := application.Run(); err != nil {
		return fmt.Errorf("ui error: %w", err)
	}

	return nil
}

func parseFlags(args []string) (Config, error) {
	fs := flag.NewFlagSet("net-monitor", flag.ContinueOnError)

	var cfg Config

	fs.BoolVar(&cfg.ShowInterfaces, "si", false, "show available network interfaces")
	fs.IntVar(&cfg.Port, "p", 0, "filter traffic by TCP/UDP port")
	fs.StringVar(&cfg.Device, "i", "", "network interface to capture")
	fs.StringVar(&cfg.Device, "interface", "", "network interface to capture")
	fs.StringVar(&cfg.Proto, "proto", "", "filter traffic by protocol: tcp, udp, or icmp")
	fs.StringVar(&cfg.Host, "host", "", "filter traffic by host IP")
	fs.StringVar(&cfg.BPF, "bpf", "", "custom BPF filter")
	fs.StringVar(&cfg.Dump, "dump", "", "dump captured packets to stdout: pcap")
	fs.IntVar(&cfg.Limit, "limit", 0, "stop after capturing this many packets")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if cfg.Port != 0 && (cfg.Port < 1 || cfg.Port > 65535) {
		return Config{}, fmt.Errorf("port must be between 1 and 65535")
	}

	cfg.Proto = strings.ToLower(cfg.Proto)

	switch cfg.Proto {
	case "", "tcp", "udp", "icmp":
	default:
		return Config{}, fmt.Errorf("proto must be one of: tcp, udp, icmp")
	}

	cfg.Dump = strings.ToLower(cfg.Dump)

	switch cfg.Dump {
	case "", "pcap":
	default:
		return Config{}, fmt.Errorf("dump format must be one of: pcap")
	}

	if cfg.Limit < 0 {
		return Config{}, fmt.Errorf("limit must be zero or greater")
	}

	if cfg.Port != 0 && cfg.Proto == "icmp" {
		return Config{}, fmt.Errorf("port filter cannot be used with icmp")
	}

	return cfg, nil
}

func printInterfaces(stdout io.Writer) error {
	devices, err := netdevice.ListDevices()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}
	if err := consoleui.PrintInterfaces(stdout, devices); err != nil {
		return fmt.Errorf("failed to print interfaces: %w", err)
	}
	return nil
}
