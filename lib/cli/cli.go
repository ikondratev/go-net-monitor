package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/ikondratev/net-monitor/lib/app"
	"github.com/ikondratev/net-monitor/lib/consoleui"
	"github.com/ikondratev/net-monitor/lib/netcapture"
	"github.com/ikondratev/net-monitor/lib/netdevice"
	"github.com/ikondratev/net-monitor/lib/netstats"
)

type Config struct {
	ShowInterfaces bool
	Device         string
	Port           int
}

func Run(args []string, stdout io.Writer) error {
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

	capture, err := netcapture.Open(device, cfg.Port)
	if err != nil {
		return fmt.Errorf("failed to open interface %q: %w", device, err)
	}
	defer capture.Close()

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
	fs.StringVar(&cfg.Device, "i", "", "network interface to capture")
	fs.StringVar(&cfg.Device, "interface", "", "network interface to capture")
	fs.IntVar(&cfg.Port, "p", 0, "filter traffic by TCP/UDP port")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if cfg.Port != 0 && (cfg.Port < 1 || cfg.Port > 65535) {
		return Config{}, fmt.Errorf("port must be between 1 and 65535")
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
