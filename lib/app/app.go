package app

import (
	"github.com/ikondratev/net-monitor/lib/consoleui"
	"github.com/ikondratev/net-monitor/lib/netcapture"
	"github.com/ikondratev/net-monitor/lib/netstats"
)

type App struct {
	device     string
	port       int
	capture    *netcapture.Capture
	aggregator *netstats.Aggregator
}

func New(port int, device string, capture *netcapture.Capture, aggregator *netstats.Aggregator) *App {
	return &App{
		device:     device,
		port:       port,
		capture:    capture,
		aggregator: aggregator,
	}
}

func (a *App) Run() error {
	go func() {
		for packet := range a.capture.Packets() {
			a.aggregator.ProcessPacket(packet)
		}
	}()

	return consoleui.RunDashboard(a.port, a.device, a.aggregator)
}
