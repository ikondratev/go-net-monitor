package app

import (
	"time"

	"github.com/ikondratev/net-monitor/lib/consoleui"
	"github.com/ikondratev/net-monitor/lib/netcapture"
	"github.com/ikondratev/net-monitor/lib/netstats"
)

type App struct {
	device     string
	capture    *netcapture.Capture
	aggregator *netstats.Aggregator
}

func New(device string, capture *netcapture.Capture, aggregator *netstats.Aggregator) *App {
	return &App{
		device:     device,
		capture:    capture,
		aggregator: aggregator,
	}
}

func (a *App) Run() {
	go func() {
		for packet := range a.capture.Packets() {
			a.aggregator.ProcessPacket(packet)
		}
	}()

	consoleui.ClearScreen()
	frameIdx := 0
	rows := a.aggregator.ConnectionRows()
	lastDataRefresh := time.Now()

	for {
		if time.Since(lastDataRefresh) >= 5*time.Second {
			rows = a.aggregator.ConnectionRows()
			lastDataRefresh = time.Now()
		}

		consoleui.DrawDashboard(a.device, frameIdx, rows, lastDataRefresh)
		frameIdx = (frameIdx + 1) % consoleui.FramesCount()
		time.Sleep(200 * time.Millisecond)
	}
}
