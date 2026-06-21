package main

import (
	"log"

	"github.com/ikondratev/net-monitor/lib/app"
	"github.com/ikondratev/net-monitor/lib/netcapture"
	"github.com/ikondratev/net-monitor/lib/netdevice"
	"github.com/ikondratev/net-monitor/lib/netstats"
)

func main() {
	device, err := netdevice.FindActiveDevice()
	if err != nil {
		log.Fatalf("Ошибка: %v", err)
	}

	capture, err := netcapture.Open(device)
	if err != nil {
		log.Fatalf("Ошибка открытия интерфейса (нужен sudo): %v", err)
	}

	defer capture.Close()
	aggregator := netstats.NewAggregator()
	application := app.New(device, capture, aggregator)
	application.Run()
}
