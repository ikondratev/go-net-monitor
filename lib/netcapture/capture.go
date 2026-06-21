package netcapture

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Capture struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

func Open(device string) (*Capture, error) {
	handle, err := pcap.OpenLive(device, 1024, true, 1*time.Second)
	if err != nil {
		return nil, err
	}
	return &Capture{
		handle: handle,
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
	}, nil
}

func (c *Capture) Packets() chan gopacket.Packet {
	return c.source.Packets()
}

func (c *Capture) Close() {
	c.handle.Close()
}
