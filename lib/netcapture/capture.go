package netcapture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	snapshotLength = 256
	promiscuous    = false
	readTimeout    = 1 * time.Second
	packetFilter   = "ip and (tcp or udp or icmp)"
)

type Capture struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

func Open(device string, port int) (*Capture, error) {
	handle, err := pcap.OpenLive(device, snapshotLength, promiscuous, readTimeout)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter(buildPacketFilter(port)); err != nil {
		handle.Close()
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

func buildPacketFilter(port int) string {
	if port > 0 {
		return fmt.Sprintf("ip and (tcp or udp) and port %d", port)
	}
	return packetFilter
}
