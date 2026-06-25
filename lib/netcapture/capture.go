package netcapture

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

type Filter struct {
	Port  int
	Proto string
	Host  string
	BPF   string
}

func Open(device string, filter Filter) (*Capture, error) {
	handle, err := pcap.OpenLive(device, snapshotLength, promiscuous, readTimeout)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter(buildPacketFilter(filter)); err != nil {
		handle.Close()
		return nil, err
	}

	return &Capture{
		handle: handle,
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
	}, nil
}

func (c *Capture) LinkType() layers.LinkType {
	return c.handle.LinkType()
}

func (c *Capture) SnapshotLength() uint32 {
	return snapshotLength
}

func (c *Capture) Packets() chan gopacket.Packet {
	return c.source.Packets()
}

func (c *Capture) Close() {
	c.handle.Close()
}

func buildPacketFilter(filter Filter) string {
	if filter.BPF != "" {
		return filter.BPF
	}

	transport := "(tcp or udp or icmp)"
	if filter.Port > 0 {
		transport = "(tcp or udp)"
	}
	if filter.Proto != "" {
		transport = filter.Proto
	}

	parts := []string{"ip", transport}

	if filter.Port > 0 {
		parts = append(parts, fmt.Sprintf("port %d", filter.Port))
	}
	if filter.Host != "" {
		parts = append(parts, fmt.Sprintf("host %s", filter.Host))
	}

	return strings.Join(parts, " and ")
}
