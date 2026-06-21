package netstats

import (
	"sort"
	"sync"

	"github.com/ikondratev/net-monitor/lib/netinterface"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Aggregator struct {
	mu         sync.Mutex
	networkMap map[netinterface.Connection]*netinterface.ConnStats
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		networkMap: make(map[netinterface.Connection]*netinterface.ConnStats),
	}
}

func (a *Aggregator) ProcessPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	conn := netinterface.Connection{
		SrcIP: ip.SrcIP.String(),
		DstIP: ip.DstIP.String(),
		Proto: ip.Protocol.String(),
	}

	// Пытаемся достать порты в зависимости от TCP или UDP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		conn.SrcPort = tcp.SrcPort.String()
		conn.DstPort = tcp.DstPort.String()
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		conn.SrcPort = udp.SrcPort.String()
		conn.DstPort = udp.DstPort.String()
	} else {
		conn.SrcPort = "-"
		conn.DstPort = "-"
	}

	// Сохраняем/обновляем в map
	a.mu.Lock()
	defer a.mu.Unlock()

	stats, exists := a.networkMap[conn]
	if !exists {
		stats = &netinterface.ConnStats{}
		a.networkMap[conn] = stats
	}
	stats.PacketCount++
	stats.TotalBytes += packet.Metadata().Length
}

func (a *Aggregator) ConnectionRows() []netinterface.ConnRow {
	a.mu.Lock()
	defer a.mu.Unlock()

	rows := make([]netinterface.ConnRow, 0, len(a.networkMap))
	for conn, stats := range a.networkMap {
		rows = append(rows, netinterface.ConnRow{
			Connection: conn,
			ConnStats:  *stats,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TotalBytes == rows[j].TotalBytes {
			return rows[i].PacketCount > rows[j].PacketCount
		}
		return rows[i].TotalBytes > rows[j].TotalBytes
	})

	return rows
}
