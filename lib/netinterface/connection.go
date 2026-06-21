package netinterface

type Connection struct {
	SrcIP   string
	SrcPort string
	DstIP   string
	DstPort string
	Proto   string
}

type ConnStats struct {
	PacketCount int
	TotalBytes  int
}

type ConnRow struct {
	Connection
	ConnStats
}
