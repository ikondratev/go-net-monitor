package netdump

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type fakeCapture struct {
	packets chan gopacket.Packet
}

func (f fakeCapture) Packets() chan gopacket.Packet {
	return f.packets
}

func (f fakeCapture) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (f fakeCapture) SnapshotLength() uint32 {
	return 256
}

func TestRunWritesPCAPAndHonorsLimit(t *testing.T) {
	capture := fakeCapture{
		packets: make(chan gopacket.Packet, 2),
	}
	capture.packets <- newPacket([]byte{0, 1, 2})
	capture.packets <- newPacket([]byte{3, 4, 5})
	close(capture.packets)

	var out bytes.Buffer
	var stderr bytes.Buffer
	if err := Run(&out, &stderr, capture, "pcap", 1, "en0"); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !strings.Contains(stderr.String(), "Dump complete: 1 packets, 3 bytes on en0") {
		t.Fatalf("expected dump progress, got %q", stderr.String())
	}

	reader, err := pcapgo.NewReader(&out)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	if reader.LinkType() != layers.LinkTypeEthernet {
		t.Fatalf("expected ethernet link type, got %v", reader.LinkType())
	}

	data, _, err := reader.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData returned error: %v", err)
	}
	if !bytes.Equal(data, []byte{0, 1, 2}) {
		t.Fatalf("unexpected packet data: %v", data)
	}

	if _, _, err := reader.ReadPacketData(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after one packet, got %v", err)
	}
}

func TestRunRejectsUnknownFormat(t *testing.T) {
	if err := Run(io.Discard, io.Discard, fakeCapture{}, "jsonl", 0, "en0"); err == nil {
		t.Fatal("expected unknown format error")
	}
}

func newPacket(data []byte) gopacket.Packet {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Unix(0, 0),
		CaptureLength: len(data),
		Length:        len(data),
	}
	return packet
}
