package netdump

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Capture interface {
	Packets() chan gopacket.Packet
	LinkType() layers.LinkType
	SnapshotLength() uint32
}

type progress struct {
	stderr io.Writer
	device string
	limit  int
	frame  int
}

func (p *progress) Render(packetCount int, totalBytes int) error {
	if p.stderr == nil {
		return nil
	}

	frames := []string{"|", "/", "-", "\\"}
	limitText := "unlimited"
	if p.limit > 0 {
		limitText = fmt.Sprintf("%d", p.limit)
	}

	lines := []string{
		fmt.Sprintf("[%s] Dumping packets to stdout", frames[p.frame%len(frames)]),
		fmt.Sprintf("Interface: %s", p.device),
		"Format: pcap",
		fmt.Sprintf("Packets: %d / %s", packetCount, limitText),
		fmt.Sprintf("Bytes: %d", totalBytes),
		"Press Ctrl+C to stop",
	}

	p.frame++

	if _, err := fmt.Fprint(p.stderr, "\r\033[J"); err != nil {
		return err
	}
	if _, err := fmt.Fprint(p.stderr, strings.Join(lines, "\n")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(p.stderr, "\r\033[%dA", len(lines)-1); err != nil {
		return err
	}
	return nil
}

func (p *progress) Finish(packetCount int, totalBytes int) error {
	if p.stderr == nil {
		return nil
	}

	if _, err := fmt.Fprint(p.stderr, "\r\033[J"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		p.stderr,
		"Dump complete: %d packets, %d bytes on %s\n",
		packetCount,
		totalBytes,
		p.device,
	); err != nil {
		return err
	}
	return nil
}

func Run(stdout io.Writer, stderr io.Writer, capture Capture, format string, limit int, device string) error {
	switch format {
	case "pcap":
		return writePCAP(stdout, stderr, capture, limit, device)
	default:
		return fmt.Errorf("dump format must be one of: pcap")
	}
}

func writePCAP(stdout io.Writer, stderr io.Writer, capture Capture, limit int, device string) error {
	writer := pcapgo.NewWriter(stdout)
	if err := writer.WriteFileHeader(capture.SnapshotLength(), capture.LinkType()); err != nil {
		return err
	}

	progress := progress{
		stderr: stderr,
		device: device,
		limit:  limit,
	}

	if err := progress.Render(0, 0); err != nil {
		return err
	}

	written := 0
	totalBytes := 0
	for packet := range capture.Packets() {
		if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			return err
		}

		written++
		totalBytes += packet.Metadata().Length
		if err := progress.Render(written, totalBytes); err != nil {
			return err
		}
		if limit > 0 && written >= limit {
			return progress.Finish(written, totalBytes)
		}
	}

	return progress.Finish(written, totalBytes)
}
