package main

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Структура для уникального сетевого соединения
type Connection struct {
	SrcIP   string
	SrcPort string
	DstIP   string
	DstPort string
	Proto   string
}

// Статистика по соединению
type ConnStats struct {
	PacketCount int
	TotalBytes  int
}

type ConnRow struct {
	Connection
	ConnStats
}

var (
	// Хранилище уникальных соединений (потокобезопасное)
	networkMap = make(map[Connection]*ConnStats)
	mu         sync.Mutex
	frames     = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
)

func main() {
	device, err := findActiveDevice()
	if err != nil {
		log.Fatalf("Ошибка: %v", err)
	}

	handle, err := pcap.OpenLive(device, 1024, true, 1*time.Second)
	if err != nil {
		log.Fatalf("Ошибка открытия интерфейса (нужен sudo): %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Горутина 1: Захват пакетов в бэкграунде
	go func() {
		for packet := range packetSource.Packets() {
			processPacket(packet)
		}
	}()

	// Горутина 2: Отрисовка интерфейса в главном потоке.
	// Данные обновляются раз в 5 секунд, а спиннер продолжает плавно двигаться.
	clearScreen()
	frameIdx := 0
	rows := getConnectionRows()
	lastDataRefresh := time.Now()

	for {
		if time.Since(lastDataRefresh) >= 5*time.Second {
			rows = getConnectionRows()
			lastDataRefresh = time.Now()
		}

		drawDashboard(device, frames[frameIdx], rows, lastDataRefresh)

		// Анимация лоадера
		frameIdx = (frameIdx + 1) % len(frames)
		time.Sleep(200 * time.Millisecond) // Частота обновления экрана
	}
}

// Разбор пакета и агрегация данных
func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	conn := Connection{
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
	mu.Lock()
	stats, exists := networkMap[conn]
	if !exists {
		stats = &ConnStats{}
		networkMap[conn] = stats
	}
	stats.PacketCount++
	stats.TotalBytes += packet.Metadata().Length
	mu.Unlock()
}

func getConnectionRows() []ConnRow {
	mu.Lock()
	defer mu.Unlock()

	rows := make([]ConnRow, 0, len(networkMap))
	for conn, stats := range networkMap {
		rows = append(rows, ConnRow{
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

func drawDashboard(device, frame string, rows []ConnRow, lastDataRefresh time.Time) {
	const (
		protoWidth  = 8
		srcWidth    = 32
		dstWidth    = 32
		packetWidth = 10
		bytesWidth  = 12
		maxRows     = 15
	)

	moveCursorHome()

	separator := "==============================================================================================================="
	fmt.Printf("%s  [ СЕТЕВОЙ МОНИТОР ] Слушаем интерфейс: %s\n", frame, device)
	fmt.Printf("Последнее обновление данных: %s | Следующее обновление через: %ds\n",
		lastDataRefresh.Format("15:04:05"), secondsUntilNextRefresh(lastDataRefresh))
	fmt.Println(separator)
	fmt.Printf("%-*s | %-*s | %-*s | %-*s | %-*s\n",
		protoWidth, "ПРОТО",
		srcWidth, "ОТКУДА (IP:PORT)",
		dstWidth, "КУДА (IP:PORT)",
		packetWidth, "ПАКЕТЫ",
		bytesWidth, "ОБЪЕМ")
	fmt.Println("---------------------------------------------------------------------------------------------------------------")

	visibleRows := len(rows)
	if visibleRows > maxRows {
		visibleRows = maxRows
	}
	for i := 0; i < visibleRows; i++ {
		row := rows[i]
		src := fmt.Sprintf("%s:%s", row.SrcIP, row.SrcPort)
		dst := fmt.Sprintf("%s:%s", row.DstIP, row.DstPort)

		fmt.Printf("%-*s | %-*s | %-*s | %-*d | %-*s\n",
			protoWidth, row.Proto,
			srcWidth, fitColumn(src, srcWidth),
			dstWidth, fitColumn(dst, dstWidth),
			packetWidth, row.PacketCount,
			bytesWidth, formatBytes(row.TotalBytes))
	}
	if len(rows) > maxRows {
		fmt.Printf("... и еще %d соединений в фоне ...\n", len(rows)-maxRows)
	}

	fmt.Println(separator)
	fmt.Println("👉 Для выхода нажмите Ctrl+C")
	clearRestOfScreen()
}

func secondsUntilNextRefresh(lastDataRefresh time.Time) int {
	remaining := 5*time.Second - time.Since(lastDataRefresh)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Seconds()) + 1
}

func fitColumn(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width <= 3 {
		return value[:width]
	}
	return value[:width-3] + "..."
}

// Функция автовыбора интерфейса
func findActiveDevice() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, d := range devices {
		if len(d.Addresses) > 0 {
			for _, addr := range d.Addresses {
				if !addr.IP.IsLoopback() {
					return d.Name, nil
				}
			}
		}
	}
	return "eth0", nil
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func moveCursorHome() {
	fmt.Print("\033[H")
}

func clearRestOfScreen() {
	fmt.Print("\033[J")
}

// Красивое форматирование байт
func formatBytes(b int) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
