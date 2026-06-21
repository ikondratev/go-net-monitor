package consoleui

import (
	"fmt"
	"time"

	"github.com/ikondratev/net-monitor/lib/netinterface"
)

var (
	frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
)

func FramesCount() int {
	return len(frames)
}

func DrawDashboard(device string, frameIdx int, rows []netinterface.ConnRow, lastDataRefresh time.Time) {
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
	fmt.Printf("%s  [ СЕТЕВОЙ МОНИТОР ] Слушаем интерфейс: %s\n", frames[frameIdx], device)
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

func ClearScreen() {
	fmt.Print("\033[2J\033[H")
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

func clearRestOfScreen() {
	fmt.Print("\033[J")
}

func moveCursorHome() {
	fmt.Print("\033[H")
}
