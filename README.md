# Net Monitor

Simple terminal network monitor. It captures packets from an active network interface and shows aggregated connection statistics in the console.

## Requirements

- Go 1.24.2 or newer
- libpcap on macOS/Linux, or Npcap on Windows
- Permissions to capture network packets

On macOS/Linux, packet capture usually requires `sudo`.

## Install

```bash
go install github.com/ikondratev/net-monitor/cmd/net-monitor@latest
```

Make sure Go's bin directory is in your `PATH`:

```bash
export PATH="$HOME/go/bin:$PATH"
```

Run:

```bash
sudo net-monitor
```

List available interfaces:

```bash
net-monitor -si
```

Capture from a specific interface:

```bash
sudo net-monitor -i en0
```

## Usage

Supported flags:

| Flag | Description |
| --- | --- |
| `-si` | Show available network interfaces and exit. |
| `-i <name>` | Capture from a specific network interface. |
| `--interface <name>` | Same as `-i`. |
| `-p <port>` | Filter TCP/UDP traffic by port. |
| `--proto <tcp\|udp\|icmp>` | Filter traffic by protocol. |
| `--host <ip>` | Filter traffic by host IP address. |
| `--bpf <filter>` | Use a custom BPF filter. Overrides the generated filter. |
| `--dump pcap` | Write captured packets to stdout in pcap format instead of starting the UI. |
| `--limit <count>` | Stop after capturing this many packets. Use with `--dump` to create bounded captures. |

Filter by protocol, host, or port:

```bash
sudo net-monitor --proto tcp
sudo net-monitor --host 192.0.2.10
sudo net-monitor -p 443
```

Use a custom BPF filter:

```bash
sudo net-monitor --bpf "tcp and host 192.0.2.10 and port 443"
```

Dump captured packets to a pcap file:

```bash
sudo net-monitor --bpf "tcp and port 443" --dump pcap --limit 100 > traffic.pcap
```

Read the saved capture with `tcpdump`:

```bash
tcpdump -nn -r traffic.pcap
```

## Build Locally

```bash
go build -o bin/net-monitor ./cmd/net-monitor
```

Run:

```bash
sudo ./bin/net-monitor
```