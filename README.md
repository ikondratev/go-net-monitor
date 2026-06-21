# Net Monitor

Simple terminal network monitor written in Go. It captures packets from an active network interface and shows aggregated connection statistics in the console.

## Requirements

- Go 1.22 or newer
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

## Build Locally

```bash
go build -o bin/net-monitor ./cmd/net-monitor
```

Run:

```bash
sudo ./bin/net-monitor
```

## Project Structure

- `cmd/net-monitor` - application entrypoint
- `lib/app` - main application loop
- `lib/consoleui` - terminal rendering
- `lib/netcapture` - packet capture setup
- `lib/netdevice` - network interface detection
- `lib/netinterface` - connection data structures
- `lib/netstats` - packet aggregation and sorting
