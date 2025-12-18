# MCBE Forwarder

A high-performance game server proxy for Minecraft Bedrock Edition and other UDP/TCP games.

[![Version](https://img.shields.io/badge/version-1.3-blue.svg)](https://github.com/yourusername/ip-forward)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

## Features

- 🚀 High performance, low latency
- 🎮 Multi-player & multi-server support
- 🌐 Dynamic DNS with hourly refresh
- 😈 Daemon mode & systemd integration
- 📝 Configurable logging

## Quick Start

```bash
# Build
./build.sh

# Run (creates default config)
./MCBE_forwarder

# Edit config
nano config.json

# Run as daemon
./MCBE_forwarder -d
```

## Usage

```bash
./MCBE_forwarder              # Run in foreground
./MCBE_forwarder -d           # Run as daemon
./MCBE_forwarder -s           # Stop daemon
./MCBE_forwarder -c <file>    # Custom config
./MCBE_forwarder -g           # Generate systemd service
./MCBE_forwarder -h           # Show help
```

## Configuration

### Minimal

```json
{
  "forwards": [
    {
      "name": "MyServer",
      "listen_port": 19132,
      "target_host": "play.example.com",
      "target_port": 19132
    }
  ]
}
```

### Full Options

```json
{
  "forwards": [
    {
      "name": "Server1",
      "listen_host": "0.0.0.0",
      "listen_port": 19132,
      "target_host": "play.example.com",
      "target_port": 19132
    }
  ],
  "enable_udp": true,
  "enable_tcp": false,
  "buffer_size": 65535,
  "udp_timeout": 120,
  "dns_refresh_interval": 3600,
  "max_sessions": 100,
  "log_level": "INFO",
  "log_file": "forward.log",
  "log_to_file": true,
  "log_to_console": true,
  "daemon_mode": false,
  "pid_file": "mcbe_forward.pid"
}
```

### Options Reference

| Option                 | Default    | Description            |
| ---------------------- | ---------- | ---------------------- |
| `forwards`             | _required_ | Array of forward rules |
| `enable_udp`           | `true`     | Enable UDP             |
| `enable_tcp`           | `false`    | Enable TCP             |
| `buffer_size`          | `65535`    | Buffer size (bytes)    |
| `udp_timeout`          | `120`      | Session timeout (sec)  |
| `dns_refresh_interval` | `3600`     | DNS refresh (sec)      |
| `max_sessions`         | `100`      | Max sessions per rule  |
| `log_level`            | `INFO`     | DEBUG/INFO/WARN/ERROR  |

## Systemd Service

```bash
# Generate & install
./MCBE_forwarder -g
sudo cp ip_forward.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ip_forward

# Check status
sudo systemctl status ip_forward
```

## Requirements

- Linux
- GCC 7+ with C++17 support

## License

MIT License
