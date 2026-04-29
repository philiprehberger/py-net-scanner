# philiprehberger-net-scanner

[![Tests](https://github.com/philiprehberger/py-net-scanner/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-net-scanner/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-net-scanner.svg)](https://pypi.org/project/philiprehberger-net-scanner/)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/py-net-scanner)](https://github.com/philiprehberger/py-net-scanner/commits/main)

LAN device discovery and TCP port scanning.

## Installation

```bash
pip install philiprehberger-net-scanner
```

## Usage

### Network Discovery

```python
from philiprehberger_net_scanner import scan_network

devices = scan_network("192.168.1.0/24", timeout=2.0)
for device in devices:
    print(f"{device.ip} - {device.hostname or 'unknown'} ({device.response_time_ms:.1f}ms)")
```

### Port Scanning

```python
from philiprehberger_net_scanner import scan_ports

# Scan common ports
ports = scan_ports("192.168.1.1", ports="common")
for port in ports:
    print(f"Port {port.number}: {port.state} ({port.service})")

# Scan specific range
ports = scan_ports("192.168.1.1", ports=range(1, 1024), timeout=0.5)

# Scan specific ports
ports = scan_ports("192.168.1.1", ports=[22, 80, 443, 3306, 5432])
```

### Single port check

```python
from philiprehberger_net_scanner import is_port_open

if is_port_open("example.com", 443, timeout=1.0):
    print("HTTPS is reachable")
```

### Async Port Scanning

```python
import asyncio
from philiprehberger_net_scanner import async_scan_ports

ports = asyncio.run(async_scan_ports("192.168.1.1", ports=range(1, 65536), timeout=0.5))
```

## API

| Function / Class | Description |
|------------------|-------------|
| `scan_network(cidr, timeout=1.0, max_workers=64, resolve_hostnames=True)` | Discover devices on a network using TCP connect probes |
| `scan_ports(host, ports="common", timeout=1.0, max_workers=128)` | Scan TCP ports on a host (`"common"`, `range`, or `list[int]`) |
| `async_scan_ports(host, ports="common", timeout=1.0, concurrency=128)` | Asyncio-based version of `scan_ports` |
| `is_port_open(host, port, timeout=1.0)` | One-off boolean check for a single TCP port |
| `Device` | Discovered host: `ip`, `hostname`, `mac`, `response_time_ms` |
| `PortResult` | Scan result: `number`, `state` (`"open"`/`"closed"`/`"filtered"`), `service` |

## Development

```bash
pip install -e .
python -m pytest tests/ -v
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/py-net-scanner)

🐛 [Report issues](https://github.com/philiprehberger/py-net-scanner/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/py-net-scanner/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
