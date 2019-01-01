# philiprehberger-net-scanner

LAN device discovery and TCP port scanning.

## Install

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

### Async Port Scanning

```python
import asyncio
from philiprehberger_net_scanner import async_scan_ports

ports = asyncio.run(async_scan_ports("192.168.1.1", ports=range(1, 65536), timeout=0.5))
```

## API

### `scan_network(cidr, timeout?, max_workers?, resolve_hostnames?) -> list[Device]`

Discover devices on a network using TCP connect probes.

### `scan_ports(host, ports?, timeout?, max_workers?) -> list[PortResult]`

Scan TCP ports on a host. `ports` can be `"common"`, a `range`, or a `list[int]`.

### `async_scan_ports(host, ports?, timeout?, concurrency?) -> list[PortResult]`

Async version using asyncio for high-performance scanning.

## License

MIT
