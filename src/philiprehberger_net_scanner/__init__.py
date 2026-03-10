"""LAN device discovery and TCP port scanning."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterator

__all__ = ["scan_network", "scan_ports", "Device", "PortResult"]

# Common ports and their services
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


@dataclass
class Device:
    """A discovered network device."""

    ip: str
    hostname: str | None = None
    mac: str | None = None
    response_time_ms: float | None = None

    def __str__(self) -> str:
        parts = [self.ip]
        if self.hostname:
            parts.append(f"({self.hostname})")
        if self.mac:
            parts.append(f"[{self.mac}]")
        if self.response_time_ms is not None:
            parts.append(f"{self.response_time_ms:.1f}ms")
        return " ".join(parts)


@dataclass
class PortResult:
    """Result of a port scan."""

    number: int
    state: str  # "open", "closed", "filtered"
    service: str | None = None

    def __str__(self) -> str:
        svc = f" ({self.service})" if self.service else ""
        return f"Port {self.number}: {self.state}{svc}"


def _tcp_check(ip: str, port: int, timeout: float) -> bool:
    """Check if a TCP port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()


def _resolve_hostname(ip: str) -> str | None:
    """Try to resolve an IP to a hostname."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _ping_host(ip: str, timeout: float) -> float | None:
    """Check if a host is reachable via TCP connect to common ports.

    Returns response time in ms, or None if unreachable.
    """
    # Try common ports for host discovery
    for port in [80, 443, 22, 445, 139]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.monotonic()
        try:
            result = sock.connect_ex((ip, port))
            elapsed = (time.monotonic() - start) * 1000
            if result == 0:
                return elapsed
        except (socket.timeout, OSError):
            continue
        finally:
            sock.close()
    return None


def scan_network(
    cidr: str,
    timeout: float = 1.0,
    max_workers: int = 64,
    resolve_hostnames: bool = True,
) -> list[Device]:
    """Discover devices on a network.

    Args:
        cidr: Network in CIDR notation (e.g., "192.168.1.0/24").
        timeout: Connection timeout per host in seconds.
        max_workers: Maximum concurrent threads.
        resolve_hostnames: Whether to attempt reverse DNS.

    Returns:
        List of discovered Device objects.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    devices: list[Device] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_ping_host, ip, timeout): ip
            for ip in hosts
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                response_time = future.result()
            except Exception:
                continue

            if response_time is not None:
                hostname = None
                if resolve_hostnames:
                    hostname = _resolve_hostname(ip)

                devices.append(Device(
                    ip=ip,
                    hostname=hostname,
                    response_time_ms=response_time,
                ))

    devices.sort(key=lambda d: ipaddress.ip_address(d.ip))
    return devices


def scan_ports(
    host: str,
    ports: range | list[int] | str = "common",
    timeout: float = 1.0,
    max_workers: int = 128,
) -> list[PortResult]:
    """Scan ports on a host.

    Args:
        host: IP address or hostname to scan.
        ports: Port range, list, or "common" for top ports.
        timeout: Connection timeout per port in seconds.
        max_workers: Maximum concurrent threads.

    Returns:
        List of PortResult objects for open ports.
    """
    if isinstance(ports, str) and ports == "common":
        port_list = list(COMMON_PORTS.keys())
    elif isinstance(ports, range):
        port_list = list(ports)
    elif isinstance(ports, list):
        port_list = ports
    else:
        raise ValueError(f"Invalid ports argument: {ports}")

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {host}")

    results: list[PortResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_tcp_check, ip, port, timeout): port
            for port in port_list
        }

        for future in as_completed(futures):
            port = futures[future]
            try:
                is_open = future.result()
            except Exception:
                continue

            if is_open:
                service = COMMON_PORTS.get(port)
                if not service:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = None

                results.append(PortResult(
                    number=port,
                    state="open",
                    service=service,
                ))

    results.sort(key=lambda r: r.number)
    return results


async def async_scan_ports(
    host: str,
    ports: range | list[int] | str = "common",
    timeout: float = 1.0,
    concurrency: int = 128,
) -> list[PortResult]:
    """Async version of scan_ports using asyncio.

    Args:
        host: IP address or hostname to scan.
        ports: Port range, list, or "common" for top ports.
        timeout: Connection timeout per port in seconds.
        concurrency: Maximum concurrent connections.

    Returns:
        List of PortResult objects for open ports.
    """
    if isinstance(ports, str) and ports == "common":
        port_list = list(COMMON_PORTS.keys())
    elif isinstance(ports, range):
        port_list = list(ports)
    elif isinstance(ports, list):
        port_list = ports
    else:
        raise ValueError(f"Invalid ports argument: {ports}")

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {host}")

    semaphore = asyncio.Semaphore(concurrency)
    results: list[PortResult] = []

    async def check_port(port: int) -> PortResult | None:
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout,
                )
                writer.close()
                await writer.wait_closed()
                service = COMMON_PORTS.get(port)
                return PortResult(number=port, state="open", service=service)
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None

    tasks = [check_port(port) for port in port_list]
    for result in await asyncio.gather(*tasks):
        if result is not None:
            results.append(result)

    results.sort(key=lambda r: r.number)
    return results
