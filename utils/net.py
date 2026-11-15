"""Небольшие сетевые примитивы без обязательной зависимости от scapy."""

from __future__ import annotations

import os
import ipaddress
import logging
import socket
from collections.abc import Iterable
from urllib.parse import urlsplit

logger = logging.getLogger("squ2ak.utils.net")


def target_host(value: str) -> str:
    """URL веб-цели тоже может передаваться сетевым модулям."""
    value = str(value).strip()
    if not value or any(char.isspace() for char in value):
        raise ValueError("Target must be an IP address or hostname")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if "://" in value or value.startswith("[") or value.count(":") == 1:
        parsed = urlsplit(value if "://" in value else "//" + value)
        if not parsed.hostname:
            raise ValueError("Target URL has no hostname")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("Target port must be between 1 and 65535")
        return parsed.hostname
    return value


def parse_ports(value: str | Iterable[int]) -> list[int]:
    """Проверяем список и диапазоны до начала сетевых операций."""
    ports: set[int] = set()
    if isinstance(value, str):
        if not value.strip():
            raise ValueError("Port list is empty")
        for item in value.split(","):
            item = item.strip()
            if not item:
                raise ValueError("Empty item in port list")
            if "-" in item:
                parts = item.split("-")
                if len(parts) != 2 or not all(p.strip().isdecimal() for p in parts):
                    raise ValueError(f"Invalid port range: {item}")
                start, end = (int(p.strip()) for p in parts)
                if not 1 <= start <= end <= 65535:
                    raise ValueError(f"Invalid port range: {item}")
                ports.update(range(start, end + 1))
            else:
                if not item.isdecimal():
                    raise ValueError(f"Invalid port: {item}")
                ports.add(int(item))
    else:
        for item in value:
            if isinstance(item, bool) or not isinstance(item, int):
                raise ValueError(f"Invalid port: {item!r}")
            ports.add(item)
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def syn_scan(host: str, ports: Iterable[int], timeout: float = 1.0) -> list[int]:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PermissionError("SYN scan requires root; use TCP connect scanning")
    try:
        from scapy.all import IP, TCP, send, sr
    except ImportError as exc:
        raise RuntimeError("scapy is not installed; use TCP connect scanning") from exc

    network_layer = IP
    if ":" in host:
        from scapy.all import IPv6

        network_layer = IPv6

    port_list = parse_ports(ports)
    opened: set[int] = set()
    # Пакеты отправляем порциями, чтобы не создавать огромный пакетный список.
    for offset in range(0, len(port_list), 256):
        packets = network_layer(dst=host) / TCP(dport=port_list[offset : offset + 256], flags="S")
        try:
            answered, _ = sr(packets, timeout=timeout, verbose=False)
        except Exception as exc:
            # Общий сканер сможет перейти на TCP при ошибке scapy/маршрута.
            raise RuntimeError(f"SYN scan failed: {exc}") from exc
        for sent, received in answered:
            if received.haslayer(TCP) and int(received[TCP].flags) & 0x12 == 0x12:
                opened.add(int(sent[TCP].dport))
                # Закрываем полуоткрытое соединение ответом RST.
                try:
                    send(
                        network_layer(dst=host)
                        / TCP(
                            sport=int(sent[TCP].sport),
                            dport=int(sent[TCP].dport),
                            flags="R",
                            seq=int(received[TCP].ack),
                        ),
                        verbose=False,
                    )
                except Exception:
                    logger.debug("Could not send SYN cleanup RST", exc_info=True)
    return sorted(opened)


def grab_banner(sock: socket.socket) -> str:
    try:
        return sock.recv(4096).decode("utf-8", errors="replace").strip()
    except (OSError, TimeoutError):
        return ""
