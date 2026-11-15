"""Эталон модуля: SYN с root, TCP connect для обычного пользователя."""

from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn

from core.module_base import BaseModule
from utils import renderer
from utils.net import parse_ports, syn_scan, tcp_connect, target_host


class PortScan(BaseModule):
    name = "portscan"
    category = "recon"
    description = "TCP/SYN-скан портов с диапазонами и списками"
    options = {
        "ports": {"default": "21,22,25,53,80,110,139,143,443,445,993,995,1433,3000,3306,5000,5432,6379,8000,8080,8443,27017",
                  "required": True, "description": "Порты: 80,443,8000-8100"},
        "threads": {"default": 64, "required": False, "description": "Число TCP-потоков"},
        "timeout": {"default": 1.0, "required": False, "description": "Таймаут порта, секунды"},
        "scan": {"default": "auto", "required": False, "description": "auto, syn или connect"},
    }

    def run(self) -> None:
        host = target_host(str(self.get_option("target")))
        ports = parse_ports(str(self.get_option("ports")))
        timeout = self.get_option("timeout")
        scan = str(self.get_option("scan")).lower()
        if scan not in {"auto", "syn", "connect"}:
            raise ValueError("scan: ожидается auto, syn или connect")
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        # Ошибки DNS не следует выдавать за отсутствие открытых портов.
        socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        open_ports = None
        if scan != "connect" and is_root:
            try:
                open_ports = []
                with Progress(TextColumn("SYN scan"), BarColumn(), MofNCompleteColumn(),
                              TimeElapsedColumn(), console=renderer.console) as progress:
                    task = progress.add_task("scan", total=len(ports))
                    for offset in range(0, len(ports), 256):
                        batch = ports[offset:offset + 256]
                        open_ports.extend(syn_scan(host, batch, timeout=timeout))
                        progress.advance(task, len(batch))
            except Exception as exc:
                renderer.print_warn(f"SYN недоступен ({exc}); использую TCP connect")
                open_ports = None
        elif not is_root and scan != "connect":
            renderer.print_warn("SYN-скан недоступен без root; использую TCP connect")
        if open_ports is None:
            open_ports = []
            executor = ThreadPoolExecutor(max_workers=self.get_option("threads"))
            futures = {}
            interrupted = False
            try:
                with Progress(TextColumn("TCP scan"), BarColumn(), MofNCompleteColumn(),
                              TimeElapsedColumn(), console=renderer.console) as progress:
                    task = progress.add_task("scan", total=len(ports))
                    futures = {executor.submit(tcp_connect, host, port, timeout): port for port in ports}
                    for future in as_completed(futures):
                        if future.result():
                            open_ports.append(futures[future])
                        progress.advance(task)
            except KeyboardInterrupt:
                interrupted = True
                raise
            finally:
                for future in futures:
                    future.cancel()
                executor.shutdown(wait=not interrupted, cancel_futures=True)
        # Повторный скан заменяет результаты только проверенных портов.
        for port in ports:
            if port not in open_ports:
                self.session.services.pop(port, None)
        rows = []
        for port in sorted(open_ports):
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            service = {6379: "redis", 3000: "http", 5000: "http", 8000: "http",
                       8080: "http", 8443: "https"}.get(port, service)
            self.session.add_service(port, name=service)
            rows.append((port, service, "open"))
        renderer.print_table("Open TCP ports", ("Port", "Service", "State"), rows)
        renderer.print_success(f"Открыто портов: {len(open_ports)}")
