"""Сбор приветствий и HTTP-заголовков открытых сервисов."""

from __future__ import annotations

import re
import socket
import ssl

from core.module_base import BaseModule
from utils import renderer
from utils.net import grab_banner, parse_ports, target_host


DEFAULT_SERVICES = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 445: "smb", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 8000: "http", 8080: "http", 8443: "https", 3000: "http",
    5000: "http",
}
WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000}


def parse_service_banner(banner: str, port: int, current_name: str = "") -> tuple[str, str]:
    name = current_name if current_name and current_name not in {"unknown", "tcp"} else DEFAULT_SERVICES.get(port, "unknown")
    web_name = "https" if port in {443, 8443} or "https" in current_name.lower() else "http"
    patterns = (
        (r"OpenSSH[_ /-]([\w.\-]+)", "ssh", "OpenSSH"),
        (r"nginx[/ ]([\w.\-]+)", web_name, "nginx"),
        (r"Apache[/ ]([\w.\-]+)", web_name, "Apache"),
        (r"(?:vsftpd)[ /]?([\d.]+)", "ftp", "vsftpd"),
        (r"ProFTPD[ /]([\w.\-]+)", "ftp", "ProFTPD"),
        (r"redis_version:([\w.\-]+)", "redis", "Redis"),
        (r"Microsoft-IIS/([\d.]+)", web_name, "Microsoft-IIS"),
    )
    for pattern, detected_name, product in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return detected_name, f"{product} {match.group(1)}"
    if banner.startswith("SSH-"):
        name = "ssh"
    elif banner.upper().startswith("HTTP/"):
        name = web_name
    elif "ftp" in banner.lower() and banner.startswith("220"):
        name = "ftp"
    return name, ""


class BannerModule(BaseModule):
    name = "banner"
    category = "recon"
    description = "Grab banners and identify versions on open ports"
    options = {
        "target": {"default": None, "required": True, "description": "Target IP or hostname"},
        "ports": {"default": "", "required": False, "description": "Ports; empty uses discovered open ports"},
        "timeout": {"default": 5.0, "required": False, "description": "Socket timeout in seconds"},
    }

    def _grab(self, host: str, port: int, timeout: float, name: str) -> str:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            is_http = port in WEB_PORTS or "http" in name.lower()
            if not is_http:
                known_name = name if name and name.lower() not in {"unknown", "tcp"} else DEFAULT_SERVICES.get(port, "unknown")
                if known_name != "unknown":
                    return grab_banner(connection)
                # HTTP на нестандартном порту молчит до первого запроса.
                connection.settimeout(min(0.3, timeout))
                banner = grab_banner(connection)
                if banner:
                    return banner
                connection.settimeout(timeout)
                connection.sendall(self._head_request(host, port))
                return self._http_headers(connection)
            if port in {443, 8443} or "https" in name.lower():
                # В лабораториях сертификаты часто самоподписанные.
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(connection, server_hostname=host) as secure:
                    secure.sendall(self._head_request(host, port))
                    return self._http_headers(secure)
            connection.sendall(self._head_request(host, port))
            return self._http_headers(connection)

    @staticmethod
    def _http_headers(connection: socket.socket) -> str:
        data = bytearray()
        while len(data) < 16384 and b"\r\n\r\n" not in data:
            try:
                chunk = connection.recv(min(4096, 16384 - len(data)))
            except (OSError, TimeoutError):
                break
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data).split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace").strip()

    @staticmethod
    def _head_request(host: str, port: int) -> bytes:
        if any(char in host for char in "\r\n"):
            raise ValueError("Invalid HTTP hostname")
        authority = f"[{host}]" if ":" in host else host
        return f"HEAD / HTTP/1.1\r\nHost: {authority}:{port}\r\nUser-Agent: squ2ak/0.1\r\nConnection: close\r\n\r\n".encode("ascii")

    def run(self) -> None:
        host = target_host(self.get_option("target"))
        timeout = float(self.get_option("timeout"))
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        configured = self.get_option("ports")
        ports = parse_ports(str(configured)) if configured else sorted(self.session.services)
        if not ports:
            renderer.print_warn("No open ports found; run recon/portscan first")
            return
        rows = []
        for port in ports:
            current = self.session.services.get(port, {})
            try:
                banner = self._grab(host, port, timeout, str(current.get("name", "")))
                name, version = parse_service_banner(banner, port, str(current.get("name", "")))
                self.session.add_service(
                    port, name=name, version=version or str(current.get("version", "")),
                    banner=banner or str(current.get("banner", "")),
                )
                rows.append((port, name, version or current.get("version", ""), banner.splitlines()[0][:120] if banner else ""))
            except (OSError, ValueError) as exc:
                renderer.print_warn(f"Port {port}: {exc}")
                # Недоступный баннер не удаляет результат сканирования.
        renderer.print_table("Service banners", ("Port", "Service", "Version", "Banner"), rows)
