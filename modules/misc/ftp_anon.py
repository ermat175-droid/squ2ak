"""Проверка анонимного FTP без загрузки или изменения файлов."""

from __future__ import annotations

import ftplib

from core.module_base import BaseModule
from modules.recon.banner import parse_service_banner
from utils import renderer
from utils.net import parse_ports, target_host


class FTPAnonymousModule(BaseModule):
    name = "ftp_anon"
    category = "misc"
    description = "Check anonymous FTP access without changing files"
    options = {
        "target": {"default": None, "required": True, "description": "Target IP or hostname"},
        "port": {"default": 21, "required": False, "description": "FTP port"},
        "timeout": {"default": 5.0, "required": False, "description": "FTP timeout in seconds"},
    }

    def run(self) -> None:
        host = target_host(self.get_option("target"))
        timeout = float(self.get_option("timeout"))
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        if "port" in self._values or "port" in self.session.params:
            ports = parse_ports(str(self.get_option("port")))
        else:
            ports = sorted(port for port, service in self.session.services.items() if "ftp" in str(service.get("name", "")).lower()) or [21]
        for port in ports:
            try:
                self._run_port(host, port, timeout)
            except (OSError, EOFError, ftplib.Error) as exc:
                renderer.print_error(f"FTP {host}:{port}: {exc}")

    def _run_port(self, host: str, port: int, timeout: float) -> None:
        ftp = ftplib.FTP()
        authority = f"[{host}]" if ":" in host else host
        source = f"ftp://{authority}:{port}"
        try:
            welcome = ftp.connect(host, port, timeout=timeout)
            _, version = parse_service_banner(welcome, port)
            self.session.add_service(port, name="ftp", version=version, banner=welcome)
            ftp.login(user="anonymous", passwd="anonymous@squ2ak.local")
            self.session.add_finding("Anonymous FTP login allowed", source, severity="medium", port=port)
            self.session.add_loot("cred", "anonymous FTP access", source)
            renderer.print_success(f"Anonymous FTP login allowed on {host}:{port}")
        except ftplib.error_perm as exc:
            renderer.print_warn(f"Anonymous FTP login rejected: {exc}")
        finally:
            try:
                ftp.quit()
            except (OSError, EOFError, ftplib.Error):
                ftp.close()
