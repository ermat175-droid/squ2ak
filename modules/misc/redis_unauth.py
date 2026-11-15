"""RESP-клиент для трёх проверок Redis, не изменяющих данные."""

from __future__ import annotations

import socket
from typing import BinaryIO

from core.module_base import BaseModule
from utils import renderer
from utils.net import parse_ports, target_host


class RedisResponseError(RuntimeError):
    pass


def read_response(reader: BinaryIO, depth: int = 0, budget: list[int] | None = None):
    # Лимиты защищают консоль от некорректного или слишком большого ответа.
    if depth > 16:
        raise ValueError("Redis response nesting is too deep")
    if budget is None:
        budget = [1024 * 1024]
    line = reader.readline(8193)
    if len(line) > 8192 or not line.endswith(b"\r\n"):
        raise ValueError("Invalid Redis response line")
    budget[0] -= len(line)
    if budget[0] < 0:
        raise ValueError("Redis response exceeds total size limit")
    marker, value = line[:1], line[1:-2]
    if marker == b"+":
        return value.decode("utf-8", errors="replace")
    if marker == b"-":
        raise RedisResponseError(value.decode("utf-8", errors="replace"))
    if marker == b":":
        return int(value)
    if marker == b"$":
        length = int(value)
        if length == -1:
            return None
        if not 0 <= length <= 1024 * 1024:
            raise ValueError("Redis bulk response exceeds size limit")
        budget[0] -= length + 2
        if budget[0] < 0:
            raise ValueError("Redis response exceeds total size limit")
        payload = reader.read(length)
        if len(payload) != length or reader.read(2) != b"\r\n":
            raise ValueError("Truncated Redis bulk response")
        return payload.decode("utf-8", errors="replace")
    if marker == b"*":
        length = int(value)
        if length == -1:
            return None
        if not 0 <= length <= 4096:
            raise ValueError("Redis array exceeds size limit")
        return [read_response(reader, depth + 1, budget) for _ in range(length)]
    raise ValueError("Unsupported Redis response type")


def send_command(sock: socket.socket, reader: BinaryIO, *args: str):
    payload = [f"*{len(args)}\r\n".encode("ascii")]
    for argument in args:
        value = argument.encode("utf-8")
        payload.extend((f"${len(value)}\r\n".encode("ascii"), value, b"\r\n"))
    sock.sendall(b"".join(payload))
    return read_response(reader)


class RedisUnauthModule(BaseModule):
    name = "redis_unauth"
    category = "misc"
    description = "Check unauthenticated Redis PING, INFO and CONFIG GET dir"
    options = {
        "target": {"default": None, "required": True, "description": "Target IP or hostname"},
        "port": {"default": 6379, "required": False, "description": "Redis port"},
        "timeout": {"default": 5.0, "required": False, "description": "Redis timeout in seconds"},
    }

    def run(self) -> None:
        host = target_host(self.get_option("target"))
        timeout = float(self.get_option("timeout"))
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        if "port" in self._values or "port" in self.session.params:
            ports = parse_ports(str(self.get_option("port")))
        else:
            ports = sorted(port for port, service in self.session.services.items() if "redis" in str(service.get("name", "")).lower()) or [6379]
        for port in ports:
            try:
                self._run_port(host, port, timeout)
            except (OSError, ValueError, RedisResponseError) as exc:
                renderer.print_error(f"Redis {host}:{port}: {exc}")

    def _run_port(self, host: str, port: int, timeout: float) -> None:
        authority = f"[{host}]" if ":" in host else host
        source = f"redis://{authority}:{port}"
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            with connection.makefile("rb") as reader:
                try:
                    pong = send_command(connection, reader, "PING")
                except RedisResponseError as exc:
                    renderer.print_warn(f"Redis rejected unauthenticated PING: {exc}")
                    return
                if pong != "PONG":
                    renderer.print_warn(f"Unexpected Redis PING response: {str(pong)[:120]}")
                    return
                version = ""
                info_available = False
                directory = None
                try:
                    info = send_command(connection, reader, "INFO")
                    if isinstance(info, str):
                        info_available = True
                        fields = dict(line.split(":", 1) for line in info.splitlines() if ":" in line and not line.startswith("#"))
                        version = fields.get("redis_version", "")
                except RedisResponseError as exc:
                    renderer.print_warn(f"Redis INFO: {exc}")
                try:
                    configuration = send_command(connection, reader, "CONFIG", "GET", "dir")
                    if isinstance(configuration, list) and len(configuration) >= 2 and configuration[0] == "dir":
                        directory = configuration[1]
                except RedisResponseError as exc:
                    renderer.print_warn(f"Redis CONFIG GET dir: {exc}")
                self.session.add_service(port, name="redis", version=version, banner="PONG")
                title = "Redis without authentication" if info_available else "Redis PING accessible without authentication"
                severity = "high" if info_available else "low"
                self.session.add_finding(title, source, severity=severity, port=port, info_accessible=info_available, config_dir=directory)
                evidence = {"ping": "PONG", "info_accessible": info_available, "version": version}
                if directory is not None:
                    evidence["dir"] = directory
                self.session.add_loot("service", evidence, source)
                renderer.print_success(f"{title} on {host}:{port}")
                renderer.print_table("Redis access", ("Check", "Result"), [("PING", "PONG"), ("INFO", version or ("allowed" if info_available else "denied")), ("CONFIG GET dir", directory if directory is not None else "unavailable")])
