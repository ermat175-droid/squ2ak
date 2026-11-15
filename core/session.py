"""Общее состояние процесса; результаты разных целей не смешиваются."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any


class Session:
    _instance: Session | None = None
    _instance_lock = RLock()

    def __new__(cls) -> Session:
        with cls._instance_lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._lock = RLock()
                obj.target = None
                obj.services = {}
                obj.loot = []
                obj.findings = []
                obj.params = {}
                cls._instance = obj
            return cls._instance

    def reset(self) -> None:
        with self._lock:
            self.target = None
            self.services.clear()
            self.loot.clear()
            self.findings.clear()
            self.params.clear()

    def set_target(self, target: str) -> None:
        target = str(target).strip()
        if not target or any(char.isspace() for char in target):
            raise ValueError("Цель должна быть IP, хостом или HTTP(S) URL без пробелов")
        with self._lock:
            if self.target != target:
                self.services.clear()
                self.loot.clear()
                self.findings.clear()
                self.params.pop("scan_stats", None)
                # До первой цели config может уже содержать URL для неё.
                if self.target is not None:
                    self.params.pop("url", None)
                    self.params.pop("urls", None)
            self.target = target

    def add_service(self, port: int, name: str = "", version: str = "", banner: str = "") -> None:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError("Порт должен быть в диапазоне 1–65535")
        with self._lock:
            previous = self.services.get(port, {})
            self.services[port] = {
                "name": name or previous.get("name", "unknown"),
                "version": version or previous.get("version", ""),
                "banner": banner or previous.get("banner", ""),
            }

    def add_loot(self, type: str, value: Any, source: str) -> None:
        with self._lock:
            if any(item["type"] == type and item["value"] == value and item["source"] == source
                   for item in self.loot):
                return
            self.loot.append({"type": type, "value": value, "source": source,
                              "timestamp": datetime.now(timezone.utc).isoformat()})

    def add_finding(self, title: str, source: str, severity: str = "info", **details: Any) -> None:
        with self._lock:
            finding = {"title": title, "source": source, "severity": severity, **details}
            if finding not in self.findings:
                self.findings.append(finding)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy({"target": self.target, "services": self.services,
                             "loot": self.loot, "findings": self.findings, "params": self.params})
