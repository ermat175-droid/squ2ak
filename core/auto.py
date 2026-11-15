"""Условный пайплайн; сбой этапа не мешает последующим проверкам.

Условия поддерживают булеву логику: ``not``, ``and``, ``or`` (приоритет
``not`` → ``and`` → ``or``), что позволяет этапу зависеть от уже найденного:
``has_service:http and not has_finding:waf`` или ``has_loot:url or has_web``.
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from core.execution import execute_module
from core.logging_setup import state_dir
from core.registry import ModuleRegistry
from core.report import write_report
from core.session import Session
from utils import renderer

logger = logging.getLogger("squ2ak")
WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def default_report_base(session: Session) -> Path:
    """Путь авто-отчёта по умолчанию рядом с логами сессии (без расширения)."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(getattr(session, "target", None) or "session"))
    return state_dir() / "reports" / f"report-{safe}-{stamp}"


class AutoRunner:
    def __init__(self, session: Session, pipeline: list[dict], mode: str,
                 registry: ModuleRegistry | None = None, *,
                 report_base: str | Path | None = None, report_format: str = "md") -> None:
        if mode not in {"full", "step"}:
            raise ValueError("Режим auto: full или step")
        if not isinstance(pipeline, list):
            raise ValueError("auto_pipeline должен быть списком")
        for stage in pipeline:
            if not isinstance(stage, dict) or not isinstance(stage.get("module"), str):
                raise ValueError("Каждый этап должен содержать имя module")
            if not isinstance(stage.get("condition", "always"), str):
                raise ValueError("condition должна быть строкой")
            if not isinstance(stage.get("options", {}), dict):
                raise ValueError("options этапа должны быть словарём")
            if not isinstance(stage.get("auto_params", {}), dict):
                raise ValueError("auto_params этапа должны быть словарём")
        self.session = session
        self.pipeline = pipeline
        self.mode = mode
        self.registry = registry if registry is not None else ModuleRegistry().discover()
        self.report_base = report_base
        self.report_format = report_format
        self.results: list[dict] = []

    def _check_condition(self, cond: str) -> bool:
        cond = cond.strip()
        if not cond:
            raise ValueError("Пустое условие")
        # OR (низший приоритет) поверх AND поверх необязательного NOT.
        return any(all(self._check_term(term) for term in or_group.split(" and "))
                   for or_group in cond.split(" or "))

    def _check_term(self, term: str) -> bool:
        term = term.strip()
        negate = False
        while term.startswith("not "):
            negate = not negate
            term = term[4:].strip()
        result = self._check_atom(term)
        return (not result) if negate else result

    def _check_atom(self, cond: str) -> bool:
        if cond == "always":
            return True
        if cond == "has_web":
            return any(port in self.session.services for port in WEB_PORTS)
        if cond == "root":
            return hasattr(os, "geteuid") and os.geteuid() == 0
        if cond.startswith("has_service:"):
            name = cond.partition(":")[2].strip().lower()
            if not name:
                raise ValueError("has_service требует имя сервиса")
            return any(name in service.get("name", "").lower() for service in self.session.services.values())
        if cond.startswith("has_open_port:"):
            port = int(cond.partition(":")[2])
            if not 1 <= port <= 65535:
                raise ValueError("Порт condition должен быть в диапазоне 1–65535")
            return port in self.session.services
        if cond.startswith("has_finding:"):
            needle = cond.partition(":")[2].strip().lower()
            if not needle:
                raise ValueError("has_finding требует подстроку")
            return any(needle in str(item.get("title", "")).lower()
                       or needle in str(item.get("module", "")).lower()
                       for item in self.session.findings)
        if cond.startswith("has_loot:"):
            kind = cond.partition(":")[2].strip().lower()
            if not kind:
                raise ValueError("has_loot требует тип loot")
            return any(str(item.get("type", "")).lower() == kind for item in self.session.loot)
        raise ValueError(f"Неизвестное условие: {cond}")

    def _wait_step(self, stage_name: str) -> str:
        while True:
            try:
                choice = input("[Enter] continue  [s] skip next  [q] quit auto  > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return "quit"
            logger.info("Auto step after %s: %r", stage_name, choice)
            if choice in {"", "s", "q"}:
                return {"": "continue", "s": "skip", "q": "quit"}[choice]
            renderer.print_warn("Введите Enter, s или q")

    def _top_severity(self, findings: list[dict]) -> str | None:
        severities = [str(item.get("severity", "info")).lower() for item in findings]
        return max(severities, key=lambda value: SEVERITY_ORDER.get(value, 0), default=None)

    def run(self, from_stage: str | None = None) -> None:
        if not self.session.target:
            renderer.print_error("Сначала set target <IP>")
            return
        start = 0
        if from_stage is not None:
            names = [stage["module"] for stage in self.pipeline]
            if from_stage not in names:
                raise ValueError(f"Этап {from_stage} не найден в auto_pipeline")
            start = names.index(from_stage)
        self.results = []
        skip_next = False
        try:
            for index in range(start, len(self.pipeline)):
                stage = self.pipeline[index]
                path, cond = stage["module"], stage.get("condition", "always")
                renderer.print_info(f"Stage {index + 1}/{len(self.pipeline)}: {path} [condition: {cond}]")
                result = {"module": path, "status": "skipped", "findings": 0, "severity": None, "duration": 0.0}
                before = len(self.session.findings)
                started = time.monotonic()
                try:
                    if skip_next:
                        skip_next = False
                        renderer.print_warn("Skipped (user choice)")
                    elif not self._check_condition(cond):
                        renderer.print_warn("Skipped (condition not met)")
                    else:
                        module = self.registry.create(path, self.session)
                        # Явные options перекрывают автоматические значения этапа.
                        options = {**stage.get("auto_params", {}), **stage.get("options", {})}
                        for key, value in options.items():
                            module.set_option(key, value)
                        result["status"] = "completed" if execute_module(module) else "failed"
                except KeyboardInterrupt:
                    result["status"] = "interrupted"
                    result["duration"] = round(time.monotonic() - started, 3)
                    new_findings = self.session.findings[before:]
                    result["findings"] = len(new_findings)
                    result["severity"] = self._top_severity(new_findings)
                    self.results.append(result)
                    renderer.print_warn("Auto прерван; возвращаемся в консоль")
                    break
                except Exception as exc:
                    result["status"] = "failed"
                    result["error"] = str(exc)
                    renderer.print_error(f"Этап {path}: {exc}")
                    logger.exception("Auto stage failed: %s", path)
                result["duration"] = round(time.monotonic() - started, 3)
                new_findings = self.session.findings[before:]
                result["findings"] = len(new_findings)
                result["severity"] = self._top_severity(new_findings)
                self.results.append(result)
                if self.mode == "step":
                    choice = self._wait_step(path)
                    if choice == "quit":
                        break
                    skip_next = choice == "skip"
        finally:
            self._print_results()
            renderer.print_summary(self.session)
            self._write_report()

    def _write_report(self) -> None:
        if not self.report_base:
            return
        try:
            for written in write_report(self.session, self.report_base, self.report_format):
                renderer.print_info(f"Report: {written}")
        except (OSError, ValueError) as exc:
            renderer.print_warn(f"Не удалось записать отчёт: {exc}")
            logger.exception("Auto report failed")

    def _print_results(self) -> None:
        if not self.results:
            return
        rows = [(index, entry["module"], entry["status"],
                 entry.get("findings", 0) or "—",
                 entry.get("severity") or "—",
                 f"{entry.get('duration', 0.0):.2f}s")
                for index, entry in enumerate(self.results, 1)]
        renderer.print_table("Auto results", ("Stage", "Module", "Status", "New findings", "Top severity", "Time"), rows)

    def print_pipeline(self) -> None:
        renderer.print_table("Auto pipeline", ("Stage", "Module", "Condition"),
                             ((index, stage["module"], stage.get("condition", "always"))
                              for index, stage in enumerate(self.pipeline, 1)))
