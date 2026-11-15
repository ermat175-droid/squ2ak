"""Отчёт по находкам, сервисам и loot: Markdown и JSON из снимка сессии."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SKIP_DETAIL = {"title", "source", "severity"}


def _snapshot(source: Any) -> dict:
    return source.snapshot() if hasattr(source, "snapshot") else dict(source)


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda item: (
        SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 5),
        str(item.get("source", "")), str(item.get("title", ""))))


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in findings:
        severity = str(item.get("severity", "info")).lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _details(finding: dict) -> str:
    parts = [f"{key}={value}" for key, value in finding.items()
             if key not in _SKIP_DETAIL and value not in (None, "", [], {})]
    return "; ".join(str(part).replace("|", "\\|").replace("\n", " ") for part in parts)


def render_markdown(source: Any) -> str:
    snapshot = _snapshot(source)
    findings = _sorted_findings(snapshot.get("findings", []))
    services = snapshot.get("services", {})
    loot = snapshot.get("loot", [])
    counts = _severity_counts(findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    lines = [
        f"# squ2ak report — {snapshot.get('target') or 'unset'}",
        "",
        f"- Generated: {generated}",
        f"- Target: `{snapshot.get('target') or 'unset'}`",
        f"- Findings: {len(findings)}"
        + (" (" + ", ".join(f"{name}: {counts[name]}"
                            for name in sorted(counts, key=lambda value: SEVERITY_ORDER.get(value, 5))) + ")"
           if counts else ""),
        f"- Services: {len(services)}  ·  Loot: {len(loot)}",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines += ["| Severity | Title | Source | Details |", "| --- | --- | --- | --- |"]
        for finding in findings:
            lines.append("| {severity} | {title} | {source} | {details} |".format(
                severity=str(finding.get("severity", "info")),
                title=str(finding.get("title", "")).replace("|", "\\|"),
                source=str(finding.get("source", "")).replace("|", "\\|"),
                details=_details(finding) or "—"))
    else:
        lines.append("_Находок нет._")

    lines += ["", "## Services", ""]
    if services:
        lines += ["| Port | Service | Version | Banner |", "| --- | --- | --- | --- |"]
        for port in sorted(services, key=lambda value: int(value)):
            info = services[port]
            lines.append("| {port} | {name} | {version} | {banner} |".format(
                port=port, name=info.get("name", ""), version=info.get("version", ""),
                banner=str(info.get("banner", ""))[:80].replace("|", "\\|").replace("\n", " ")))
    else:
        lines.append("_Открытые сервисы не зафиксированы._")

    lines += ["", "## Loot", ""]
    if loot:
        for item in loot:
            lines.append(f"- **{item.get('type', '')}**: `{item.get('value', '')}` "
                         f"← {item.get('source', '')}")
    else:
        lines.append("_Loot пуст._")
    return "\n".join(lines) + "\n"


def render_json(source: Any) -> str:
    snapshot = _snapshot(source)
    snapshot = dict(snapshot)
    snapshot["findings"] = _sorted_findings(snapshot.get("findings", []))
    snapshot["generated"] = datetime.now(timezone.utc).isoformat()
    snapshot["severity_counts"] = _severity_counts(snapshot["findings"])
    return json.dumps(snapshot, ensure_ascii=False, indent=2, default=str) + "\n"


def _with_ext(base: Path, ext: str) -> Path:
    # Добавляем расширение, не затирая точки в имени (важно для IP-целей),
    # но не дублируем, если оно уже стоит.
    if base.suffix.lower() == "." + ext:
        return base
    return base.with_name(base.name + "." + ext)


def write_report(source: Any, path: str | Path, fmt: str = "md") -> list[Path]:
    """Пишет отчёт; fmt: md, json или both. Возвращает список записанных файлов."""
    if fmt not in {"md", "json", "both"}:
        raise ValueError("Формат отчёта: md, json или both")
    snapshot = _snapshot(source)
    base = Path(path).expanduser()
    base.parent.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if fmt in {"md", "both"}:
        target = _with_ext(base, "md")
        target.write_text(render_markdown(snapshot), encoding="utf-8")
        written.append(target)
    if fmt in {"json", "both"}:
        target = _with_ext(base, "json")
        target.write_text(render_json(snapshot), encoding="utf-8")
        written.append(target)
    return written
