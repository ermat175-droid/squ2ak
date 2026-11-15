"""Безопасный цветной вывод; текст целей не интерпретируется как rich markup."""

from __future__ import annotations

import sys
from typing import Iterable, Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console(markup=False)


def configure_console() -> None:
    global console
    console = Console(file=sys.stdout, markup=False)


def print_banner() -> None:
    console.print(Text("╔══════════════════════════════════════╗\n"
                       "║           s q u 2 a k  v0.1          ║\n"
                       "║     CTF & Pentest Framework          ║\n"
                       "╚══════════════════════════════════════╝", style="bold cyan"))
    console.print("\nQuick start:\n"
                  "  [1] set target <IP>      задать цель\n"
                  "  [2] auto                 автоцепочка (пошагово)\n"
                  "  [3] show modules         список модулей\n"
                  "  [4] help                 все команды\n")


def _message(prefix: str, message: Any, style: str) -> None:
    text = Text(prefix + " ", style=style)
    text.append(str(message))
    console.print(text)


def print_success(message: Any) -> None:
    _message("[+]", message, "green")


def print_error(message: Any) -> None:
    _message("[!]", message, "red")


def print_info(message: Any) -> None:
    _message("[*]", message, "cyan")


def print_warn(message: Any) -> None:
    _message("[-]", message, "yellow")


def print_table(title: str, columns: Iterable[str], rows: Iterable[Iterable[Any]]) -> None:
    table = Table(title=Text(title), header_style="bold cyan")
    for column in columns:
        table.add_column(str(column), overflow="fold")
    for row in rows:
        table.add_row(*(Text(str(cell)) for cell in row))
    console.print(table)


def print_loot(session) -> None:
    if not session.loot:
        print_info("Loot пока нет")
        return
    for item in session.loot:
        console.print(Text(f"  - {item['type']}:{item['value']} ({item['source']})", style="magenta"))


def _print_web_findings(snapshot) -> None:
    stats = snapshot["params"].get("scan_stats", {})
    if not isinstance(stats, dict):
        stats = {}
    for kind, title in (("sqli", "SQLi findings"), ("lfi", "LFI findings")):
        findings = [item for item in snapshot["findings"] if item.get("module") == f"web/{kind}"]
        if kind not in stats and not findings:
            continue
        counters = stats.get(kind, {})
        if not isinstance(counters, dict):
            counters = {}
        if kind == "sqli":
            columns = ("URL", "Parameter", "Method", "Payload", "Evidence")
            rows = ((item["source"], item.get("parameter", ""), item.get("method", "GET"),
                     item.get("payload", ""), item.get("evidence", "")) for item in findings)
        else:
            columns = ("URL", "Parameter", "Payload", "Detected")
            rows = ((item["source"], item.get("parameter", ""), item.get("payload", ""),
                     item.get("detected", "")) for item in findings)
        console.print()
        print_table(title, columns, rows)
        # Счётчики относятся к последнему запуску; таблица хранит находки сессии.
        print_info(f"Кандидатов: {counters.get('candidates', 0)}, "
                   f"проверено: {counters.get('tested', 0)}, "
                   f"уязвимостей: {counters.get('findings', len(findings))}")


def print_summary(session) -> None:
    snapshot = session.snapshot()
    console.print(Text("\n═══ SUMMARY ═══", style="bold cyan"))
    console.print(f"Target: {snapshot['target'] or 'не задана'}\n")
    print_table("Open ports", ("Port", "Service", "Version"),
                ((port, service.get("name", "unknown"), service.get("version", ""))
                 for port, service in sorted(snapshot["services"].items())))
    console.print("\nFindings:")
    if not snapshot["findings"]:
        console.print("  — пока нет")
    for finding in snapshot["findings"]:
        console.print(Text(f"  [!] {finding['title']} ({finding['source']})", style="yellow"))
    _print_web_findings(snapshot)
    console.print("\nLoot:")
    print_loot(session)
    console.print("\nSuggestions:")
    suggestions: list[tuple[str, str]] = []
    services = snapshot["services"]
    if 6379 in services or any("redis" in item.get("name", "").lower() for item in services.values()):
        suggestions.append(("misc/redis_unauth", "проверить доступ Redis без пароля"))
    if 21 in services or any("ftp" in item.get("name", "").lower() for item in services.values()):
        suggestions.append(("misc/ftp_anon", "проверить анонимный FTP"))
    if any("?" in str(item["value"]) for item in snapshot["loot"] if item["type"] == "url"):
        suggestions.append(("web/sqli", "найдены URL с параметрами; также попробуйте web/lfi"))
    elif any(port in {80, 443, 8000, 8080, 8443, 3000, 5000} for port in services):
        suggestions.append(("web/dirb", "исследовать HTTP-каталоги"))
    for module, reason in suggestions:
        console.print(Text(f"  → use {module}    ({reason})", style="cyan"))
    if not suggestions:
        console.print("  → show modules")
