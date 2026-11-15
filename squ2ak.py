#!/usr/bin/env python3
"""Точка входа squ2ak: REPL, one-shot и auto."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    print("squ2ak требует Python 3.11+", file=sys.stderr)
    raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="squ2ak — CTF & Pentest Framework v0.1",
                                     epilog="Опции модуля: --ports 80,443 --timeout 2 --scan connect; --set key=value")
    parser.add_argument("--target", help="IP, хост или HTTP(S) URL")
    parser.add_argument("--module", help="Путь модуля, например recon/portscan")
    parser.add_argument("--auto", choices=("full", "step"), help="Запустить auto_pipeline")
    parser.add_argument("--from-stage", help="Начать auto с указанного модуля")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().with_name("config.yaml"))
    parser.add_argument("--list-modules", action="store_true")
    parser.add_argument("--report", metavar="PATH", help="Записать отчёт по сессии (без расширения)")
    parser.add_argument("--report-format", choices=("md", "json", "both"), default="md",
                        help="Формат отчёта: md (по умолчанию), json или both")
    parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="Глобальный параметр")
    parser.add_argument("--version", action="version", version="squ2ak 0.1.0")
    return parser


def extra_options(tokens: list[str]) -> dict[str, str]:
    result = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--") or token == "--":
            raise ValueError(f"Ожидается --param value, получено: {token}")
        option = token[2:]
        if "=" in option:
            key, value = option.split("=", 1)
        else:
            key = option
            index += 1
            if index >= len(tokens) or tokens[index].startswith("--"):
                raise ValueError(f"Задайте значение --{key}")
            value = tokens[index]
        if not key:
            raise ValueError("Пустое имя параметра")
        result[key.replace("-", "_")] = value
        index += 1
    return result


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, remaining = parser.parse_known_args(argv)
    if args.module and args.auto:
        parser.error("--module и --auto выбирают разные режимы")
    if args.from_stage and not args.auto:
        parser.error("--from-stage требует --auto")
    if remaining and not (args.module or args.auto):
        parser.error("Опции модуля требуют --module или --auto")
    try:
        import yaml
        from core.auto import AutoRunner, default_report_base
        from core.execution import execute_module
        from core.logging_setup import SessionLog
        from core.registry import ModuleRegistry
        from core.report import write_report
        from core.repl import REPL, parse_value
        from core.session import Session
        from utils import renderer
    except ImportError as exc:
        print(f"Не хватает зависимости: {exc}. Установите requirements.txt в venv.", file=sys.stderr)
        return 1
    try:
        with SessionLog() as log:
            log.command("CLI " + " ".join(sys.argv[1:] if argv is None else argv))
            renderer.print_banner()
            renderer.print_info(f"Session log: {log.path}")
            data = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict) or not isinstance(data.get("params", {}), dict):
                raise ValueError("config.yaml должен содержать словарь и params-словарь")
            session = Session()
            session.reset()
            session.params.update(data.get("params", {}))
            for item in args.set:
                if "=" not in item:
                    raise ValueError("--set требует KEY=VALUE")
                key, value = item.split("=", 1)
                if key.lower() == "target":
                    session.set_target(value)
                else:
                    session.params[key.lower()] = parse_value(value)
            if args.target:
                session.set_target(args.target)
            registry = ModuleRegistry().discover()
            pipeline = data.get("auto_pipeline", [])
            repl = REPL(session, registry, pipeline, log)
            if args.list_modules:
                repl._show_modules()
                return 0 if not registry.errors else 1

            def emit_report() -> None:
                if not args.report:
                    return
                for written in write_report(session, args.report, args.report_format):
                    renderer.print_info(f"Report: {written}")

            options = extra_options(remaining)
            if args.module:
                module = registry.create(args.module, session)
                for key, value in options.items():
                    module.set_option(key, parse_value(value))
                success = execute_module(module)
                renderer.print_summary(session)
                emit_report()
                return 0 if success else 1
            if args.auto:
                session.params.update({key: parse_value(value) for key, value in options.items()})
                # Явный --report имеет приоритет; иначе auto сам кладёт отчёт рядом с логами.
                auto_report = session.params.get("auto_report", True) and not args.report
                report_base = default_report_base(session) if auto_report else None
                runner = AutoRunner(session, pipeline, args.auto, registry,
                                    report_base=report_base, report_format=args.report_format)
                if not session.target:
                    raise ValueError("Для auto задайте --target")
                runner.run(args.from_stage)
                emit_report()
                if any(stage["status"] == "interrupted" for stage in runner.results):
                    return 130
                return 1 if any(stage["status"] == "failed" for stage in runner.results) else 0
            repl.run()
            emit_report()
            return 0
    except KeyboardInterrupt:
        print("\nМодуль прерван", file=sys.stderr)
        return 130
    except Exception as exc:
        # Ошибка конфигурации/файловой системы не оставляет traceback в терминале.
        print(f"squ2ak: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
