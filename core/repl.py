"""Интерактивная консоль с историей и контекстным Tab."""

from __future__ import annotations

import json
import logging
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from io import StringIO

import requests
import yaml
from prompt_toolkit import ANSI, PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.text import Text

from core.auto import AutoRunner, default_report_base
from core.execution import execute_module
from core.logging_setup import state_dir
from core.registry import ModuleRegistry
from core.report import write_report
from core.session import Session
from utils import renderer

logger = logging.getLogger("squ2ak")
COMMANDS = ["help", "show", "use", "set", "setg", "run", "exploit", "back", "sessions",
            "loot", "report", "python", "auto", "clear", "exit"]


def parse_value(value: str):
    # YAML разрешает списки для urls, числа и bool без выполнения выражений.
    try:
        result = yaml.safe_load(value)
        return value if result is None else result
    except yaml.YAMLError:
        return value


class Squ2akCompleter(Completer):
    def __init__(self, repl: REPL) -> None:
        self.repl = repl

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        words = text.split()
        prefix = "" if not text or text[-1].isspace() else words[-1]
        context = words if not prefix else words[:-1]
        candidates = []
        if not context:
            candidates = COMMANDS
        elif context == ["use"] or context == ["auto", "from"]:
            candidates = self.repl.registry.paths()
        elif context == ["show"]:
            candidates = ["modules", "options"]
        elif context == ["auto"]:
            candidates = ["full", "step", "from", "list"]
        elif context == ["report"]:
            candidates = ["md", "json", "both"]
        elif len(context) == 1 and context[0] in {"set", "setg"}:
            options = self.repl.active.options if self.repl.active is not None else {}
            candidates = sorted(set(options) | set(self.repl.session.params) |
                                {"target", "ports", "timeout", "threads", "url", "urls", "wordlist"})
        for candidate in candidates:
            if candidate.startswith(prefix):
                yield Completion(candidate, start_position=-len(prefix))


class REPL:
    def __init__(self, session: Session, registry: ModuleRegistry, pipeline: list[dict], session_log=None) -> None:
        self.session, self.registry, self.pipeline = session, registry, pipeline
        self.session_log = session_log
        self.active = None
        self.python_context = {"session": session, "requests": requests, "re": re, "subprocess": subprocess}

    def _prompt(self):
        text = Text("squ2ak", style="bold cyan")
        if self.active is not None:
            text.append(f" ({self.active.path})", style="cyan")
        text.append(" > ", style="cyan")
        output = StringIO()
        Console(file=output, force_terminal=True, color_system="truecolor").print(text, end="")
        return ANSI(output.getvalue())

    def run(self) -> None:
        prompt_session = None
        if sys.stdin.isatty():
            history_path = state_dir() / "history"
            history_path.touch(mode=0o600, exist_ok=True)
            prompt_session = PromptSession(history=FileHistory(str(history_path)),
                                           completer=Squ2akCompleter(self),
                                           auto_suggest=AutoSuggestFromHistory(),
                                           complete_while_typing=False)
        while True:
            try:
                if prompt_session is not None:
                    line = prompt_session.prompt(self._prompt())
                else:
                    label = f"squ2ak ({self.active.path})" if self.active is not None else "squ2ak"
                    line = input(label + " > ")
            except EOFError:
                break
            except KeyboardInterrupt:
                renderer.print_warn("Ввод отменён; exit завершает консоль")
                continue
            if not self.dispatch(line):
                break

    def dispatch(self, line: str) -> bool:
        line = line.strip()
        if not line:
            return True
        if self.session_log is not None:
            self.session_log.command(line)
        else:
            logger.info("Command: %s", line)
        try:
            if line.split(None, 1)[0].lower() == "python":
                pieces = line.split(None, 1)
                self._python(pieces[1] if len(pieces) == 2 else "")
                return True
            parts = shlex.split(line)
            command, args = parts[0].lower(), parts[1:]
            if command in {"exit", "quit"}:
                return False
            if command == "help":
                self._help()
            elif command == "clear":
                renderer.console.clear()
            elif command == "use" and len(args) == 1:
                self.active = self.registry.create(args[0], self.session)
                renderer.print_success(f"Выбран {self.active.path}")
            elif command in {"set", "setg"} and len(args) >= 2:
                key, value = args[0].lower(), parse_value(" ".join(args[1:]))
                if key == "target":
                    self.session.set_target(str(value))
                elif command == "set" and self.active is not None:
                    self.active.set_option(key, value)
                else:
                    self.session.params[key] = value
                renderer.print_success(f"{key} => {value}")
            elif command == "show" and args == ["modules"]:
                self._show_modules()
            elif command == "show" and args == ["options"]:
                self._show_options()
            elif command in {"run", "exploit"} and not args:
                if self.active is None:
                    renderer.print_error("Сначала use <category>/<name>")
                else:
                    execute_module(self.active)
            elif command == "back" and not args:
                self.active = None
            elif command == "sessions" and not args:
                renderer.console.print(Text(json.dumps(self.session.snapshot(), ensure_ascii=False,
                                                       indent=2, default=str)))
            elif command == "loot" and not args:
                renderer.print_loot(self.session)
            elif command == "report":
                self._report(args)
            elif command == "auto":
                self._auto(args)
            else:
                renderer.print_error("Неизвестная команда или аргументы; используйте help")
        except KeyboardInterrupt:
            renderer.print_warn("Модуль прерван; консоль готова к следующей команде")
        except Exception as exc:
            renderer.print_error(str(exc))
            logger.exception("Command failed: %s", line)
        return True

    def _python(self, code: str) -> None:
        if not code:
            renderer.print_error("python <code>")
            return
        try:
            try:
                compiled = compile(code, "<squ2ak>", "eval")
            except SyntaxError:
                exec(compile(code, "<squ2ak>", "exec"), self.python_context)
            else:
                result = eval(compiled, self.python_context)
                if result is not None:
                    renderer.console.print(Text(repr(result)))
        except SystemExit as exc:
            renderer.print_warn(f"Python завершил код с SystemExit({exc.code}); REPL продолжает работу")

    def _show_modules(self) -> None:
        renderer.print_table("Modules", ("Category", "Name", "Description"),
                             ((cls.category, cls.name, cls.description)
                              for _, cls in sorted(self.registry.modules.items())))

    def _show_options(self) -> None:
        if self.active is None:
            renderer.print_table("Session options", ("Option", "Value"),
                                 [("target", self.session.target), *sorted(self.session.params.items())])
            return
        renderer.print_table(self.active.path, ("Option", "Value", "Required", "Source", "Description"),
                             ((key, self.active.get_option(key), "yes" if spec.get("required") else "no",
                               "session" if key == "target" else "local" if key in self.active._values
                               else "global" if key in self.session.params else "default",
                               spec.get("description", "")) for key, spec in self.active.options.items()))

    def _report(self, args: list[str]) -> None:
        fmt, path = "md", None
        for arg in args:
            if arg.lower() in {"md", "json", "both"}:
                fmt = arg.lower()
            elif path is None:
                path = arg
            else:
                raise ValueError("report [путь] [md|json|both]")
        if path is None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", self.session.target or "session")
            path = f"squ2ak-report-{safe}-{stamp}"
        for written in write_report(self.session, path, fmt):
            renderer.print_success(f"Отчёт: {written}")

    def _auto(self, args: list[str]) -> None:
        mode, from_stage = "step", None
        if args == ["list"]:
            AutoRunner(self.session, self.pipeline, mode, self.registry).print_pipeline()
            return
        if args in (["full"], ["step"]):
            mode = args[0]
        elif len(args) == 2 and args[0] == "from":
            from_stage = args[1]
        elif args:
            raise ValueError("auto [full|step|list] или auto from <module_path>")
        params = self.session.params
        report_base = default_report_base(self.session) if params.get("auto_report", True) else None
        report_format = str(params.get("auto_report_format", "md"))
        if report_format not in {"md", "json", "both"}:
            report_format = "md"
        AutoRunner(self.session, self.pipeline, mode, self.registry,
                   report_base=report_base, report_format=report_format).run(from_stage)

    def _help(self) -> None:
        renderer.print_table("Commands", ("Command", "Description"), [
            ("help", "Все команды"), ("show modules", "Список доступных модулей"),
            ("use <category>/<name>", "Выбрать модуль"),
            ("set <param> <value>", "Параметр модуля; без модуля — параметр сессии"),
            ("setg <param> <value>", "Глобальное значение для всех модулей"),
            ("show options", "Параметры и источник каждого значения"),
            ("run / exploit", "Запустить выбранный модуль"), ("back", "Снять выбор модуля"),
            ("sessions", "Глобальное состояние"), ("loot", "Флаги, файлы и другие находки"),
            ("report [path] [md|json|both]", "Отчёт по находкам/сервисам/loot"),
            ("python <code>", "Python: session, requests, re, subprocess"),
            ("auto / auto step", "Пайплайн с паузами Enter/s/q"),
            ("auto full", "Пайплайн без пауз"), ("auto from <module_path>", "Начать с этапа, с паузами"),
            ("auto list", "Текущий пайплайн"), ("clear", "Очистить экран"), ("exit", "Выход"),
        ])


Squ2akREPL = REPL
