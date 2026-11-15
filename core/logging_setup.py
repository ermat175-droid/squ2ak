"""Лог команд и вывода, включая print из встроенной Python-консоли."""

from __future__ import annotations

import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def state_dir() -> Path:
    path = Path(os.environ.get("SQU2AK_HOME", str(Path.home() / ".squ2ak"))).expanduser()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


class Tee:
    def __init__(self, stream, log_file, lock: RLock) -> None:
        self.stream, self.log_file, self.lock = stream, log_file, lock

    def write(self, text: str) -> int:
        with self.lock:
            result = self.stream.write(text)
            self.log_file.write(ANSI.sub("", text))
            self.log_file.flush()
            return result

    def flush(self) -> None:
        with self.lock:
            self.stream.flush()
            self.log_file.flush()

    def __getattr__(self, name):
        return getattr(self.stream, name)


class SessionLog:
    def __init__(self) -> None:
        directory = state_dir() / "sessions"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.path = directory / f"{name}.log"
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        self.file = os.fdopen(fd, "w", encoding="utf-8", buffering=1)
        self.lock = RLock()
        self.original_stdout, self.original_stderr = sys.stdout, sys.stderr
        self.handler = None

    def __enter__(self) -> SessionLog:
        sys.stdout = Tee(self.original_stdout, self.file, self.lock)
        sys.stderr = Tee(self.original_stderr, self.file, self.lock)
        # Traceback нужен в файле; в терминале остаётся краткая ошибка renderer.
        self.handler = logging.StreamHandler(self.file)
        self.handler.lock = self.lock
        self.handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger = logging.getLogger("squ2ak")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.addHandler(self.handler)
        from utils.renderer import configure_console
        configure_console()
        return self

    def command(self, line: str) -> None:
        with self.lock:
            self.file.write(f"\n[{datetime.now(timezone.utc).isoformat()}] > {line}\n")
            self.file.flush()

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handler is not None:
            if exc is not None:
                logging.getLogger("squ2ak").error("CLI stopped: %s", exc,
                                                exc_info=(exc_type, exc, traceback))
            logging.getLogger("squ2ak").removeHandler(self.handler)
            self.handler.close()
        sys.stdout, sys.stderr = self.original_stdout, self.original_stderr
        from utils.renderer import configure_console
        configure_console()
        self.file.close()
