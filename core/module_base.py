"""Контракт модулей и наследование параметров."""

from __future__ import annotations

import logging
import math
from copy import deepcopy
from pathlib import Path
from typing import Any

from core.session import Session
from utils import renderer

logger = logging.getLogger("squ2ak")


class BaseModule:
    name: str = ""
    category: str = ""
    description: str = ""
    options: dict = {}
    common_options = {
        "target": {"default": None, "required": True, "description": "IP, хост или URL цели"},
        "timeout": {"default": 5.0, "required": False, "description": "Сетевой таймаут, секунды"},
    }
    project_dir = Path(__file__).resolve().parents[1]

    def __init__(self, session: Session) -> None:
        self.session = session
        self.options = deepcopy({**self.common_options, **type(self).options})
        self._values: dict[str, Any] = {}
        self._configured_target = session.target

    @property
    def path(self) -> str:
        return f"{self.category}/{self.name}"

    def set_option(self, name: str, value: Any) -> None:
        self._sync_target()
        name = name.lower()
        if name not in self.options:
            raise ValueError(f"Неизвестный параметр {name}; используйте show options")
        value = self._coerce(name, value)
        if name == "target":
            self.session.set_target(value)
        else:
            self._values[name] = value

    def _coerce(self, name: str, value: Any) -> Any:
        default = self.options[name].get("default")
        if name == "timeout":
            return float(value)
        if isinstance(default, bool):
            if isinstance(value, bool):
                return value
            if str(value).lower() in {"true", "1", "yes", "on"}:
                return True
            if str(value).lower() in {"false", "0", "no", "off"}:
                return False
            raise ValueError(f"{name}: ожидается true или false")
        if isinstance(default, int):
            return int(value)
        if isinstance(default, float):
            return float(value)
        return value

    def get_option(self, name: str) -> Any:
        self._sync_target()
        if name not in self.options:
            raise KeyError(name)
        if name == "target":
            return self.session.target
        value = self._values.get(name, self.session.params.get(name, self.options[name].get("default")))
        return self._coerce(name, value)

    def _sync_target(self) -> None:
        if self._configured_target != self.session.target:
            if self._configured_target is not None:
                self._values.pop("url", None)
            self._configured_target = self.session.target

    def effective_options(self) -> dict[str, Any]:
        return {name: self.get_option(name) for name in self.options}

    def validate(self) -> bool:
        try:
            values = self.effective_options()
            missing = [key for key, spec in self.options.items()
                       if spec.get("required") and values[key] in (None, "", [])]
            if missing:
                raise ValueError("Задайте обязательные параметры: " + ", ".join(missing))
            if not math.isfinite(values.get("timeout", 1)) or values.get("timeout", 1) <= 0:
                raise ValueError("timeout должен быть конечным числом больше нуля")
            for name in ("threads", "workers", "max_urls"):
                if name in values and not 1 <= values[name] <= 1024:
                    raise ValueError(f"{name} должен быть в диапазоне 1–1024")
            return True
        except (ValueError, TypeError, KeyError) as exc:
            renderer.print_error(str(exc))
            logger.debug("Invalid module options", exc_info=True)
            return False

    def run(self) -> None:
        raise NotImplementedError
