"""Автозагрузка подклассов BaseModule с изоляцией ошибок импорта."""

from __future__ import annotations

import importlib
import inspect
import logging
from pathlib import Path

from core.module_base import BaseModule
from core.session import Session
from utils import renderer

logger = logging.getLogger("squ2ak")


class ModuleRegistry:
    def __init__(self, project_dir: Path | None = None) -> None:
        self.project_dir = project_dir or BaseModule.project_dir
        self.modules: dict[str, type[BaseModule]] = {}
        self.errors: dict[str, str] = {}

    def register(self, module_class: type[BaseModule]) -> None:
        if not module_class.name or not module_class.category:
            raise ValueError(f"Модуль {module_class.__name__} не объявил category/name")
        path = f"{module_class.category}/{module_class.name}"
        if path in self.modules and self.modules[path] is not module_class:
            raise ValueError(f"Дублирующееся имя модуля: {path}")
        self.modules[path] = module_class

    def discover(self) -> ModuleRegistry:
        for package in ("modules", "templates"):
            for file in sorted((self.project_dir / package).rglob("*.py")):
                if file.name.startswith("_") or "__pycache__" in file.parts:
                    continue
                import_name = ".".join(file.relative_to(self.project_dir).with_suffix("").parts)
                try:
                    module = importlib.import_module(import_name)
                    for _, cls in inspect.getmembers(module, inspect.isclass):
                        if cls is not BaseModule and cls.__module__ == module.__name__ and issubclass(cls, BaseModule):
                            self.register(cls)
                except Exception as exc:
                    self.errors[import_name] = str(exc)
                    renderer.print_warn(f"Модуль {import_name} недоступен: {exc}")
                    logger.exception("Module discovery failed: %s", import_name)
        return self

    def create(self, path: str, session: Session) -> BaseModule:
        try:
            module_class = self.modules[path]
        except KeyError as exc:
            raise ValueError(f"Модуль {path} не найден; используйте show modules") from exc
        return module_class(session)

    def paths(self) -> list[str]:
        return sorted(self.modules)


Registry = ModuleRegistry
