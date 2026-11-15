"""Общий запуск для REPL, CLI и auto."""

import logging
import time

from core.module_base import BaseModule
from utils import renderer

logger = logging.getLogger("squ2ak")


def execute_module(module: BaseModule) -> bool:
    renderer.print_info(f"Running {module.path} against {module.session.target or 'unset'}...")
    if not module.validate():
        return False
    started = time.monotonic()
    try:
        module.run()
        logger.info("Finished %s in %.3fs", module.path, time.monotonic() - started)
        return True
    except KeyboardInterrupt:
        logger.info("Interrupted module %s", module.path)
        raise
    except Exception as exc:
        renderer.print_error(f"{module.path}: {exc}")
        logger.exception("Module failed: %s", module.path)
        return False
