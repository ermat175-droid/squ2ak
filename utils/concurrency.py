"""Ограниченный конкурентный проход с корректной обработкой Ctrl+C.

Повторяет поведение dirb: при Ctrl+C отменяет невыполненные задачи и не ждёт
уже запущенные. Исключения задач не прерывают проход — они возвращаются рядом
с элементом, чтобы вызывающий модуль сам решил, предупреждать или падать.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, Iterator

MAX_WORKERS = 64


def threaded_map(
    func: Callable[[Any], Any],
    items: Iterable[Any],
    threads: int = 8,
) -> Iterator[tuple[Any, Any, BaseException | None]]:
    """Применяет func к каждому элементу, выдавая (item, result, error).

    Порядок выдачи — по мере готовности. При threads<=1 или одном элементе
    работает последовательно, без создания пула (удобно для тестов и отладки).
    """
    items = list(items)
    workers = max(1, min(MAX_WORKERS, int(threads)))
    if workers == 1 or len(items) <= 1:
        for item in items:
            try:
                yield item, func(item), None
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001 — ошибка задачи возвращается вызывающему
                yield item, None, exc
        return

    pool = ThreadPoolExecutor(max_workers=workers)
    interrupted = False
    try:
        futures = {pool.submit(func, item): item for item in items}
        try:
            for future in as_completed(futures):
                item = futures[future]
                try:
                    yield item, future.result(), None
                except KeyboardInterrupt:
                    raise
                except Exception as exc:  # noqa: BLE001
                    yield item, None, exc
        except KeyboardInterrupt:
            interrupted = True
            for future in futures:
                future.cancel()
            raise
    finally:
        pool.shutdown(wait=not interrupted, cancel_futures=True)
