"""Поиск каталогов с проверкой типичных мягких 404."""

from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from pathlib import Path
import re
import secrets
from types import SimpleNamespace
from urllib.parse import unquote, urljoin, urlsplit

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from core.module_base import BaseModule
from utils import renderer
from utils.net import parse_ports
from utils.web import WebClient, WebRequestError, web_urls


def _first_status(response) -> int:
    return response.history[0].status_code if response.history else response.status_code


def _body_signature(response) -> str:
    text = response.text[:10_000]
    path = urlsplit(str(response.url)).path
    if path and path != "/":
        # Заменяем путь целиком: слово app или login может быть частью общей SPA-страницы.
        text = text.replace(path, "<path>")
    return re.sub(r"\s+", " ", text).strip()


def _is_soft404(response, probes) -> bool:
    signature = _body_signature(response)
    for probe in probes:
        if _first_status(response) != _first_status(probe) or response.status_code != probe.status_code:
            continue
        baseline = _body_signature(probe)
        if signature == baseline:
            return True
        # Похожие длинные HTML-страницы часто имеют динамический токен или дату.
        if len(signature) > 100 and abs(len(signature) - len(baseline)) <= max(8, len(baseline) * 0.03):
            if SequenceMatcher(None, signature, baseline, autojunk=False).quick_ratio() > 0.98:
                if SequenceMatcher(None, signature, baseline, autojunk=False).ratio() > 0.98:
                    return True
    return False


class DirbModule(BaseModule):
    name = "dirb"
    category = "web"
    description = "Поиск директорий по словарю, включая защиту от soft 404"
    options = {
        "url": {"default": "", "required": False, "description": "Базовый URL"},
        "wordlist": {"default": "", "required": False, "description": "Словарь; по умолчанию wordlists/common.txt"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot, например 3000,8080"},
        "threads": {"default": 12, "required": False, "description": "Число потоков (1–64)"},
        "status_codes": {"default": "200,201,204,301,302,307,308,401,403", "required": False, "description": "Интересующие HTTP-коды"},
        "follow_redirects": {"default": True, "required": False, "description": "Следовать перенаправлениям"},
        "show_all_statuses": {"default": False, "required": False, "description": "Показывать все ответы, включая 404 и soft 404"},
        "extensions": {"default": "", "required": False, "description": "Дополнительные расширения, например php,txt,tar.gz"},
        "max_words": {"default": 5000, "required": False, "description": "Лимит путей словаря"},
        "recursion": {"default": False, "required": False, "description": "Повторять словарь в найденных каталогах"},
        "recursion_depth": {"default": 1, "required": False, "description": "Глубина рекурсии каталогов (1–4)"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }
    RECURSION_BUDGET = 64

    def run(self) -> None:
        path = Path(str(self.get_option("wordlist") or self.project_dir / "wordlists/common.txt"))
        if not path.is_absolute():
            path = self.project_dir / path
        words = self._read_words(path)
        statuses = {int(code.strip()) for code in str(self.get_option("status_codes")).split(",")}
        if any(not 100 <= code <= 599 for code in statuses):
            raise ValueError("HTTP-коды должны быть в диапазоне 100–599")
        threads = max(1, min(64, int(self.get_option("threads"))))
        follow = self.get_option("follow_redirects")
        show_all = self.get_option("show_all_statuses")
        services = dict(self.session.services)
        if self.get_option("ports"):
            for port in parse_ports(str(self.get_option("ports"))):
                services[port] = {"name": "https" if port in {443, 8443} else "http"}
        target_session = SimpleNamespace(target=self.session.target, services=services)
        rows = []
        failed = 0
        recursion = bool(self.get_option("recursion"))
        depth_limit = max(1, min(4, int(self.get_option("recursion_depth")))) if recursion else 0

        with WebClient(timeout=float(self.get_option("timeout")), follow_redirects=follow,
                       verify=self.get_option("verify")) as client:
            scanned: set[str] = set()
            queue: deque[tuple[str, int]] = deque(
                (base.split("?", 1)[0].rstrip("/") + "/", 0)
                for base in web_urls(target_session, self.get_option("url") or None))

            def scan_base(base: str) -> set[str]:
                nonlocal failed
                children: set[str] = set()
                probes = []
                for _ in range(2):
                    try:
                        probes.append(client.get(urljoin(base, "squ2ak-missing-" + secrets.token_hex(12))))
                    except WebRequestError:
                        pass
                if not probes:
                    renderer.print_warn(f"{base}: HTTP-сервис недоступен; словарь пропущен.")
                    return children
                with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=renderer.console) as progress:
                    task = progress.add_task(f"Directories {base}", total=len(words))
                    pool = ThreadPoolExecutor(max_workers=threads)
                    interrupted = False
                    try:
                        futures = {pool.submit(client.get, urljoin(base, word)): urljoin(base, word) for word in words}
                        try:
                            for future in as_completed(futures):
                                url = futures[future]
                                try:
                                    response = future.result()
                                    status = _first_status(response)
                                    interesting = status in statuses and not _is_soft404(response, probes)
                                    if show_all or interesting:
                                        displayed_status = f"{status} → {response.status_code}" if response.history else str(status)
                                        rows.append((displayed_status, len(response.content), url, str(response.url)))
                                    if interesting:
                                        self.session.add_loot("url", url, base)
                                        final_url = str(response.url)
                                        if final_url != url:
                                            # Auto получает также конечный каталог для поиска ссылок и форм.
                                            self.session.add_loot("url", final_url, base)
                                        label = "Protected path" if status in {401, 403} else "Web path found"
                                        self.session.add_finding(f"{label}: {urlsplit(url).path}", url, status=status, final_url=final_url)
                                        if recursion and status not in {401, 403}:
                                            child = self._child_dir(base, url, final_url)
                                            if child:
                                                children.add(child)
                                except WebRequestError:
                                    failed += 1
                                finally:
                                    progress.advance(task)
                        except KeyboardInterrupt:
                            interrupted = True
                            for future in futures:
                                future.cancel()
                            raise
                    finally:
                        pool.shutdown(wait=not interrupted, cancel_futures=True)
                return children

            while queue:
                base, depth = queue.popleft()
                if base in scanned or len(scanned) >= self.RECURSION_BUDGET:
                    continue
                scanned.add(base)
                children = scan_base(base)
                if recursion and depth < depth_limit:
                    for child in sorted(children):
                        if child not in scanned:
                            queue.append((child, depth + 1))
        renderer.print_table("Discovered paths", ["Status", "Bytes", "URL", "Final URL"], sorted(rows, key=lambda row: row[2]))
        if failed:
            renderer.print_warn(f"HTTP-ошибки при проверке {failed} путей; остальные результаты сохранены.")

    def _child_dir(self, base: str, url: str, final_url: str) -> str | None:
        """Каталог того же origin глубже base — кандидат для рекурсии."""
        origin = urlsplit(base)
        base_path = origin.path
        for candidate in (final_url, url):
            parsed = urlsplit(candidate.split("?", 1)[0])
            if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
                continue
            if parsed.path.endswith("/") and parsed.path != base_path:
                return candidate.split("?", 1)[0].rstrip("/") + "/"
        return None

    def _read_words(self, path: Path) -> list[str]:
        limit = max(1, min(100_000, int(self.get_option("max_words"))))
        extensions = [value.strip().removeprefix(".") for value in str(self.get_option("extensions") or "").split(",") if value.strip()]
        if any(not re.fullmatch(r"[A-Za-z0-9_-]{1,20}(?:\.[A-Za-z0-9_-]{1,20}){0,3}", extension)
               or len(extension) > 64 for extension in extensions):
            raise ValueError("Расширения: буквы, цифры, дефис, подчёркивание; допустимо tar.gz")
        words = []
        seen = set()
        with path.open(encoding="utf-8", errors="replace") as source:
            for line in source:
                word = line.strip()
                if not word or word.startswith("#"):
                    continue
                decoded = word
                for _ in range(3):
                    decoded = unquote(decoded)
                if (urlsplit(decoded).scheme or decoded.startswith("/")
                        or ".." in decoded.split("/") or any(char in decoded for char in ":?#\\")
                        or any(char.isspace() or ord(char) < 32 for char in decoded)):
                    continue
                for candidate in [word] + [word.rstrip("/") + "." + extension for extension in extensions]:
                    if candidate not in seen:
                        seen.add(candidate)
                        words.append(candidate)
                    if len(words) >= limit:
                        return words
        return words
