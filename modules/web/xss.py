"""Reflected XSS: контекст-ломающий маркер должен отразиться без HTML-кодирования.

Низкий процент ложных срабатываний: засчитывается только дословное отражение
payload с опасными символами (`<`, `>`, `"`). Если приложение экранирует вывод,
в ответе окажется `&lt;svg...` и совпадения не будет. Проверяется лишь ответ,
который действительно является HTML (иначе отражение не исполнится браузером).
"""

import secrets
import string

from core.module_base import BaseModule
from modules.web.sqli import web_session
from utils import renderer
from utils.concurrency import threaded_map
from utils.crawl import collect_candidates
from utils.web import WebClient, WebRequestError

# (шаблон payload, человекочитаемое имя контекста)
PROBES = [
    ("<svg/onload=alert({m})>", "html-text"),
    ('"><img src=x onerror=alert({m})>', "double-quote-attr"),
    ("'><img src=x onerror=alert({m})>", "single-quote-attr"),
    ("</script><svg onload=alert({m})>", "script-block"),
]


def _is_html(response) -> bool:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type:
        return content_type in {"text/html", "application/xhtml+xml"}
    head = response.text[:1024].lower()
    return "<html" in head or "<!doctype html" in head or "<body" in head


def _marker() -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))


class XssModule(BaseModule):
    name = "xss"
    category = "web"
    description = "Reflected XSS: дословное отражение контекст-ломающего маркера"
    options = {
        "url": {"default": "", "required": False, "description": "Базовый URL; при crawl URL веб-сервисов сессии"},
        "param": {"default": "", "required": False, "description": "Явный параметр, например q"},
        "method": {"default": "GET", "required": False, "description": "GET или POST для явного параметра"},
        "crawl": {"default": True, "required": False, "description": "Искать параметры в ссылках и формах"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "max_urls": {"default": 10, "required": False, "description": "Лимит кандидатов и страниц обхода"},
        "max_depth": {"default": 1, "required": False, "description": "Глубина обхода"},
        "max_parameters": {"default": 10, "required": False, "description": "Максимум полей одного кандидата"},
        "threads": {"default": 8, "required": False, "description": "Параллельная проверка параметров (1–64)"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        stats = {"candidates": 0, "tested": 0, "findings": 0}
        self.session.params.setdefault("scan_stats", {})["xss"] = stats
        param = str(self.get_option("param") or "")
        threads = max(1, min(64, int(self.get_option("threads"))))
        with WebClient(timeout=float(self.get_option("timeout")), verify=self.get_option("verify")) as client:
            candidates = collect_candidates(
                web_session(self), client, url=self.get_option("url") or None,
                param=param or None, method=self.get_option("method"), crawl=self.get_option("crawl"),
                max_urls=self.get_option("max_urls"), max_depth=self.get_option("max_depth"),
            )
            tasks = []
            for candidate in candidates:
                indexes = [index for index, (name, _) in enumerate(candidate.params) if not param or name == param]
                for index in indexes[:max(1, min(50, self.get_option("max_parameters")))]:
                    tasks.append((candidate, index))
            stats["candidates"] = len(tasks)

            def probe(task):
                candidate, index = task
                return self._check(client, candidate, index)

            for task, result, error in threaded_map(probe, tasks, threads):
                stats["tested"] += 1
                if error is not None:
                    renderer.print_warn(str(error))
                    continue
                if not result:
                    continue
                candidate, index = task
                name = candidate.params[index][0]
                context, payload = result
                stats["findings"] += 1
                rows.append((candidate.url, name, candidate.method, context, payload))
                self.session.add_finding(
                    f"Reflected XSS: {name} ({context})", candidate.url, severity="high",
                    parameter=name, method=candidate.method, payload=payload, context=context,
                    module=self.path)
                self.session.add_loot("finding", f"Reflected XSS: {name} ({context})", candidate.url)
        renderer.print_table("Reflected XSS findings", ["URL", "Parameter", "Method", "Context", "Payload"], rows)
        renderer.print_info(f"Кандидатов: {stats['candidates']}, проверено: {stats['tested']}, уязвимостей: {stats['findings']}")

    def _check(self, client, candidate, index):
        for template, context in PROBES:
            payload = template.format(m=_marker())
            try:
                response = candidate.send(client, index, payload)
            except WebRequestError as exc:
                renderer.print_warn(str(exc))
                continue
            if _is_html(response) and payload in response.text:
                return context, payload
        return None


Xss = XssModule
