"""Open redirect: параметр уводит перенаправление на чужой хост.

Клиент не следует за редиректами — проверяется сам Location (или клиентский
redirect в теле). Срабатывает только когда целевой хост равен нашему
подставному домену, что исключает совпадения с легитимными внутренними URL.
"""

import re
from urllib.parse import urlsplit

from core.module_base import BaseModule
from utils import renderer
from utils.concurrency import threaded_map
from utils.crawl import collect_candidates
from utils.web import WebClient, WebRequestError, service_view

EVIL = "squ2ak-evil.example"
PAYLOADS = [f"https://{EVIL}/", f"//{EVIL}/", f"https:/{EVIL}", f"/\\{EVIL}", f"http://{EVIL}/"]


def _offsite(response, evil):
    if response.status_code in {301, 302, 303, 307, 308}:
        location = response.headers.get("location", "")
        normalized = location.replace("\\", "/")
        parsed = urlsplit(normalized if "//" in normalized else "//" + normalized.lstrip("/"))
        if (parsed.hostname or "").lower() == evil:
            return "high", f"Location: {location[:120]}"
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type or not content_type:
        body = response.text[:200_000]
        if re.search(r'(?:url=|location(?:\.href)?\s*=\s*["\']?)(?:https?:)?(?://|/\\)' + re.escape(evil), body, re.I):
            return "medium", f"client-side redirect to {evil}"
    return None


class OpenRedirectModule(BaseModule):
    name = "open_redirect"
    category = "web"
    description = "Open redirect: параметр уводит на внешний хост"
    options = {
        "url": {"default": "", "required": False, "description": "Базовый URL; при crawl URL веб-сервисов сессии"},
        "param": {"default": "", "required": False, "description": "Явный параметр, например next"},
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
        self.session.params.setdefault("scan_stats", {})["open_redirect"] = stats
        param = str(self.get_option("param") or "")
        threads = max(1, min(64, int(self.get_option("threads"))))
        # Редиректы не раскрываем сами — нас интересует именно первый Location.
        with WebClient(timeout=float(self.get_option("timeout")), follow_redirects=False,
                       verify=self.get_option("verify")) as client:
            candidates = collect_candidates(
                service_view(self.session, self.get_option("ports")), client,
                url=self.get_option("url") or None, param=param or None, method=self.get_option("method"),
                crawl=self.get_option("crawl"), max_urls=self.get_option("max_urls"),
                max_depth=self.get_option("max_depth"))
            tasks = []
            for candidate in candidates:
                indexes = [index for index, (name, _) in enumerate(candidate.params) if not param or name == param]
                for index in indexes[:max(1, min(50, self.get_option("max_parameters")))]:
                    tasks.append((candidate, index))
            stats["candidates"] = len(tasks)

            def probe(task):
                candidate, index = task
                for payload in PAYLOADS:
                    try:
                        response = candidate.send(client, index, payload)
                    except WebRequestError as exc:
                        renderer.print_warn(str(exc))
                        continue
                    hit = _offsite(response, EVIL)
                    if hit:
                        return hit[0], payload, hit[1]
                return None

            for task, result, error in threaded_map(probe, tasks, threads):
                stats["tested"] += 1
                if error is not None:
                    renderer.print_warn(str(error))
                    continue
                if not result:
                    continue
                candidate, index = task
                name = candidate.params[index][0]
                severity, payload, evidence = result
                stats["findings"] += 1
                rows.append((candidate.url, name, candidate.method, payload, evidence))
                self.session.add_finding(f"Open redirect: {name}", candidate.url, severity=severity,
                                         parameter=name, method=candidate.method, payload=payload,
                                         evidence=evidence, module=self.path)
                self.session.add_loot("finding", f"Open redirect: {name}", candidate.url)
        renderer.print_table("Open redirect findings", ["URL", "Parameter", "Method", "Payload", "Evidence"], rows)
        renderer.print_info(f"Кандидатов: {stats['candidates']}, проверено: {stats['tested']}, уязвимостей: {stats['findings']}")


OpenRedirect = OpenRedirectModule
