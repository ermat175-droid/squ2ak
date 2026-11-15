"""Server-Side Template Injection: доказательство вычисления выражения движком.

Как и cmdi, не ищем отражение payload, а внедряем арифметику в синтаксисе
разных шаблонизаторов и ищем в ответе ТОЛЬКО вычисленный результат между
случайными маркерами. Его появление доказывает, что движок выполнил выражение.
"""

import secrets
import string

from core.module_base import BaseModule
from modules.web.sqli import web_session
from utils import renderer
from utils.concurrency import threaded_map
from utils.crawl import collect_candidates
from utils.web import WebClient, WebRequestError


def _marker() -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))


def _payloads(head: str, tail: str, first: int, second: int):
    expr = f"{first}*{second}"
    return [
        ("jinja2/twig", head + "{{" + expr + "}}" + tail),
        ("freemarker/mako", head + "${" + expr + "}" + tail),
        ("smarty", head + "{" + expr + "}" + tail),
        ("erb", head + "<%= " + expr + " %>" + tail),
        ("razor", head + "@(" + expr + ")" + tail),
    ]


class SstiModule(BaseModule):
    name = "ssti"
    category = "web"
    description = "SSTI: доказательство вычисления выражения шаблонизатором"
    options = {
        "url": {"default": "", "required": False, "description": "Базовый URL; при crawl URL веб-сервисов сессии"},
        "param": {"default": "", "required": False, "description": "Явный параметр, например name"},
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
        self.session.params.setdefault("scan_stats", {})["ssti"] = stats
        param = str(self.get_option("param") or "")
        threads = max(1, min(64, int(self.get_option("threads"))))
        with WebClient(timeout=float(self.get_option("timeout")), verify=self.get_option("verify")) as client:
            candidates = collect_candidates(
                web_session(self), client, url=self.get_option("url") or None,
                param=param or None, method=self.get_option("method"), crawl=self.get_option("crawl"),
                max_urls=self.get_option("max_urls"), max_depth=self.get_option("max_depth"))
            tasks = []
            for candidate in candidates:
                indexes = [index for index, (name, _) in enumerate(candidate.params) if not param or name == param]
                for index in indexes[:max(1, min(50, self.get_option("max_parameters")))]:
                    tasks.append((candidate, index))
            stats["candidates"] = len(tasks)

            def probe(task):
                candidate, index = task
                value = candidate.params[index][1]
                return self._check(client, candidate, index, value)

            for task, result, error in threaded_map(probe, tasks, threads):
                stats["tested"] += 1
                if error is not None:
                    renderer.print_warn(str(error))
                    continue
                if not result:
                    continue
                candidate, index = task
                name = candidate.params[index][0]
                engine, payload, evidence = result
                stats["findings"] += 1
                rows.append((candidate.url, name, candidate.method, engine, payload))
                self.session.add_finding(f"Server-side template injection: {name} ({engine})", candidate.url,
                                         severity="critical", parameter=name, method=candidate.method,
                                         payload=payload, evidence=evidence, engine=engine, module=self.path)
                self.session.add_loot("finding", f"SSTI: {name} ({engine})", candidate.url)
        renderer.print_table("SSTI findings", ["URL", "Parameter", "Method", "Engine", "Payload"], rows)
        renderer.print_info(f"Кандидатов: {stats['candidates']}, проверено: {stats['tested']}, уязвимостей: {stats['findings']}")

    def _check(self, client, candidate, index, value):
        head, tail = _marker(), _marker()
        first, second = secrets.randbelow(89) + 11, secrets.randbelow(89) + 11
        expected = f"{head}{first * second}{tail}"
        for engine, template in _payloads(head, tail, first, second):
            payload = value + template
            try:
                response = candidate.send(client, index, payload)
            except WebRequestError as exc:
                renderer.print_warn(str(exc))
                continue
            if expected in response.text and expected not in payload:
                return engine, payload, f"evaluated template result {expected}"
        return None


Ssti = SstiModule
