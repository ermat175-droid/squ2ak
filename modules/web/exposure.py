"""Открытые чувствительные файлы: .git, .env, бэкапы, служебные страницы.

Статус 200 недостаточен (SPA отдаёт 200 на всё): каждый путь подтверждается
маркером содержимого, поэтому ложных срабатываний почти нет. Проверки путей
идут параллельно через общий конкурентный хелпер.
"""

import re
from urllib.parse import urljoin, urlsplit

from core.module_base import BaseModule
from utils import renderer
from utils.concurrency import threaded_map
from utils.web import WebClient, WebRequestError, service_view, web_urls


def _text(pattern, *, reject_html=True):
    def check(response):
        body = response.text[:200_000]
        if reject_html and re.search(r"<html|<!doctype html", body[:512], re.I):
            return False
        return bool(re.search(pattern, body))
    return check


def _ds_store(response):
    return response.content[:8] == b"\x00\x00\x00\x01Bud1"


# (путь, человекочитаемое имя, severity, валидатор содержимого)
CHECKS = [
    (".git/HEAD", "Exposed .git/HEAD", "high", _text(r"^(?:ref:\s+refs/|[0-9a-f]{40}\b)")),
    (".git/config", "Exposed .git/config", "high", _text(r"\[core\]")),
    (".env", "Exposed .env", "high", _text(r"(?m)^[A-Z][A-Z0-9_]{1,40}=")),
    (".svn/entries", "Exposed .svn/entries", "medium", _text(r"^\d+\s|svn:")),
    (".htpasswd", "Exposed .htpasswd", "high",
     _text(r"(?m)^[^:\s]{1,64}:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13}$)")),
    ("phpinfo.php", "Exposed phpinfo()", "medium", _text(r"phpinfo\(\)|<title>phpinfo\(\)|PHP Version")),
    ("server-status", "Apache server-status", "medium", _text(r"Apache Server Status")),
    ("wp-config.php.bak", "Exposed wp-config backup", "high", _text(r"DB_PASSWORD|DB_NAME", reject_html=False)),
    ("config.php.bak", "Exposed PHP config backup", "high", _text(r"<\?php[\s\S]{0,4000}(?:password|passwd|secret)", reject_html=False)),
    (".DS_Store", "Exposed .DS_Store", "low", _ds_store),
]


class ExposureModule(BaseModule):
    name = "exposure"
    category = "web"
    description = "Открытые .git/.env/бэкапы и служебные страницы с проверкой содержимого"
    options = {
        "url": {"default": "", "required": False, "description": "URL; иначе веб-порты сессии"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "threads": {"default": 8, "required": False, "description": "Параллельная проверка путей (1–64)"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        threads = max(1, min(64, int(self.get_option("threads"))))
        with WebClient(timeout=self.get_option("timeout"), verify=self.get_option("verify")) as client:
            bases = [url.split("?", 1)[0].rstrip("/") + "/"
                     for url in web_urls(service_view(self.session, self.get_option("ports")), self.get_option("url") or None)]
            tasks = [(base, check) for base in bases for check in CHECKS]

            def probe(task):
                base, (path, label, severity, validator) = task
                response = client.get(urljoin(base, path))
                status = response.history[0].status_code if response.history else response.status_code
                if status == 200 and validator(response):
                    return label, severity, path, str(response.url)
                return None

            for task, result, error in threaded_map(probe, tasks, threads):
                if error is not None:
                    continue  # недоступный путь — это норма, не шумим
                if not result:
                    continue
                label, severity, path, final = result
                rows.append((task[0], path, severity, final))
                self.session.add_finding(label, task[0], severity=severity, path=path, final_url=final, module=self.path)
                self.session.add_loot("url", final, task[0])
        renderer.print_table("Exposed files", ["Base", "Path", "Severity", "Final URL"], rows)
        renderer.print_info(f"Открытых артефактов: {len(rows)}")


Exposure = ExposureModule
