"""Аудит заголовков безопасности HTTP-ответа.

Детерминированная проверка: отсутствие или слабость конкретного заголовка.
Severity намеренно невысокая (info/low) — это гигиена, а не эксплуатация.
"""

import re

from core.module_base import BaseModule
from utils import renderer
from utils.web import WebClient, WebRequestError, service_view, web_urls


class SecHeadersModule(BaseModule):
    name = "secheaders"
    category = "web"
    description = "Аудит заголовков безопасности (CSP, HSTS, cookies, утечки версий)"
    options = {
        "url": {"default": "", "required": False, "description": "URL; иначе веб-порты сессии"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        with WebClient(timeout=self.get_option("timeout"), verify=self.get_option("verify")) as client:
            for url in web_urls(service_view(self.session, self.get_option("ports")), self.get_option("url") or None):
                try:
                    response = client.get(url if url.count("/") > 2 else url.rstrip("/") + "/")
                except WebRequestError as exc:
                    renderer.print_warn(str(exc))
                    continue
                final = str(response.url)
                is_https = final.lower().startswith("https://")
                for name, severity, note in self._audit(response.headers, is_https):
                    rows.append((final, name, severity, note))
                    self.session.add_finding(f"Security header: {name}", final, severity=severity,
                                             header=name, note=note, module=self.path)
        renderer.print_table("Security headers", ["URL", "Issue", "Severity", "Detail"], rows)
        renderer.print_info(f"Проблем с заголовками: {len(rows)}")

    @staticmethod
    def _audit(headers, is_https):
        get = lambda key: headers.get(key, "")
        issues = []
        csp = get("content-security-policy")
        if not csp:
            issues.append(("Content-Security-Policy отсутствует", "low", "нет защиты от XSS/инъекций ресурсов"))
        if is_https and not get("strict-transport-security"):
            issues.append(("Strict-Transport-Security отсутствует", "low", "возможен downgrade на HTTP"))
        xcto = get("x-content-type-options").lower()
        if xcto != "nosniff":
            issues.append(("X-Content-Type-Options не nosniff", "low", f"значение: {xcto or 'нет'}"))
        if not get("x-frame-options") and "frame-ancestors" not in csp.lower():
            issues.append(("Защита от clickjacking отсутствует", "low", "нет X-Frame-Options и frame-ancestors"))
        if not get("referrer-policy"):
            issues.append(("Referrer-Policy отсутствует", "info", "referer может утекать на сторонние сайты"))
        if not get("permissions-policy"):
            issues.append(("Permissions-Policy отсутствует", "info", "браузерные возможности не ограничены"))
        for cookie in headers.get_list("set-cookie"):
            name = cookie.split("=", 1)[0].strip()
            flags = cookie.lower()
            missing = [flag for flag, present in (
                ("HttpOnly", "httponly" in flags), ("Secure", "secure" in flags),
                ("SameSite", "samesite" in flags)) if not present]
            if missing:
                issues.append((f"Cookie {name} без {', '.join(missing)}", "low", "флаги защиты cookie не выставлены"))
        for leak in ("server", "x-powered-by", "x-aspnet-version"):
            value = get(leak)
            if value and re.search(r"\d", value):
                issues.append((f"Утечка версии в {leak}", "info", value[:80]))
        return issues


SecHeaders = SecHeadersModule
