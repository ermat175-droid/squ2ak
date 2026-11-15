"""Разрешённые HTTP-методы (OPTIONS/Allow) и активная проверка TRACE (XST)."""

import secrets

from core.module_base import BaseModule
from utils import renderer
from utils.web import WebClient, WebRequestError, service_view, web_urls

RISKY = {"PUT": "medium", "DELETE": "medium", "PATCH": "low",
         "TRACE": "low", "CONNECT": "low"}


class HttpMethodsModule(BaseModule):
    name = "http_methods"
    category = "web"
    description = "Опасные HTTP-методы по OPTIONS и проверка TRACE (XST)"
    options = {
        "url": {"default": "", "required": False, "description": "URL; иначе веб-порты сессии"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "test_trace": {"default": True, "required": False, "description": "Активно проверять отражение TRACE (XST)"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        with WebClient(timeout=self.get_option("timeout"), verify=self.get_option("verify")) as client:
            for url in web_urls(service_view(self.session, self.get_option("ports")), self.get_option("url") or None):
                target = url if url.count("/") > 2 else url.rstrip("/") + "/"
                try:
                    response = client.request("OPTIONS", target)
                except WebRequestError as exc:
                    renderer.print_warn(str(exc))
                    continue
                allow = response.headers.get("allow", "")
                methods = sorted({method.strip().upper() for method in allow.split(",") if method.strip()})
                risky = [method for method in methods if method in RISKY]
                if risky:
                    severity = max((RISKY[method] for method in risky), key=lambda value: {"low": 1, "medium": 2}[value])
                    rows.append((str(response.url), ", ".join(methods), severity, "risky methods: " + ", ".join(risky)))
                    self.session.add_finding(f"Risky HTTP methods: {', '.join(risky)}", str(response.url),
                                             severity=severity, methods=methods, module=self.path)
                if self.get_option("test_trace"):
                    xst = self._trace_reflects(client, target)
                    if xst:
                        rows.append((str(response.url), "TRACE", "medium", "TRACE reflects request (XST)"))
                        self.session.add_finding("Cross-Site Tracing (TRACE enabled)", str(response.url),
                                                 severity="medium", evidence=xst, module=self.path)
        renderer.print_table("HTTP methods", ["URL", "Allowed", "Severity", "Detail"], rows)
        renderer.print_info(f"Находок по методам: {len(rows)}")

    def _trace_reflects(self, client, target):
        token = "squ2ak-" + secrets.token_hex(6)
        try:
            response = client.request("TRACE", target, headers={"X-Squ2ak": token})
        except WebRequestError:
            return None
        if response.status_code == 200 and token in response.text:
            return f"echoed header token in TRACE response ({token})"
        return None


HttpMethods = HttpMethodsModule
