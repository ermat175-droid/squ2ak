"""Небезопасная конфигурация CORS: отражение чужого Origin и доверие к нему.

Отправляет пробный кросс-доменный Origin и проверяет Access-Control-Allow-*.
Срабатывает только когда сервер действительно доверяет нашему Origin
(отражает его или возвращает null/*), поэтому ложных срабатываний почти нет.
"""

from core.module_base import BaseModule
from utils import renderer
from utils.web import WebClient, WebRequestError, service_view, web_urls

EVIL_ORIGIN = "https://squ2ak-evil.example"


class CorsModule(BaseModule):
    name = "cors"
    category = "web"
    description = "CORS misconfiguration: отражение Origin, null и credentials"
    options = {
        "url": {"default": "", "required": False, "description": "URL; иначе веб-порты сессии"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        with WebClient(timeout=self.get_option("timeout"), verify=self.get_option("verify")) as client:
            for url in web_urls(service_view(self.session, self.get_option("ports")), self.get_option("url") or None):
                target = url if url.count("/") > 2 else url.rstrip("/") + "/"
                for origin in (EVIL_ORIGIN, "null"):
                    try:
                        response = client.get(target, headers={"Origin": origin})
                    except WebRequestError as exc:
                        renderer.print_warn(str(exc))
                        continue
                    result = self._evaluate(response.headers, origin)
                    if not result:
                        continue
                    severity, note = result
                    allow = response.headers.get("access-control-allow-origin", "")
                    rows.append((str(response.url), origin, allow, severity, note))
                    self.session.add_finding(f"CORS misconfiguration ({note})", str(response.url), severity=severity,
                                             origin=origin, allow_origin=allow,
                                             allow_credentials=response.headers.get("access-control-allow-credentials", ""),
                                             module=self.path)
                    self.session.add_loot("finding", f"CORS: {note}", str(response.url))
        renderer.print_table("CORS findings", ["URL", "Sent Origin", "Allow-Origin", "Severity", "Issue"], rows)
        renderer.print_info(f"Проблем CORS: {len(rows)}")

    @staticmethod
    def _evaluate(headers, origin):
        allow = headers.get("access-control-allow-origin", "").strip()
        credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        if not allow:
            return None
        if allow == origin and origin == "null":
            return ("high" if credentials else "medium", "trusts Origin: null")
        if allow == origin:
            return ("high" if credentials else "medium", "reflects arbitrary Origin with credentials" if credentials else "reflects arbitrary Origin")
        if allow == "*" and origin != "null":
            # '*' с credentials браузер игнорирует, но это явная ошибка конфигурации.
            return ("medium", "wildcard with credentials flag") if credentials else ("low", "wildcard Access-Control-Allow-Origin")
        return None


Cors = CorsModule
