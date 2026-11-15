"""Обнаружение GraphQL-эндпоинтов и включённой интроспекции схемы.

Включённая интроспекция (ответ с data.__schema) раскрывает всю модель API —
это находка. Эндпоинт, отвечающий GraphQL-ошибкой, но без схемы, фиксируется
как информационный факт.
"""

import json

from core.module_base import BaseModule
from utils import renderer
from utils.web import WebClient, WebRequestError, service_view, web_urls

ENDPOINTS = ["graphql", "graphql/", "api/graphql", "v1/graphql", "query", "graphql/console", "graphiql"]
INTROSPECTION = {"query": "query{__schema{queryType{name}}}"}


class GraphqlModule(BaseModule):
    name = "graphql"
    category = "web"
    description = "GraphQL endpoint и интроспекция схемы"
    options = {
        "url": {"default": "", "required": False, "description": "URL; иначе веб-порты сессии"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        seen = set()
        with WebClient(timeout=self.get_option("timeout"), verify=self.get_option("verify")) as client:
            bases = [url.split("?", 1)[0].rstrip("/") + "/"
                     for url in web_urls(service_view(self.session, self.get_option("ports")), self.get_option("url") or None)]
            for base in bases:
                for endpoint in ENDPOINTS:
                    target = base + endpoint
                    if target in seen:
                        continue
                    seen.add(target)
                    try:
                        response = client.request("POST", target, json=INTROSPECTION)
                    except WebRequestError as exc:
                        renderer.print_warn(str(exc))
                        continue
                    result = self._classify(response)
                    if not result:
                        continue
                    severity, note = result
                    rows.append((str(response.url), response.status_code, severity, note))
                    self.session.add_finding(f"GraphQL: {note}", str(response.url), severity=severity,
                                             endpoint=endpoint, status=response.status_code, module=self.path)
                    if severity != "info":
                        self.session.add_loot("url", str(response.url), self.path)
        renderer.print_table("GraphQL", ["URL", "Status", "Severity", "Note"], rows)
        renderer.print_info(f"GraphQL-эндпоинтов: {len(rows)}")

    @staticmethod
    def _classify(response):
        try:
            data = json.loads(response.text[:500_000])
        except (json.JSONDecodeError, ValueError):
            data = None
        if isinstance(data, dict) and isinstance(data.get("data"), dict) and "__schema" in data["data"]:
            return "high", "introspection enabled"
        if isinstance(data, dict) and "errors" in data:
            body = response.text.lower()
            if "__schema" in body or "graphql" in body or "must provide query" in body or "syntax error" in body:
                return "info", "endpoint present, introspection likely disabled"
        return None


Graphql = GraphqlModule
