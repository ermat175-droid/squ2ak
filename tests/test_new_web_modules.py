"""Регрессии новых web-модулей: все запросы только через MockTransport."""

import base64
import hashlib
import hmac
import json
import re
import unittest
from unittest.mock import patch

import httpx

from core.session import Session
from utils.web import WebClient


def _b64(data):
    raw = data if isinstance(data, bytes) else json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class _Base(unittest.TestCase):
    module_cls = None
    module_path = ""

    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")

    def run_module(self, handler, **options):
        module = self.module_cls(self.session)
        for key, value in options.items():
            module.set_option(key, value)
        factory = lambda **kwargs: WebClient(**kwargs, transport=httpx.MockTransport(handler))
        with patch(f"{self.module_path}.WebClient", factory), patch("utils.renderer.print_table"):
            module.run()


class SecHeadersTests(_Base):
    from modules.web.secheaders import SecHeadersModule as module_cls
    module_path = "modules.web.secheaders"

    def test_missing_headers_and_version_leak_reported(self):
        def handler(request):
            return httpx.Response(200, text="ok", headers=[
                ("server", "nginx/1.18.0"), ("set-cookie", "sid=abc")])
        self.run_module(handler)
        titles = [f["header"] for f in self.session.findings]
        self.assertTrue(any("Content-Security-Policy" in t for t in titles))
        self.assertTrue(any("X-Content-Type-Options" in t for t in titles))
        self.assertTrue(any("clickjacking" in t for t in titles))
        self.assertTrue(any("Cookie sid" in t for t in titles))
        self.assertTrue(any("Утечка версии" in t for t in titles))

    def test_hardened_response_has_no_findings(self):
        def handler(request):
            return httpx.Response(200, text="ok", headers=[
                ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
                ("referrer-policy", "no-referrer"),
                ("permissions-policy", "geolocation=()"),
                ("set-cookie", "sid=abc; HttpOnly; Secure; SameSite=Lax"),
                ("server", "nginx")])
        self.run_module(handler)
        self.assertEqual(self.session.findings, [])


class CorsTests(_Base):
    from modules.web.cors import CorsModule as module_cls
    module_path = "modules.web.cors"

    def test_reflected_origin_with_credentials_is_high(self):
        def handler(request):
            origin = request.headers.get("origin", "")
            if origin == "https://squ2ak-evil.example":
                return httpx.Response(200, text="ok", headers=[
                    ("access-control-allow-origin", origin),
                    ("access-control-allow-credentials", "true")])
            return httpx.Response(200, text="ok")
        self.run_module(handler)
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["severity"], "high")

    def test_no_cors_headers_no_findings(self):
        self.run_module(lambda request: httpx.Response(200, text="ok"))
        self.assertEqual(self.session.findings, [])


class ExposureTests(_Base):
    from modules.web.exposure import ExposureModule as module_cls
    module_path = "modules.web.exposure"

    def test_git_head_detected_html_env_rejected(self):
        def handler(request):
            if request.url.path == "/.git/HEAD":
                return httpx.Response(200, text="ref: refs/heads/main\n")
            if request.url.path == "/.env":
                return httpx.Response(200, text="<html>Not found fallback</html>")
            return httpx.Response(404, text="nope")
        self.run_module(handler)
        labels = [f["title"] for f in self.session.findings]
        self.assertIn("Exposed .git/HEAD", labels)
        self.assertNotIn("Exposed .env", labels)

    def test_real_env_file_detected(self):
        def handler(request):
            if request.url.path == "/.env":
                return httpx.Response(200, text="APP_KEY=base64:secret\nDB_PASSWORD=hunter2\n")
            return httpx.Response(404, text="nope")
        self.run_module(handler)
        self.assertIn("Exposed .env", [f["title"] for f in self.session.findings])


class GraphqlTests(_Base):
    from modules.web.graphql import GraphqlModule as module_cls
    module_path = "modules.web.graphql"

    def test_introspection_enabled_is_high(self):
        def handler(request):
            if request.url.path == "/graphql":
                return httpx.Response(200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}})
            return httpx.Response(404, text="nope")
        self.run_module(handler)
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["severity"], "high")

    def test_errors_without_schema_is_info(self):
        def handler(request):
            if request.url.path == "/graphql":
                return httpx.Response(400, json={"errors": [{"message": "Must provide query string"}]})
            return httpx.Response(404, text="nope")
        self.run_module(handler)
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["severity"], "info")


class HttpMethodsTests(_Base):
    from modules.web.http_methods import HttpMethodsModule as module_cls
    module_path = "modules.web.http_methods"

    def test_risky_methods_and_trace_xst(self):
        def handler(request):
            if request.method == "OPTIONS":
                return httpx.Response(200, headers={"allow": "GET, POST, PUT, DELETE, TRACE"})
            if request.method == "TRACE":
                return httpx.Response(200, text=request.headers.get("x-squ2ak", ""))
            return httpx.Response(200, text="ok")
        self.run_module(handler)
        titles = [f["title"] for f in self.session.findings]
        self.assertTrue(any("Risky HTTP methods" in t for t in titles))
        self.assertTrue(any("Cross-Site Tracing" in t for t in titles))

    def test_safe_methods_no_findings(self):
        def handler(request):
            if request.method == "OPTIONS":
                return httpx.Response(200, headers={"allow": "GET, POST, HEAD, OPTIONS"})
            return httpx.Response(405, text="no")
        self.run_module(handler, test_trace=False)
        self.assertEqual(self.session.findings, [])


class OpenRedirectTests(_Base):
    from modules.web.open_redirect import OpenRedirectModule as module_cls
    module_path = "modules.web.open_redirect"

    def test_offsite_location_is_detected(self):
        def handler(request):
            value = request.url.params.get("next", "")
            if "squ2ak-evil.example" in value:
                return httpx.Response(302, headers={"location": value})
            return httpx.Response(200, text="home")
        self.run_module(handler, url="http://example.test/go", param="next")
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["severity"], "high")

    def test_internal_redirect_not_flagged(self):
        def handler(request):
            return httpx.Response(302, headers={"location": "/dashboard"})
        self.run_module(handler, url="http://example.test/go", param="next")
        self.assertEqual(self.session.findings, [])


class SstiTests(_Base):
    from modules.web.ssti import SstiModule as module_cls
    module_path = "modules.web.ssti"

    def test_evaluated_template_is_detected(self):
        template = re.compile(r"([a-z]{6})\{\{(\d+)\*(\d+)\}\}([a-z]{6})")
        def handler(request):
            value = request.url.params.get("name", "")
            rendered = template.sub(lambda m: m.group(1) + str(int(m.group(2)) * int(m.group(3))) + m.group(4), value)
            return httpx.Response(200, text=f"<h1>Hello {rendered}</h1>")
        self.run_module(handler, url="http://example.test/hello", param="name")
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["severity"], "critical")
        self.assertEqual(self.session.findings[0]["engine"], "jinja2/twig")

    def test_plain_reflection_is_not_flagged(self):
        def handler(request):
            return httpx.Response(200, text=f"<h1>{request.url.params.get('name', '')}</h1>")
        self.run_module(handler, url="http://example.test/hello", param="name")
        self.assertEqual(self.session.findings, [])


class JwtTests(_Base):
    from modules.web.jwt import JwtModule as module_cls
    module_path = "modules.web.jwt"

    def test_alg_none_is_high(self):
        token = _b64({"alg": "none", "typ": "JWT"}) + "." + _b64({"user": "admin"}) + "."
        self.run_module(lambda request: httpx.Response(404), token=token)
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["severity"], "high")
        self.assertIn("alg=none", self.session.findings[0]["note"])

    def test_weak_hmac_secret_is_cracked(self):
        head, payload = _b64({"alg": "HS256", "typ": "JWT"}), _b64({"user": "admin"})
        signature = base64.urlsafe_b64encode(
            hmac.new(b"secret", f"{head}.{payload}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        token = f"{head}.{payload}.{signature}"
        self.run_module(lambda request: httpx.Response(404), token=token)
        high = [f for f in self.session.findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1)
        self.assertIn("secret", high[0]["note"])

    def test_strong_secret_is_only_info(self):
        head, payload = _b64({"alg": "HS256", "typ": "JWT"}), _b64({"user": "admin"})
        signature = base64.urlsafe_b64encode(
            hmac.new(b"Zx9!unguessable-long-key", f"{head}.{payload}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        token = f"{head}.{payload}.{signature}"
        self.run_module(lambda request: httpx.Response(404), token=token)
        self.assertTrue(all(f["severity"] == "info" for f in self.session.findings))

    def test_token_harvested_from_set_cookie(self):
        token = _b64({"alg": "none"}) + "." + _b64({"u": 1}) + "."
        def handler(request):
            return httpx.Response(200, text="ok", headers=[("set-cookie", f"session={token}; Path=/")])
        self.run_module(handler, url="http://example.test/")
        self.assertTrue(any(f["severity"] == "high" for f in self.session.findings))


if __name__ == "__main__":
    unittest.main()
