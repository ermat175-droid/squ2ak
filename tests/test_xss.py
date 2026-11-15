"""Проверки reflected XSS: дословное отражение против экранирования и не-HTML."""

import html
import unittest
from unittest.mock import patch

import httpx

from core.session import Session
from modules.web.xss import XssModule
from utils.web import WebClient

HTML = {"content-type": "text/html; charset=utf-8"}


class XssTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")

    def run_module(self, handler, **options):
        module = XssModule(self.session)
        for key, value in options.items():
            module.set_option(key, value)
        factory = lambda **kwargs: WebClient(**kwargs, transport=httpx.MockTransport(handler))
        with patch("modules.web.xss.WebClient", factory), patch("utils.renderer.print_table") as table:
            module.run()
        return table

    def stats(self):
        return self.session.params["scan_stats"]["xss"]

    def test_detects_unencoded_reflection_in_html(self):
        def handler(request):
            value = request.url.params.get("q", "")
            return httpx.Response(200, text=f"<html><body>Results for {value}</body></html>", headers=HTML)
        self.run_module(handler, url="http://example.test/search", param="q")
        self.assertEqual(len(self.session.findings), 1)
        finding = self.session.findings[0]
        self.assertEqual(finding["parameter"], "q")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("onload=alert", finding["payload"])
        self.assertEqual(self.stats()["findings"], 1)

    def test_html_escaped_reflection_is_not_flagged(self):
        def handler(request):
            value = request.url.params.get("q", "")
            return httpx.Response(200, text=f"<html>{html.escape(value)}</html>", headers=HTML)
        self.run_module(handler, url="http://example.test/search", param="q")
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.stats()["findings"], 0)

    def test_reflection_in_non_html_response_is_not_flagged(self):
        def handler(request):
            value = request.url.params.get("q", "")
            return httpx.Response(200, text=value, headers={"content-type": "application/json"})
        self.run_module(handler, url="http://example.test/api", param="q")
        self.assertEqual(self.session.findings, [])

    def test_attribute_context_reflection_is_detected(self):
        def handler(request):
            value = request.url.params.get("q", "")
            return httpx.Response(200, text=f'<html><input value="{value}"></html>', headers=HTML)
        self.run_module(handler, url="http://example.test/search", param="q")
        self.assertEqual(len(self.session.findings), 1)
        self.assertIn(self.session.findings[0]["context"], {"double-quote-attr", "html-text"})


if __name__ == "__main__":
    unittest.main()
