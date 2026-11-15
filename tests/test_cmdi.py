"""Проверки command injection: доказанное выполнение против простого отражения."""

import re
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

from core.session import Session
from modules.web.cmdi import CmdiModule
from utils.web import WebClient

EXEC = re.compile(r"echo ([a-z]{6})\$\(\((\d+)\*(\d+)\)\)([a-z]{6})")


def _evaluate(value: str) -> str:
    """Иммитирует уязвимую оболочку: выполняет только echo-арифметику."""
    match = EXEC.search(value)
    if not match:
        return value
    head, first, second, tail = match.group(1), int(match.group(2)), int(match.group(3)), match.group(4)
    return f"{head}{first * second}{tail}"


class CmdiTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")

    def run_module(self, handler, **options):
        module = CmdiModule(self.session)
        options.setdefault("time_based", False)
        for key, value in options.items():
            module.set_option(key, value)
        factory = lambda **kwargs: WebClient(**kwargs, transport=httpx.MockTransport(handler))
        with patch("modules.web.cmdi.WebClient", factory), patch("utils.renderer.print_table") as table:
            module.run()
        return table

    def stats(self):
        return self.session.params["scan_stats"]["cmdi"]

    def test_detects_execution_via_echoed_arithmetic(self):
        def handler(request):
            value = request.url.params.get("host", "")
            return httpx.Response(200, text=f"<pre>ping {_evaluate(value)}</pre>")
        self.run_module(handler, url="http://example.test/ping", param="host")
        self.assertEqual(len(self.session.findings), 1)
        finding = self.session.findings[0]
        self.assertEqual(finding["parameter"], "host")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["detection"], "command-exec")
        self.assertEqual(self.stats()["findings"], 1)

    def test_plain_reflection_is_not_flagged(self):
        def handler(request):
            # Отражает payload дословно, но НЕ выполняет его.
            return httpx.Response(200, text=f"<pre>{request.url.params.get('host', '')}</pre>")
        self.run_module(handler, url="http://example.test/ping", param="host")
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.stats()["findings"], 0)
        self.assertGreaterEqual(self.stats()["tested"], 1)

    def test_detects_execution_in_post_body(self):
        def handler(request):
            value = dict(parse_qs(request.content.decode())).get("cmd", [""])[0]
            return httpx.Response(200, text=f"<html>{_evaluate(value)}</html>")
        self.run_module(handler, url="http://example.test/run", param="cmd", method="POST")
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["method"], "POST")


if __name__ == "__main__":
    unittest.main()
