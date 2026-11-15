"""Проверки HTTP-обёртки и YAML-движка без внешней сети."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import yaml
from pydantic import ValidationError

from core.session import Session
from templates.runner import Matcher, Template, TemplateRequest, TemplateRunner, load_template, template_url
from utils.web import WebClient, WebRequestError, normalize_url, web_urls


class URLTests(unittest.TestCase):
    def test_ipv6_and_url_targets(self):
        self.assertEqual(normalize_url("::1"), "http://[::1]")
        self.assertEqual(normalize_url("[::1]:8080"), "http://[::1]:8080")
        self.assertEqual(normalize_url("example.test:8000/path?q=1"), "http://example.test:8000/path?q=1")
        self.assertEqual(normalize_url("https://example.test/a%2fb?q=1#fragment"), "https://example.test/a%2fb?q=1")

    def test_discovered_web_services(self):
        session = SimpleNamespace(target="::1", services={
            22: {"name": "ssh"}, 80: {"name": "http"},
            443: {"name": "https"}, 9443: {"name": "https-alt"},
        })
        self.assertEqual(web_urls(session), ["http://[::1]", "https://[::1]", "https://[::1]:9443"])
        self.assertEqual(web_urls(session, "http://localhost:7777/app"), ["http://localhost:7777/app"])

    def test_explicit_target_url_has_priority(self):
        session = SimpleNamespace(target="https://example.test:8443/app?id=1", services={80: {"name": "http"}})
        self.assertEqual(web_urls(session), ["https://example.test:8443/app?id=1"])
        session.target = "example.test:8080"
        self.assertEqual(web_urls(session), ["http://example.test:8080"])

    def test_invalid_targets_are_rejected(self):
        for target in ("", "ftp://host", "http://host:70000", "http://user:pass@host"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_url(target)


class WebClientTests(unittest.TestCase):
    def test_redirects_browser_headers_and_encoded_traversal(self):
        seen = []

        def handler(request):
            seen.append(request)
            if request.url.path == "/start":
                return httpx.Response(302, headers={"Location": "/final"})
            return httpx.Response(200, text="ok")

        with WebClient(transport=httpx.MockTransport(handler)) as client:
            response = client.get("http://ctf.test/start")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.history), 1)
            client.get("http://ctf.test/cgi-bin/.%2e/%2e%2e/etc/passwd")
        self.assertIn("Mozilla", seen[0].headers["user-agent"])
        self.assertEqual(seen[-1].url.raw_path, b"/cgi-bin/.%2e/%2e%2e/etc/passwd")

    def test_network_errors_retry(self):
        calls = []

        def handler(request):
            calls.append(request)
            if len(calls) == 1:
                raise httpx.ReadTimeout("fixture timeout", request=request)
            return httpx.Response(403, text="denied")

        with patch("utils.web.time.sleep") as sleep:
            with WebClient(retries=1, transport=httpx.MockTransport(handler)) as client:
                response = client.get("http://ctf.test")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(calls), 2)
        sleep.assert_called_once()

    def test_exhausted_timeout_is_wrapped(self):
        def handler(request):
            raise httpx.ConnectError("fixture failure", request=request)

        with WebClient(retries=0, transport=httpx.MockTransport(handler)) as client:
            with self.assertRaisesRegex(WebRequestError, "ConnectError"):
                client.get("http://ctf.test")

    def test_invalid_retry_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            WebClient(timeout=0)
        with self.assertRaises(ValueError):
            WebClient(retries=-1)


class TemplateValidationTests(unittest.TestCase):
    def response(self, status=200, body="root:x:0:0", headers=None):
        return httpx.Response(status, text=body, headers=headers, request=httpx.Request("GET", "http://ctf.test"))

    def test_word_status_and_regex_matchers(self):
        response = self.response(headers={"Server": "Apache/2.4.49"})
        self.assertTrue(Matcher(type="word", words=["root:x:0:0"]).matches(response))
        self.assertTrue(Matcher(type="status", status=[200]).matches(response))
        self.assertTrue(Matcher(type="regex", regex=[r"Apache/2\.4\.\d+"], part="header").matches(response))
        self.assertFalse(Matcher(type="word", words=["passwd", "root:x"], condition="and").matches(response))
        self.assertTrue(Matcher(type="word", words=["ROOT:X"], case_insensitive=True).matches(response))
        self.assertTrue(Matcher(type="word", words=["missing"], negative=True).matches(response))

    def test_request_matcher_and_prevents_status_false_positive(self):
        request = TemplateRequest.model_validate({
            "path": "/", "matchers-condition": "and",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["root:x"]}],
        })
        self.assertEqual(request.path, ["/"])
        self.assertTrue(request.matches(self.response(200)))
        self.assertFalse(request.matches(self.response(404)))

    def test_empty_matchers_and_external_paths_are_invalid(self):
        for data in (
            {"path": "/", "matchers": []},
            {"path": [], "matchers": [{"type": "status", "status": [200]}]},
            {"path": "https://other.test/", "matchers": [{"type": "status", "status": [200]}]},
            {"path": "//other.test/", "matchers": [{"type": "status", "status": [200]}]},
            {"path": "{{BaseURL}}@other.test/", "matchers": [{"type": "status", "status": [200]}]},
            {"path": "/", "matchers": [{"type": "word", "words": [""]}]},
            {"path": "/", "matchers": [{"type": "status", "status": []}]},
        ):
            with self.subTest(data=data), self.assertRaises(ValidationError):
                TemplateRequest.model_validate(data)

    def test_encoded_paths_are_preserved(self):
        path = "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"
        self.assertEqual(template_url("http://ctf.test/app", path), "http://ctf.test" + path)
        self.assertEqual(template_url("http://ctf.test/app", "{{BaseURL}}/check"), "http://ctf.test/app/check")
        self.assertEqual(template_url("http://ctf.test/app?q=1", "check"), "http://ctf.test/app/check")

    def test_invalid_regex_is_a_validation_error(self):
        with self.assertRaises(ValidationError):
            Matcher(type="regex", regex=["("])

    def test_yaml_load_is_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.yaml"
            path.write_text("!!python/object/apply:builtins.str ['unsafe']", encoding="utf-8")
            with self.assertRaises(yaml.YAMLError):
                load_template(path)

    def test_supplied_example_is_valid(self):
        path = Path(__file__).resolve().parents[1] / "templates/examples/apache-path-traversal.yaml"
        template = load_template(path)
        self.assertEqual(template.id, "cve-2021-41773")
        self.assertFalse(template.requests[0].matches(self.response(404)))
        self.assertTrue(template.requests[0].matches(self.response(200)))


class TemplateRunnerTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("http://ctf.test")

    def tearDown(self):
        self.session.reset()

    def test_valid_template_runs_after_invalid_template(self):
        seen = []

        def handler(request):
            seen.append(request.url.raw_path)
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")

        def client_factory(**kwargs):
            return WebClient(**kwargs, transport=httpx.MockTransport(handler))

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / "01-invalid.yaml").write_text("info: broken\n", encoding="utf-8")
            example = Path(__file__).resolve().parents[1] / "templates/examples/apache-path-traversal.yaml"
            (directory / "02-valid.yaml").write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            module = TemplateRunner(self.session)
            module.set_option("templates", str(directory))
            with patch("templates.runner.WebClient", side_effect=client_factory), \
                 patch("templates.runner.renderer.print_error"), \
                 patch("templates.runner.renderer.print_info"), \
                 patch("templates.runner.renderer.print_success"), \
                 patch("templates.runner.renderer.print_table"), \
                 self.assertLogs("squ2ak.templates.runner", level="ERROR"):
                module.run()
        self.assertEqual(seen, [b"/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"])
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["severity"], "high")
        self.assertEqual(self.session.loot[0]["type"], "finding")

    def test_request_failure_does_not_stop_other_paths(self):
        def handler(request):
            if request.url.path == "/bad":
                raise httpx.ConnectError("fixture failed", request=request)
            return httpx.Response(200, text="match")

        def client_factory(**kwargs):
            return WebClient(**kwargs, transport=httpx.MockTransport(handler))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.yaml"
            path.write_text(
                "id: fixture\ninfo:\n  name: Fixture\nrequests:\n"
                "  - path: ['/bad', '/good']\n"
                "    matchers:\n      - type: word\n        words: ['match']\n",
                encoding="utf-8",
            )
            module = TemplateRunner(self.session)
            module.set_option("templates", str(path))
            module.set_option("retries", 0)
            with patch("templates.runner.WebClient", side_effect=client_factory), \
                 patch("templates.runner.renderer.print_warn"), \
                 patch("templates.runner.renderer.print_info"), \
                 patch("templates.runner.renderer.print_success"), \
                 patch("templates.runner.renderer.print_table"), \
                 self.assertLogs("squ2ak.templates.runner", level="WARNING"):
                module.run()
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["source"], "http://ctf.test/good")

    def test_missing_template_path_fails_before_http(self):
        with tempfile.TemporaryDirectory() as directory:
            module = TemplateRunner(self.session)
            module.set_option("templates", str(Path(directory) / "missing"))
            with patch("templates.runner.WebClient") as client, \
                 self.assertRaises((FileNotFoundError, ValueError)):
                module.run()
            client.assert_not_called()

    def test_empty_template_directory_fails_before_http(self):
        with tempfile.TemporaryDirectory() as directory:
            module = TemplateRunner(self.session)
            module.set_option("templates", directory)
            with patch("templates.runner.WebClient") as client, self.assertRaises(ValueError):
                module.run()
            client.assert_not_called()

    def test_all_invalid_templates_fail_without_sending_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.yaml"
            path.write_text("info: broken\n", encoding="utf-8")
            module = TemplateRunner(self.session)
            module.set_option("templates", directory)
            with patch("templates.runner.WebClient") as client, \
                 patch("templates.runner.renderer.print_error"), \
                 self.assertLogs("squ2ak.templates.runner", level="ERROR"), \
                 self.assertRaises(ValueError):
                module.run()
            client.return_value.__enter__.return_value.request.assert_not_called()
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.session.loot, [])


if __name__ == "__main__":
    unittest.main()
