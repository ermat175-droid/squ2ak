"""Регрессии LFI: явные параметры, обход форм и признаки содержимого файлов."""

import base64
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl

import httpx

from core.session import Session
from modules.web.lfi import LFIModule
from utils.web import WebClient


PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


class LFIRegressionTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")

    def run_module(self, handler, **options):
        module = LFIModule(self.session)
        for key, value in options.items():
            module.set_option(key, value)
        factory = lambda **kwargs: WebClient(**kwargs, transport=httpx.MockTransport(handler))
        with patch("modules.web.lfi.WebClient", factory), patch("utils.renderer.print_table") as table:
            module.run()
        return table

    def stats(self):
        return self.session.params["scan_stats"]["lfi"]

    def test_base_url_and_explicit_file_parameter_need_no_ready_payload(self):
        observed = []
        def handler(request):
            value = request.url.params.get("file", "")
            observed.append(value)
            return httpx.Response(200, text=PASSWD if "etc/passwd" in value else "Ordinary file viewer")
        table = self.run_module(handler, url="http://example.test/ftp", param="file")
        self.assertEqual(observed[0], "test")
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["parameter"], "file")
        self.assertEqual(self.session.loot[0]["value"], "/etc/passwd")
        self.assertNotIn(PASSWD, str(self.session.snapshot()))
        self.assertEqual(self.stats(), {"candidates": 1, "tested": 1, "findings": 1})
        self.assertEqual(list(table.call_args.args[1]), ["URL", "Parameter", "Payload", "Detected"])

    def test_manual_parameter_overrides_suspicious_name_filter(self):
        def handler(request):
            value = request.url.params.get("asset", "")
            return httpx.Response(200, text=PASSWD if "etc/passwd" in value else "Ordinary asset response")
        self.run_module(handler, url="http://example.test/view", param="asset")
        self.assertEqual(self.session.findings[0]["parameter"], "asset")

    def test_expanded_suspicious_names_are_checked_but_id_is_skipped(self):
        names = ("file", "page", "path", "doc", "include", "view", "template", "load", "read")
        def handler(request):
            values = list(request.url.params.multi_items())
            return httpx.Response(200, text=PASSWD if any("etc/passwd" in value for _, value in values) else "Ordinary page")
        query = "&".join(f"{name}=index" for name in names) + "&id=1"
        self.run_module(handler, url="http://example.test/view?" + query, crawl=False)
        self.assertEqual({finding["parameter"] for finding in self.session.findings}, set(names))
        self.assertEqual(self.stats()["tested"], len(names))

    def test_wildcard_parameters_can_check_nonstandard_query_field(self):
        def handler(request):
            value = request.url.params.get("asset", "")
            return httpx.Response(200, text=PASSWD if "etc/passwd" in value else "Ordinary response")
        self.run_module(handler, url="http://example.test/view?asset=index", parameters="*", crawl=False)
        self.assertEqual(self.session.findings[0]["parameter"], "asset")

    def test_crawl_checks_get_link_and_post_form_with_other_fields_intact(self):
        observed = []
        page = (
            '<a href="/view?load=index">view</a>'
            '<a href="https://outside.test/view?file=index">outside</a>'
            '<form method="POST" action="/view">'
            '<input name="tag" value="a"><input name="tag" value="b">'
            '<input name="file" value="index"><input name="token" value="keep">'
            '</form>'
        )
        def handler(request):
            fields = list(request.url.params.multi_items()) if request.method == "GET" else parse_qsl(request.content.decode())
            observed.append((request.method, str(request.url), fields))
            if request.url.path == "/":
                return httpx.Response(200, text=page)
            body = PASSWD if any("etc/passwd" in value for _, value in fields) else "Ordinary viewer response"
            return httpx.Response(200, text=body)
        self.run_module(handler, url="http://example.test/", crawl=True)
        self.assertEqual({finding["parameter"] for finding in self.session.findings}, {"load", "file"})
        post_checks = [fields for method, _, fields in observed
                       if method == "POST" and "etc/passwd" in dict(fields).get("file", "")]
        self.assertTrue(post_checks)
        self.assertEqual([value for name, value in post_checks[0] if name == "tag"], ["a", "b"])
        self.assertIn(("token", "keep"), post_checks[0])
        self.assertTrue(all(httpx.URL(url).host == "example.test" for _, url, _ in observed))

    def test_win_ini_needs_only_one_actual_section_header(self):
        for section in ("fonts", "extensions"):
            with self.subTest(section=section):
                self.session.reset()
                self.session.set_target("example.test")
                def handler(request):
                    value = request.url.params.get("file", "")
                    body = f"[{section}]\nname=value\n" if "win.ini" in value.lower() else "Ordinary viewer response"
                    return httpx.Response(200, text=body)
                self.run_module(handler, url="http://example.test/view", param="file")
                self.assertEqual(self.session.loot[0]["value"], "win.ini")

    def test_php_filter_requires_decoded_php_source(self):
        encoded = base64.b64encode(b"<?php echo 'hello'; ?>\n").decode()
        def handler(request):
            value = request.url.params.get("file", "")
            return httpx.Response(200, text=encoded if value.startswith("php://filter/") else "Ordinary viewer response")
        self.run_module(handler, url="http://example.test/view", param="file")
        self.assertEqual(len(self.session.findings), 1)
        self.assertIn("php://filter", self.session.findings[0]["payload"])
        self.assertNotIn(encoded, str(self.session.snapshot()))

    def test_short_echo_php_tag_is_recognized_after_base64_decode(self):
        encoded = base64.b64encode(b"<?= getenv('APP_ENV'); ?>").decode()
        def handler(request):
            value = request.url.params.get("file", "")
            return httpx.Response(200, text=encoded if value.startswith("php://filter/") else "Ordinary response")
        self.run_module(handler, url="http://example.test/view", param="file")
        self.assertEqual(len(self.session.findings), 1)

    def test_generic_base64_and_reflected_paths_are_not_file_evidence(self):
        ordinary_base64 = base64.b64encode(b"This is ordinary encoded text, without executable PHP source.").decode()
        def handler(request):
            value = request.url.params.get("file", "")
            body = ordinary_base64 if value.startswith("php://filter/") else "Invalid file: " + value
            return httpx.Response(200, text=body)
        self.run_module(handler, url="http://example.test/view", param="file")
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.stats()["findings"], 0)

    def test_existing_passwd_and_nonzero_root_uid_do_not_confirm_lfi(self):
        for body in (PASSWD, "root:x:1000:1000:user:/home/user:/bin/bash\n"):
            with self.subTest(body=body):
                self.session.reset()
                self.session.set_target("example.test")
                def handler(request):
                    return httpx.Response(200, text=body)
                self.run_module(handler, url="http://example.test/view", param="file")
                self.assertEqual(self.session.findings, [])

    def test_proc_environ_marker_does_not_store_environment_values(self):
        environ = "USER=www-data\x00HOME=/var/www\x00PATH=/usr/bin:/bin\x00SECRET=do-not-store\x00"
        def handler(request):
            value = request.url.params.get("file", "")
            return httpx.Response(200, text=environ if value == "/proc/self/environ" else "Ordinary file viewer")
        self.run_module(handler, url="http://example.test/view", param="file")
        self.assertEqual(self.session.loot[0]["value"], "/proc/self/environ")
        self.assertNotIn("SECRET=do-not-store", str(self.session.snapshot()))

    def test_default_payloads_include_the_requested_formats(self):
        observed = []
        def handler(request):
            observed.append(request.url.params.get("file", ""))
            return httpx.Response(200, text="Ordinary viewer response without file contents")
        self.run_module(handler, url="http://example.test/view", param="file")
        for payload in (
            "../../../../etc/passwd", "....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/proc/self/environ", "....\\....\\....\\windows\\win.ini",
        ):
            self.assertIn(payload, observed)

    def test_custom_payload_file_replaces_defaults(self):
        observed = []
        def handler(request):
            value = request.url.params.get("file", "")
            observed.append(value)
            return httpx.Response(200, text=PASSWD if value == "CUSTOM_FILE_CANARY" else "Ordinary viewer response")
        with TemporaryDirectory() as temporary:
            payloads = Path(temporary) / "payloads.txt"
            payloads.write_text("# Свой индикатор\nCUSTOM_FILE_CANARY\n", encoding="utf-8")
            self.run_module(handler, url="http://example.test/view", param="file", payloads_file=str(payloads))
        self.assertEqual(observed, ["test", "CUSTOM_FILE_CANARY"])
        self.assertEqual(len(self.session.findings), 1)

    def test_no_candidates_reports_empty_findings_and_zero_stats(self):
        def handler(request):
            return httpx.Response(200, text="<app-root></app-root>")
        table = self.run_module(handler, url="http://example.test/", crawl=True)
        self.assertEqual(self.stats(), {"candidates": 0, "tested": 0, "findings": 0})
        self.assertEqual(list(table.call_args.args[2]), [])


if __name__ == "__main__":
    unittest.main()
