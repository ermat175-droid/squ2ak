"""Регрессии SQLi: параметры, HTML-формы и проверяемые признаки ответа."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl

import httpx

from core.session import Session
from modules.web.sqli import SQLiModule
from utils.web import WebClient


class SQLiRegressionTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")

    def run_module(self, handler, **options):
        module = SQLiModule(self.session)
        for key, value in options.items():
            module.set_option(key, value)
        factory = lambda **kwargs: WebClient(**kwargs, transport=httpx.MockTransport(handler))
        with patch("modules.web.sqli.WebClient", factory), patch("utils.renderer.print_table") as table:
            module.run()
        return table

    def stats(self):
        return self.session.params["scan_stats"]["sqli"]

    def test_explicit_parameter_adds_query_and_detects_sqlite_error(self):
        observed = []
        def handler(request):
            observed.append(request.url.params.get("q", ""))
            value = request.url.params.get("q", "")
            if "'" in value:
                return httpx.Response(500, text="SQLITE_ERROR: near unexpected quote: syntax error")
            return httpx.Response(200, text='{"data":[{"id":1,"name":"Normal product"}]}')
        table = self.run_module(
            handler, url="http://example.test/rest/products/search", param="q", boolean=False,
        )
        self.assertEqual(observed[0], "test")
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["parameter"], "q")
        self.assertIn("SQLITE_ERROR", self.session.findings[0]["evidence"])
        self.assertEqual(self.stats(), {"candidates": 1, "tested": 1, "findings": 1})
        self.assertEqual(list(table.call_args.args[1]), ["URL", "Parameter", "Method", "Payload", "Evidence"])

    def test_explicit_post_parameter_uses_body(self):
        observed = []
        def handler(request):
            observed.append((request.method, str(request.url), parse_qsl(request.content.decode())))
            value = dict(parse_qsl(request.content.decode())).get("q", "")
            if "'" in value:
                return httpx.Response(500, text="SQLITE_ERROR: unrecognized token")
            return httpx.Response(200, text="Ordinary search response without database errors")
        self.run_module(
            handler, url="http://example.test/search", param="q", method="POST", boolean=False,
        )
        self.assertTrue(observed)
        self.assertTrue(all(method == "POST" for method, _, _ in observed))
        self.assertEqual(observed[0][2], [("q", "test")])
        self.assertTrue(all(httpx.URL(url).query == b"" for _, url, _ in observed))
        self.assertEqual(len(self.session.findings), 1)

    def test_crawl_collects_get_link_and_post_form_preserving_duplicates(self):
        observed = []
        page = (
            '<a href="/item?id=1">item</a>'
            '<a href="https://outside.test/item?id=9">outside</a>'
            '<form method="POST" action="/search">'
            '<input name="tag" value="a"><input name="tag" value="b">'
            '<input name="q" value="test"><input name="csrf" value="token">'
            '</form>'
        )
        def handler(request):
            observed.append((request.method, str(request.url), parse_qsl(request.content.decode())))
            if request.url.path == "/":
                return httpx.Response(200, text=page)
            values = list(request.url.params.multi_items()) if request.method == "GET" else parse_qsl(request.content.decode())
            query = dict(values).get("q", "") or dict(values).get("id", "")
            if "'" in query:
                return httpx.Response(500, text="SQLITE_ERROR: near token: syntax error")
            return httpx.Response(200, text="Normal parameterized page with useful search results")
        self.run_module(handler, url="http://example.test/", crawl=True, boolean=False)
        self.assertTrue(any(method == "GET" and "/item?" in url for method, url, _ in observed))
        post_checks = [values for method, url, values in observed
                       if method == "POST" and httpx.URL(url).path == "/search"
                       and "'" in dict(values).get("q", "")]
        self.assertTrue(post_checks)
        self.assertEqual([value for name, value in post_checks[0] if name == "tag"], ["a", "b"])
        self.assertIn(("csrf", "token"), post_checks[0])
        self.assertTrue(all(httpx.URL(url).host == "example.test" for _, url, _ in observed))
        self.assertEqual({finding["parameter"] for finding in self.session.findings}, {"id", "q"})

    def test_custom_payload_file_replaces_default_error_payloads(self):
        observed = []
        def handler(request):
            value = request.url.params.get("q", "")
            observed.append(value)
            if "CUSTOM_SQLI_CANARY" in value:
                return httpx.Response(500, text="SQLITE_ERROR: near token: syntax error")
            return httpx.Response(200, text="Ordinary response without a database error")
        with TemporaryDirectory() as temporary:
            payloads = Path(temporary) / "payloads.txt"
            payloads.write_text("# Свой безопасный индикатор\nCUSTOM_SQLI_CANARY\n", encoding="utf-8")
            self.run_module(
                handler, url="http://example.test/search", param="q", payloads_file=str(payloads), boolean=False,
            )
        self.assertTrue(any("CUSTOM_SQLI_CANARY" in value for value in observed))
        self.assertFalse(any("'" in value or '"' in value for value in observed))
        self.assertEqual(len(self.session.findings), 1)

    def test_existing_sqlite_error_does_not_become_new_finding(self):
        def handler(request):
            return httpx.Response(500, text="SQLITE_ERROR: near token: syntax error")
        self.run_module(handler, url="http://example.test/search", param="q", boolean=False)
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.stats()["tested"], 1)
        self.assertEqual(self.stats()["findings"], 0)

    def test_http_500_without_sql_evidence_is_not_a_finding(self):
        def handler(request):
            if "'" in request.url.params.get("q", ""):
                return httpx.Response(500, text="Internal server error: temporary overload")
            return httpx.Response(200, text="A normal catalogue response without an error")
        self.run_module(handler, url="http://example.test/search", param="q", boolean=False)
        self.assertEqual(self.session.findings, [])

    def test_default_payloads_include_or_error_probe(self):
        observed = []
        def handler(request):
            value = request.url.params.get("q", "")
            observed.append(value)
            if "OR 1=1" in value:
                return httpx.Response(500, text="SQLITE_ERROR: incomplete input")
            return httpx.Response(200, text="Search returned an ordinary stable product list")
        self.run_module(handler, url="http://example.test/search", param="q", boolean=False)
        self.assertTrue(any("OR 1=1" in value for value in observed))
        self.assertEqual(len(self.session.findings), 1)

    def test_or_boolean_pair_can_differ_from_the_original_search(self):
        observed = []
        ordinary = '{"data":[{"id":1,"name":"One matching product"}]}'
        all_products = '{"data":[' + ",".join(f'{{"id":{index},"name":"Product {index}"}}' for index in range(20)) + "]}"
        no_products = '{"data":[],"status":"No matching products found"}'
        def handler(request):
            value = request.url.params.get("q", "")
            observed.append(value)
            body = all_products if "OR 1=1" in value else no_products if "OR 1=2" in value else ordinary
            return httpx.Response(200, text=body)
        self.run_module(handler, url="http://example.test/search", param="q", boolean=True)
        self.assertEqual(len(self.session.findings), 1)
        self.assertIn("boolean", self.session.findings[0]["title"].lower())
        self.assertGreaterEqual(sum("OR 1=1" in value for value in observed), 2)
        self.assertGreaterEqual(sum("OR 1=2" in value for value in observed), 2)

    def test_crawl_without_candidates_reports_zero_counts(self):
        def handler(request):
            return httpx.Response(200, text="<app-root></app-root>")
        table = self.run_module(handler, url="http://example.test/", crawl=True, boolean=False)
        self.assertEqual(self.stats(), {"candidates": 0, "tested": 0, "findings": 0})
        self.assertEqual(list(table.call_args.args[2]), [])

    def test_candidate_parameter_limit_is_respected(self):
        observed = []
        def handler(request):
            observed.append(list(request.url.params.multi_items()))
            return httpx.Response(200, text="An ordinary stable response with no SQL errors")
        self.run_module(
            handler, url="http://example.test/item?a=1&b=2&c=3", crawl=False,
            max_parameters=1, boolean=False,
        )
        self.assertEqual(self.stats()["tested"], 1)
        self.assertTrue(all(dict(values)["b"] == "2" and dict(values)["c"] == "3" for values in observed))

    def test_later_error_payload_runs_after_an_earlier_network_failure(self):
        observed = []

        def handler(request):
            value = request.url.params.get("q", "")
            observed.append(value)
            if value == "'":
                raise httpx.ReadTimeout("rejected first payload", request=request)
            if value == '"':
                return httpx.Response(500, text="SQLITE_ERROR: later payload exposes a syntax error")
            return httpx.Response(200, text="Ordinary baseline response without a database error")

        with patch("utils.web.time.sleep"), patch("utils.renderer.print_warn") as warning:
            self.run_module(handler, url="http://example.test/search", param="q", boolean=False)
        self.assertIn('"', observed)
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["payload"], '"')
        self.assertEqual(self.stats(), {"candidates": 1, "tested": 1, "findings": 1})
        warning.assert_called_once()

    def test_boolean_pair_continues_after_initial_or_confirmation_network_failure(self):
        for fail_after in (1, 2):
            with self.subTest(fail_after=fail_after):
                self.session.reset()
                self.session.set_target("example.test")
                first_pair_reads = 0
                observed = []
                ordinary = '{"data":[{"id":1,"name":"One matching product"}]}'
                all_products = '{"data":[' + ",".join(
                    f'{{"id":{index},"name":"Product {index}"}}' for index in range(20)
                ) + "]}"
                no_products = '{"data":[],"status":"No matching products found"}'

                def handler(request):
                    nonlocal first_pair_reads
                    value = request.url.params.get("q", "")
                    observed.append(value)
                    if value == "test' OR 1=1--":
                        first_pair_reads += 1
                        if first_pair_reads >= fail_after:
                            raise httpx.ReadTimeout("first boolean pair interrupted", request=request)
                    if value.startswith("test") and "OR 1=1" in value:
                        body = all_products
                    elif value.startswith("test") and "OR 1=2" in value:
                        body = no_products
                    else:
                        body = ordinary
                    return httpx.Response(200, text=body)

                with patch("utils.web.time.sleep"), patch("utils.renderer.print_warn") as warning:
                    self.run_module(handler, url="http://example.test/search", param="q", boolean=True)
                self.assertEqual(len(self.session.findings), 1)
                self.assertEqual(self.session.findings[0]["detection"], "boolean-based")
                self.assertEqual(self.session.findings[0]["payload"], "test')) OR 1=1--")
                self.assertGreaterEqual(observed.count("test')) OR 1=1--"), 2)
                self.assertGreaterEqual(observed.count("test')) OR 1=2--"), 2)
                warning.assert_called_once()

    def test_failed_repeated_baseline_skips_boolean_checks_without_raising(self):
        baseline_reads = 0
        observed = []

        def handler(request):
            nonlocal baseline_reads
            value = request.url.params.get("q", "")
            observed.append(value)
            if value == "test":
                baseline_reads += 1
                if baseline_reads > 1:
                    raise httpx.ReadTimeout("repeated baseline unavailable", request=request)
            return httpx.Response(200, text="Ordinary baseline response without database errors")

        with patch("utils.web.time.sleep"), patch("utils.renderer.print_warn") as warning:
            self.run_module(handler, url="http://example.test/search", param="q", boolean=True)
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.stats(), {"candidates": 1, "tested": 1, "findings": 0})
        self.assertFalse(any(value.startswith("test") and value != "test" for value in observed))
        warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
