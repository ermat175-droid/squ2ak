"""Краулер и кодирование payload проверяются без сетевых соединений."""

import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl

import httpx

from core.session import Session
from utils.crawl import Candidate, collect_candidates
from utils.web import WebClient


class CrawlTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")

    def client(self, handler):
        return WebClient(transport=httpx.MockTransport(handler), retries=0)

    def test_explicit_parameter_preserves_query_and_skips_crawl(self):
        with self.client(lambda request: self.fail("Explicit parameter must not crawl")) as client:
            candidates = collect_candidates(
                self.session, client, url="http://example.test/search?lang=ru", param="q"
            )
        self.assertEqual(candidates[0].params, [("lang", "ru"), ("q", "test")])
        self.assertEqual(candidates[0].source, "parameter")

    def test_explicit_duplicate_parameter_keeps_existing_values(self):
        with self.client(lambda request: self.fail("No discovery request expected")) as client:
            candidates = collect_candidates(
                self.session, client, url="http://example.test/?q=a&q=b", param="q"
            )
        self.assertEqual(candidates[0].params, [("q", "a"), ("q", "b")])

    def test_get_send_replaces_only_requested_occurrence(self):
        requests = []
        with self.client(lambda request: requests.append(request) or httpx.Response(200)) as client:
            candidate = Candidate("http://example.test/?id=1&id=2&next=a%26b#fragment")
            candidate.send(client, 1, "' OR 1=1--")
        self.assertEqual(
            list(requests[0].url.params.multi_items()),
            [("id", "1"), ("id", "' OR 1=1--"), ("next", "a&b")],
        )
        self.assertNotIn("#", str(requests[0].url))

    def test_post_send_urlencodes_duplicate_fields_and_keeps_query(self):
        requests = []
        with self.client(lambda request: requests.append(request) or httpx.Response(200)) as client:
            candidate = Candidate(
                "http://example.test/search?source=form", "POST", [("q", "first"), ("q", "second")]
            )
            candidate.send(client, 1, "'&next=x")
        request = requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url.query, b"source=form")
        self.assertEqual(parse_qsl(request.content.decode()), [("q", "first"), ("q", "'&next=x")])
        self.assertEqual(request.headers["content-type"], "application/x-www-form-urlencoded")

    def test_links_are_observed_same_origin_and_deduplicated(self):
        requested = []
        def handler(request):
            requested.append(str(request.url))
            return httpx.Response(200, text='''
                <a href="/item?id=1#one">item</a><a href="/item?id=1#two">repeat</a>
                <a href="https://outside.test/?id=2">outside</a>
                <a href="javascript:alert(1)">script</a>
                <a href="http://user:pass@example.test/?id=3">credentials</a>
            ''')
        with self.client(handler) as client:
            candidates = collect_candidates(self.session, client, max_depth=0)
        self.assertEqual([candidate.url for candidate in candidates], ["http://example.test/item?id=1"])
        self.assertEqual(requested, ["http://example.test/"])

    def test_get_form_merges_action_query_and_controls(self):
        def handler(request):
            return httpx.Response(200, text='''
                <form action="/search?lang=ru" method="get">
                  <input name="q" value="one"><input name="q" value="two">
                  <input type="hidden" name="token" value="xyz">
                  <input type="checkbox" name="flag" checked>
                  <input type="checkbox" name="unchecked">
                  <input type="password" name="password" value="private">
                  <input type="file" name="upload"><input type="submit" name="submit">
                  <input name="disabled" disabled>
                  <textarea name="note">hello</textarea>
                  <select name="kind"><option value="a">A</option><option selected value="b">B</option></select>
                </form>
            ''')
        with self.client(handler) as client:
            candidates = collect_candidates(self.session, client, max_depth=0)
        self.assertEqual(candidates[0].params, [
            ("lang", "ru"), ("q", "one"), ("q", "two"), ("token", "xyz"),
            ("flag", "on"), ("password", ""), ("note", "hello"), ("kind", "b"),
        ])
        self.assertEqual(candidates[0].method, "GET")
        self.assertEqual(candidates[0].source, "form")

    def test_post_form_preserves_action_query_and_multiple_selection(self):
        def handler(request):
            return httpx.Response(200, text='''
                <form action="/read?lang=ru" method="post">
                  <input name="file" value="index.html">
                  <input type="password" name="password" value="do-not-copy">
                  <select multiple name="kind"><option selected value="a">A</option>
                    <option selected value="b">B</option><option disabled selected value="c">C</option></select>
                </form>
                <form action="https://outside.test/post" method="post"><input name="file"></form>
            ''')
        with self.client(handler) as client:
            candidates = collect_candidates(self.session, client, max_depth=0)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].url, "http://example.test/read?lang=ru")
        self.assertEqual(candidates[0].method, "POST")
        self.assertEqual(candidates[0].params, [("file", "index.html"), ("password", ""),
                                              ("kind", "a"), ("kind", "b")])

    def test_password_only_get_and_post_forms_remain_candidates_with_empty_values(self):
        for method in ("get", "post"):
            with self.subTest(method=method):
                page = (
                    f'<form action="/login" method="{method}">'
                    '<input type="password" name="password" value="must-not-use">'
                    '<input type="password" name="disabled_password" value="secret" disabled>'
                    '<input type="submit" name="submit" value="Login"></form>'
                )
                with self.client(lambda request: httpx.Response(200, text=page)) as client:
                    candidates = collect_candidates(self.session, client, max_depth=0)
                self.assertEqual(len(candidates), 1)
                self.assertEqual(candidates[0].method, method.upper())
                self.assertEqual(candidates[0].params, [("password", "")])
                self.assertNotIn("must-not-use", str(candidates[0]))
                self.assertNotIn("secret", str(candidates[0]))

    def test_crawl_depth_discovers_nested_forms(self):
        requested = []
        def handler(request):
            requested.append(request.url.path)
            if request.url.path == "/":
                return httpx.Response(200, text='<a href="/catalog">catalog</a>')
            return httpx.Response(200, text='<form action="/search"><input name="q" value=""></form>')
        with self.client(handler) as client:
            candidates = collect_candidates(self.session, client, max_depth=1)
        self.assertEqual(requested, ["/", "/catalog"])
        self.assertEqual(candidates[0].url, "http://example.test/search?q=")

    def test_request_limit_bounds_pages_even_without_candidates(self):
        requested = []
        def handler(request):
            requested.append(request.url.path)
            return httpx.Response(200, text="".join(f'<a href="/page/{index}">page</a>' for index in range(20)))
        with self.client(handler) as client:
            candidates = collect_candidates(self.session, client, max_urls=3, max_depth=2)
        self.assertEqual(candidates, [])
        self.assertEqual(len(requested), 3)

    def test_candidate_limit_bounds_discovery(self):
        def handler(request):
            return httpx.Response(200, text="".join(f'<a href="/search?q={index}">query</a>' for index in range(20)))
        with self.client(handler) as client:
            candidates = collect_candidates(self.session, client, max_urls=3)
        self.assertEqual(len(candidates), 3)

    def test_discovered_urls_are_seeded_and_external_loot_is_ignored(self):
        self.session.params["urls"] = ["http://example.test/item?id=1", "https://outside.test/?id=9"]
        self.session.add_loot("url", "http://example.test/view?file=readme", "dirb")
        self.session.add_loot("url", "https://outside.test/?file=secret", "dirb")
        with self.client(lambda request: self.fail("crawl=false must not request")) as client:
            candidates = collect_candidates(self.session, client, crawl=False)
        self.assertEqual([candidate.url for candidate in candidates], [
            "http://example.test/item?id=1", "http://example.test/view?file=readme",
        ])

    def test_lfi_filter_keeps_baseline_fields(self):
        self.session.params["urls"] = [
            "http://example.test/item?id=1", "http://example.test/view?file=readme&lang=ru"
        ]
        with self.client(lambda request: self.fail("No discovery expected")) as client:
            candidates = collect_candidates(self.session, client, crawl=False, lfi_names={"FILE"})
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].params, [("file", "readme"), ("lang", "ru")])

    def test_cross_origin_redirect_is_not_followed(self):
        requested = []
        def handler(request):
            requested.append(str(request.url))
            return httpx.Response(302, headers={"location": "http://outside.test/?q=secret"})
        with self.client(handler) as client:
            candidates = collect_candidates(self.session, client)
        self.assertEqual(requested, ["http://example.test/"])
        self.assertEqual(candidates, [])

    def test_same_origin_redirect_is_followed_within_budget(self):
        requested = []
        def handler(request):
            requested.append(request.url.path)
            if request.url.path == "/":
                return httpx.Response(301, headers={"location": "/home"})
            return httpx.Response(200, text='<a href="/item?id=1">item</a>')
        with self.client(handler) as client:
            candidates = collect_candidates(self.session, client, max_depth=0)
        self.assertEqual(requested, ["/", "/home"])
        self.assertEqual(len(candidates), 1)

    def test_network_error_does_not_stop_other_seeds(self):
        self.session.params["urls"] = ["http://example.test/catalog"]
        def handler(request):
            if request.url.path == "/":
                raise httpx.ConnectError("unavailable", request=request)
            return httpx.Response(200, text='<a href="/view?file=readme">file</a>')
        with self.client(handler) as client, patch("utils.renderer.print_warn") as warning:
            candidates = collect_candidates(self.session, client, max_depth=0)
        self.assertEqual(len(candidates), 1)
        warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
