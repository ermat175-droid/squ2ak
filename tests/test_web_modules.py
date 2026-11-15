"""HTTP-проверки используют только MockTransport, без внешних целей."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

from core.session import Session
from modules.web.dirb import DirbModule, _is_soft404
from modules.web.lfi import LFIModule
from modules.web.sqli import SQLiModule, boolean_evidence, candidate_urls, replace_parameter
from modules.web.tech import TechModule
from utils.web import WebClient


def response(body, status=200, url="http://example.test/"):
    return httpx.Response(status, text=body, request=httpx.Request("GET", url))


class WebModuleTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")

    def factory(self, handler):
        return lambda **kwargs: WebClient(**kwargs, transport=httpx.MockTransport(handler))

    def test_tech_detects_headers_and_generator_in_either_order(self):
        found = dict(TechModule.detect(
            {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.2.1"},
            '<meta content="WordPress 6.4.2" name="generator"><script src="/wp-content/a.js"></script>',
        ))
        self.assertEqual(found["nginx"], "1.18.0")
        self.assertEqual(found["PHP"], "8.2.1")
        self.assertEqual(found["WordPress"], "6.4.2")

    def test_tech_saves_version_and_findings(self):
        def handler(request):
            return httpx.Response(200, headers={"Server": "Apache/2.4.49"}, text="hello")
        with patch("modules.web.tech.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
            TechModule(self.session).run()
        self.assertEqual(self.session.services[80]["version"], "Apache 2.4.49")
        self.assertEqual(self.session.findings[0]["technology"], "Apache")

    def test_tech_prioritizes_application_headers(self):
        found = dict(TechModule.detect(
            {"X-Powered-By": "Express", "X-AspNet-Version": "4.0.30319"},
            "<app-root></app-root>",
        ))
        self.assertEqual(found["Express.js"], "")
        self.assertEqual(found["ASP.NET"], "4.0.30319")

    def test_tech_detects_express_session_cookie(self):
        found = dict(TechModule.detect(
            {"Set-Cookie": "connect.sid=s%3Aexample; Path=/; HttpOnly"}, "",
        ))
        self.assertIn("Express.js", found)

    def test_tech_detects_angular_asset_names_including_hashes(self):
        for suffix in ("", ".39e721c6a043"):
            with self.subTest(suffix=suffix):
                body = "".join(
                    f'<script src="/{name}{suffix}.js" type="module"></script>'
                    for name in ("runtime", "polyfills", "main")
                )
                self.assertIn("Angular", dict(TechModule.detect({}, body)))

    def test_tech_detects_named_framework_script_assets(self):
        for technology, asset in (
            ("Angular", "/vendor/angular/angular.min.js"),
            ("React", "/static/react.production.min.js"),
            ("Vue", "/js/vue.runtime.min.js"),
        ):
            with self.subTest(technology=technology):
                found = dict(TechModule.detect({}, f'<script src="{asset}"></script>'))
                self.assertIn(technology, found)

    def test_tech_reads_same_origin_bundle_and_collects_unique_findings(self):
        requested = []
        def handler(request):
            requested.append(str(request.url))
            if request.url.path == "/":
                return httpx.Response(
                    200, headers={"X-Powered-By": "Express"},
                    text='<script src="/bundle.js"></script><script src="https://outside.test/angular.js"></script>',
                )
            if request.url.path == "/bundle.js":
                return httpx.Response(
                    200, headers={"X-Powered-By": "Express", "Content-Type": "application/javascript"},
                    text='/* @angular/core */ export const bootstrap = true;',
                )
            return httpx.Response(404, text="not found")
        with patch("modules.web.tech.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
            TechModule(self.session).run()
        technologies = [item["technology"] for item in self.session.findings]
        self.assertIn("Angular", technologies)
        self.assertEqual(technologies.count("Express.js"), 1)
        self.assertIn("http://example.test/bundle.js", requested)
        self.assertTrue(all(url.startswith("http://example.test/") for url in requested))

    def test_tech_limits_number_of_bundle_requests(self):
        requested = []
        def handler(request):
            requested.append(request.url.path)
            if request.url.path == "/":
                return httpx.Response(200, text='<script src="/one.js"></script><script src="/two.js"></script>')
            return httpx.Response(200, headers={"Content-Type": "application/javascript"}, text="/* @angular/core */")
        module = TechModule(self.session)
        module.set_option("max_scripts", 1)
        with patch("modules.web.tech.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
            module.run()
        self.assertEqual(requested, ["/", "/one.js"])

    def test_tech_limits_analyzed_bundle_bytes(self):
        def handler(request):
            if request.url.path == "/":
                return httpx.Response(200, text='<script src="/bundle.js"></script>')
            return httpx.Response(
                200, headers={"Content-Type": "application/javascript"},
                text="x" * 2048 + "/* @angular/core */",
            )
        module = TechModule(self.session)
        module.set_option("max_script_bytes", 1024)
        with patch("modules.web.tech.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
            module.run()
        self.assertNotIn("Angular", [item["technology"] for item in self.session.findings])

    def test_dirb_excludes_soft404_and_saves_real_paths(self):
        requested = []
        def handler(request):
            requested.append(str(request.url))
            if request.url.path == "/admin":
                return httpx.Response(200, text="Administrative control panel")
            if request.url.path == "/private":
                return httpx.Response(403, text="Forbidden")
            if request.url.path == "/login":
                return httpx.Response(302, headers={"location": "/signin"})
            if request.url.path == "/signin":
                return httpx.Response(200, text="Sign in using username and password")
            return httpx.Response(200, text="No such path: " + request.url.path)
        with TemporaryDirectory() as temporary:
            wordlist = Path(temporary) / "words.txt"
            wordlist.write_text("admin\nprivate\nlogin\nmissing\nhttp://evil.test/a\n../escape\nmailto:evil\n", encoding="utf-8")
            module = DirbModule(self.session)
            module.set_option("wordlist", str(wordlist))
            with patch("modules.web.dirb.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
                module.run()
        self.assertEqual({item["value"] for item in self.session.loot}, {"http://example.test/admin", "http://example.test/private", "http://example.test/login", "http://example.test/signin"})
        self.assertTrue(all(url.startswith("http://example.test/") for url in requested))
        self.assertNotIn("http://example.test/escape", requested)

    def test_soft404_does_not_hide_different_status(self):
        self.assertFalse(_is_soft404(response("Forbidden", 403), [response("Forbidden", 200)]))

    def test_parameter_replacement_preserves_duplicates_and_other_values(self):
        result = replace_parameter("http://example.test/?id=1&id=2&next=a%26b#frag", 1, "' AND 1=1")
        self.assertEqual(parse_qs(httpx.URL(result).query.decode()), {"id": ["1", "' AND 1=1"], "next": ["a&b"]})
        self.assertNotIn("#", result)

    def test_candidate_urls_never_follow_external_links(self):
        def handler(request):
            return httpx.Response(200, text='<a href="/item?id=1">item</a><a href="https://outside.test/?id=2">outside</a>')
        with self.factory(handler)() as client:
            urls = candidate_urls(self.session, None, client, 10)
        self.assertEqual(urls, ["http://example.test/item?id=1"])

    def test_sqli_finds_new_database_error(self):
        def handler(request):
            value = request.url.params.get("id", "")
            if "'" in value:
                return httpx.Response(500, text="You have an error in your SQL syntax near unexpected quote")
            return httpx.Response(200, text="Product page with an ordinary description")
        module = SQLiModule(self.session)
        module.set_option("url", "http://example.test/item?id=1")
        module.set_option("boolean", False)
        with patch("modules.web.sqli.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
            module.run()
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.findings[0]["parameter"], "id")

    def test_sqli_existing_error_is_not_new_evidence(self):
        def handler(request):
            return httpx.Response(500, text="You have an error in your SQL syntax")
        module = SQLiModule(self.session)
        module.set_option("url", "http://example.test/item?id=1")
        module.set_option("boolean", False)
        with patch("modules.web.sqli.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
            module.run()
        self.assertEqual(self.session.findings, [])

    def test_boolean_requires_stable_baseline(self):
        ordinary = response("<html>Product page with full description and item details</html>")
        false = response("<html>No matching products are available</html>")
        self.assertTrue(boolean_evidence(ordinary, ordinary, ordinary, false))
        self.assertFalse(boolean_evidence(ordinary, false, ordinary, false))
        self.assertFalse(boolean_evidence(ordinary, ordinary, ordinary, ordinary))

    def test_sqli_repeated_boolean_pair(self):
        def handler(request):
            if "1=2" in request.url.params.get("id", ""):
                return httpx.Response(200, text="<html>No matching products are available</html>")
            return httpx.Response(200, text="<html>Product page with full description and item details</html>")
        module = SQLiModule(self.session)
        module.set_option("url", "http://example.test/item?id=1")
        with patch("modules.web.sqli.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
            module.run()
        self.assertEqual(self.session.findings[0]["parameter"], "id")
        self.assertIn("boolean-based", self.session.findings[0]["title"])

    def test_lfi_requires_file_contents(self):
        def handler(request):
            value = request.url.params.get("file", "")
            body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" if "etc/passwd" in value else "Welcome to the file viewer"
            return httpx.Response(200, text=body)
        module = LFIModule(self.session)
        module.set_option("url", "http://example.test/view?file=index.html")
        with patch("modules.web.lfi.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
            module.run()
        self.assertEqual(self.session.loot[0]["type"], "file")
        self.assertEqual(self.session.loot[0]["value"], "/etc/passwd")

    def test_lfi_ignores_reflected_filename_and_existing_file(self):
        for body in ("Invalid file /etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"):
            self.session.reset()
            self.session.set_target("example.test")
            module = LFIModule(self.session)
            module.set_option("url", "http://example.test/view?file=index.html")
            def handler(request):
                return httpx.Response(200, text=body)
            with patch("modules.web.lfi.WebClient", self.factory(handler)), patch("utils.renderer.print_table"):
                module.run()
            self.assertEqual(self.session.findings, [])


if __name__ == "__main__":
    unittest.main()
