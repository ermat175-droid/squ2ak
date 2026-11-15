"""Проверки dirb: redirects, статусы, soft 404 и безопасные словари."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx

from core.session import Session
from modules.web.dirb import DirbModule
from utils.web import WebClient


class DirbTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")

    def run_dirb(self, handler, words, **options):
        module = DirbModule(self.session)
        for name, value in options.items():
            module.set_option(name, value)
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "words.txt"
            path.write_text("\n".join(words) + "\n", encoding="utf-8")
            module.set_option("wordlist", str(path))
            def factory(**kwargs):
                return WebClient(**kwargs, transport=httpx.MockTransport(handler))
            with patch("modules.web.dirb.WebClient", factory), patch("utils.renderer.print_table") as table:
                module.run()
            return table.call_args.args[2]

    def test_ftp_redirect_includes_original_and_final_urls_in_loot(self):
        def handler(request):
            if request.url.path == "/ftp":
                return httpx.Response(301, headers={"Location": "/ftp/"})
            if request.url.path == "/ftp/":
                return httpx.Response(200, text="<title>Directory listing /ftp/</title><a href='backup.zip'>backup</a>")
            return httpx.Response(404, text="Not found")
        rows = self.run_dirb(handler, ["ftp", "ftp/"])
        redirected = next(row for row in rows if row[2] == "http://example.test/ftp")
        self.assertEqual(redirected[0], "301 → 200")
        self.assertEqual(redirected[3], "http://example.test/ftp/")
        self.assertEqual({item["value"] for item in self.session.loot}, {
            "http://example.test/ftp", "http://example.test/ftp/",
        })

    def test_default_statuses_include_created_empty_and_protected_paths(self):
        status_by_path = {"/created": 201, "/empty": 204, "/protected": 401, "/forbidden": 403}
        def handler(request):
            return httpx.Response(status_by_path.get(request.url.path, 404), text="response")
        rows = self.run_dirb(handler, [path[1:] for path in status_by_path])
        self.assertEqual({row[0] for row in rows}, {"201", "204", "401", "403"})
        self.assertEqual(len(self.session.findings), 4)

    def test_temporary_redirect_is_followed_and_recorded(self):
        def handler(request):
            if request.url.path == "/login":
                return httpx.Response(307, headers={"Location": "/signin"})
            if request.url.path == "/signin":
                return httpx.Response(200, text="Sign-in page")
            return httpx.Response(404, text="Not found")
        rows = self.run_dirb(handler, ["login"])
        self.assertEqual(rows[0][0], "307 → 200")
        self.assertEqual(rows[0][3], "http://example.test/signin")

    def test_show_all_displays_404_and_soft404_without_creating_findings(self):
        def handler(request):
            if request.url.path == "/absent":
                return httpx.Response(404, text="Not found")
            return httpx.Response(200, text="SPA fallback")
        rows = self.run_dirb(handler, ["absent", "fallback"], show_all_statuses=True)
        self.assertEqual({row[0] for row in rows}, {"200", "404"})
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.session.loot, [])

    def test_default_output_suppresses_404_and_soft404(self):
        def handler(request):
            if request.url.path == "/absent":
                return httpx.Response(404, text="Not found")
            return httpx.Response(200, text="SPA fallback")
        rows = self.run_dirb(handler, ["absent", "fallback"])
        self.assertEqual(rows, [])
        self.assertEqual(self.session.loot, [])

    def test_follow_redirects_can_be_disabled(self):
        requested = []
        def handler(request):
            requested.append(request.url.path)
            if request.url.path == "/ftp":
                return httpx.Response(301, headers={"Location": "/ftp/"})
            return httpx.Response(404, text="Not found")
        rows = self.run_dirb(handler, ["ftp"], follow_redirects=False)
        self.assertEqual(rows[0][0], "301")
        self.assertEqual(rows[0][3], "http://example.test/ftp")
        self.assertNotIn("/ftp/", requested)

    def test_ports_option_targets_requested_web_port(self):
        requested = []
        def handler(request):
            requested.append(request.url.port)
            return httpx.Response(200 if request.url.path == "/ftp/" else 404, text="Directory")
        rows = self.run_dirb(handler, ["ftp/"], ports="3000")
        self.assertTrue(all(port == 3000 for port in requested))
        self.assertEqual(rows[0][2], "http://example.test:3000/ftp/")
        self.assertEqual(self.session.services, {})

    def test_wordlist_preserves_slash_and_rejects_unsafe_paths(self):
        module = DirbModule(self.session)
        words = ["ftp", "ftp/", "/absolute", "//external.test/path", "../escape",
                 "dir/../../escape", "http://external.test/file", "mailto:test", "a?query=1",
                 "path#fragment", "..%2fescape", "%2e%2e/escape", "%252e%252e/escape",
                 "path\\escape", "a%00b", "safe/file.txt", ".env", ".git/HEAD", "ftp"]
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "words.txt"
            path.write_text("\n".join(words), encoding="utf-8")
            actual = module._read_words(path)
        self.assertEqual(actual, ["ftp", "ftp/", "safe/file.txt", ".env", ".git/HEAD"])

    def test_compound_extensions_are_supported_and_deduplicated(self):
        module = DirbModule(self.session)
        module.set_option("extensions", "bak,.old,zip,tar.gz,bak")
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "words.txt"
            path.write_text("backup\nbackup/\n", encoding="utf-8")
            actual = module._read_words(path)
        self.assertEqual(actual, ["backup", "backup.bak", "backup.old", "backup.zip", "backup.tar.gz", "backup/"])

    def test_unsafe_extensions_are_rejected(self):
        module = DirbModule(self.session)
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "words.txt"
            path.write_text("backup\n", encoding="utf-8")
            for extension in ("../old", "tar..gz", "php?file=x", "/zip", "..zip"):
                with self.subTest(extension=extension):
                    module.set_option("extensions", extension)
                    with self.assertRaises(ValueError):
                        module._read_words(path)

    def test_default_wordlist_has_meaningful_paths_and_backup_extensions(self):
        module = DirbModule(self.session)
        actual = module._read_words(module.project_dir / "wordlists/common.txt")
        self.assertGreaterEqual(len(actual), 450)
        self.assertEqual(len(actual), len(set(actual)))
        self.assertTrue({"ftp", "ftp/", "rest", "api", "robots.txt", "admin", ".env", ".git/HEAD"}.issubset(actual))
        for extension in (".bak", ".old", ".zip", ".tar.gz"):
            self.assertTrue(any(path.endswith(extension) for path in actual))

    def test_recursion_scans_discovered_directories(self):
        requested = []
        def handler(request):
            requested.append(request.url.path)
            if request.url.path == "/admin":
                return httpx.Response(301, headers={"Location": "/admin/"})
            if request.url.path == "/admin/":
                return httpx.Response(200, text="Admin index")
            if request.url.path == "/admin/secret":
                return httpx.Response(200, text="Top secret")
            return httpx.Response(404, text="Not found")
        rows = self.run_dirb(handler, ["admin", "secret"], recursion=True, recursion_depth=1)
        self.assertIn("/admin/secret", requested)
        self.assertTrue(any(row[2] == "http://example.test/admin/secret" for row in rows))
        self.assertIn("http://example.test/admin/secret", {item["value"] for item in self.session.loot})

    def test_recursion_disabled_by_default_leaves_children_unscanned(self):
        requested = []
        def handler(request):
            requested.append(request.url.path)
            if request.url.path == "/admin":
                return httpx.Response(301, headers={"Location": "/admin/"})
            if request.url.path == "/admin/":
                return httpx.Response(200, text="Admin index")
            return httpx.Response(404, text="Not found")
        self.run_dirb(handler, ["admin", "secret"])
        self.assertNotIn("/admin/secret", requested)

    def test_recursion_does_not_descend_into_protected_directories(self):
        requested = []
        def handler(request):
            requested.append(request.url.path)
            if request.url.path == "/private/":
                return httpx.Response(403, text="Forbidden")
            return httpx.Response(404, text="Not found")
        self.run_dirb(handler, ["private/", "secret"], recursion=True, recursion_depth=1)
        self.assertNotIn("/private/secret", requested)


if __name__ == "__main__":
    unittest.main()
