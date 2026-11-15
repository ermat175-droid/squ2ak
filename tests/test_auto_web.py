"""Передача параметров auto, веб-сводка и изоляция статистики целей."""

import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx
from rich.console import Console
import yaml

from core.auto import AutoRunner
from core.module_base import BaseModule
from core.registry import ModuleRegistry
from core.session import Session
from utils import renderer
from utils.web import WebClient


class AutoOptionsModule(BaseModule):
    name = "auto_options"
    category = "test"
    description = "Фиксирует реально переданные параметры без сети"
    options = {
        "crawl": {"default": False, "required": False, "description": "Обход"},
        "max_urls": {"default": 10, "required": False, "description": "Лимит"},
    }

    def run(self):
        self.session.params.setdefault("observed", []).append({
            "crawl": self.get_option("crawl"), "max_urls": self.get_option("max_urls"),
        })


class AutoWebRegressionTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("example.test")
        self.addCleanup(self.session.reset)

    def registry(self):
        registry = ModuleRegistry()
        registry.register(AutoOptionsModule)
        return registry

    def capture_summary(self):
        output = io.StringIO()
        console = Console(file=output, width=160, force_terminal=False, markup=False)
        with patch.object(renderer, "console", console):
            renderer.print_summary(self.session)
        return output.getvalue()

    def test_auto_params_reach_module_and_options_have_precedence(self):
        self.session.params.update({"crawl": False, "max_urls": 99})
        pipeline = [{
            "module": "test/auto_options", "condition": "always",
            "auto_params": {"crawl": True, "max_urls": 7},
            "options": {"max_urls": 3},
        }]
        with patch.object(renderer, "print_info"), patch.object(renderer, "print_summary"):
            runner = AutoRunner(self.session, pipeline, "full", self.registry())
            runner.run()
        self.assertEqual(self.session.params["observed"], [{"crawl": True, "max_urls": 3}])
        self.assertEqual(runner.results[0]["status"], "completed")
        self.assertEqual(self.session.params["max_urls"], 99)
        self.assertIs(self.session.params["crawl"], False)
        self.assertEqual(pipeline[0]["auto_params"]["max_urls"], 7)

    def test_options_can_override_auto_crawl_boolean(self):
        pipeline = [{
            "module": "test/auto_options", "auto_params": {"crawl": True},
            "options": {"crawl": False},
        }]
        with patch.object(renderer, "print_info"), patch.object(renderer, "print_summary"):
            AutoRunner(self.session, pipeline, "full", self.registry()).run()
        self.assertIs(self.session.params["observed"][0]["crawl"], False)

    def test_invalid_auto_params_fail_before_any_stage_runs(self):
        for value in ([], "crawl=true", None, 42):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AutoRunner(self.session, [{"module": "test/auto_options", "auto_params": value}],
                           "full", self.registry())
        self.assertNotIn("observed", self.session.params)

    def test_default_config_enables_crawling_web_sqli_and_lfi_stages(self):
        config = yaml.safe_load((BaseModule.project_dir / "config.yaml").read_text(encoding="utf-8"))
        stages = {stage["module"]: stage for stage in config["auto_pipeline"]}
        for module in ("web/sqli", "web/lfi"):
            with self.subTest(module=module):
                self.assertEqual(stages[module]["condition"], "has_web")
                self.assertIs(stages[module]["auto_params"]["crawl"], True)
        names = [stage["module"] for stage in config["auto_pipeline"]]
        self.assertLess(names.index("web/dirb"), names.index("web/sqli"))
        self.assertLess(names.index("web/dirb"), names.index("web/lfi"))

    def test_summary_prints_empty_web_sections_and_actual_counters(self):
        self.session.params["scan_stats"] = {
            "sqli": {"candidates": 0, "tested": 0, "findings": 0},
            "lfi": {"candidates": 0, "tested": 0, "findings": 0},
        }
        output = self.capture_summary()
        self.assertIn("SQLi findings", output)
        self.assertIn("LFI findings", output)
        self.assertGreaterEqual(output.count("Кандидатов: 0"), 2)
        self.assertGreaterEqual(output.count("проверено: 0"), 2)
        self.assertGreaterEqual(output.count("уязвимостей: 0"), 2)

    def test_summary_includes_positive_web_evidence_and_filters_other_modules(self):
        self.session.params["scan_stats"] = {
            "sqli": {"candidates": 2, "tested": 2, "findings": 1},
            "lfi": {"candidates": 1, "tested": 1, "findings": 1},
        }
        self.session.add_finding(
            "Possible SQL injection", "http://example.test/search", module="web/sqli",
            parameter="q", method="GET", payload="' OR 1=1--", evidence="SQLITE_ERROR_MARKER",
        )
        self.session.add_finding(
            "Local file read", "http://example.test/view", module="web/lfi",
            parameter="file", payload="../../../../etc/passwd", detected="Linux passwd",
        )
        self.session.add_finding(
            "Technology fixture", "http://example.test/", module="web/tech",
            evidence="INCORRECT_EVIDENCE_MARKER",
        )
        output = self.capture_summary()
        self.assertIn("SQLi findings", output)
        self.assertIn("LFI findings", output)
        self.assertIn("SQLITE_ERROR_MARKER", output)
        self.assertIn("Linux passwd", output)
        self.assertIn("../../../../etc/passwd", output)
        self.assertIn("http://example.test/search", output)
        self.assertIn("Кандидатов: 2", output)
        self.assertNotIn("INCORRECT_EVIDENCE_MARKER", output)

    def test_switching_target_clears_web_stats_but_keeps_unrelated_globals(self):
        stats = {"sqli": {"candidates": 2, "tested": 2, "findings": 1}}
        self.session.params.update({"scan_stats": stats, "threads": 4, "crawl": True})
        self.session.set_target("example.test")
        self.assertIs(self.session.params["scan_stats"], stats)
        self.session.set_target("second.test")
        self.assertNotIn("scan_stats", self.session.params)
        self.assertEqual(self.session.params["threads"], 4)
        self.assertIs(self.session.params["crawl"], True)

    def test_dirb_loot_feeds_auto_sqli_and_lfi_via_real_registry(self):
        requested = []
        def handler(request):
            requested.append(str(request.url))
            if request.url.path == "/viewer":
                return httpx.Response(200, text='<a href="/item?id=1">item</a><a href="/read?file=index">file</a>')
            if request.url.path == "/item":
                value = request.url.params.get("id", "")
                return httpx.Response(500, text="SQLITE_ERROR: syntax error") if "'" in value else httpx.Response(200, text="Normal product page without SQL errors")
            if request.url.path == "/read":
                value = request.url.params.get("file", "")
                return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\n" if "etc/passwd" in value else "Ordinary viewer response")
            if request.url.path == "/":
                return httpx.Response(200, text="<app-root></app-root>")
            return httpx.Response(404, text="Not found")
        factory = lambda **kwargs: WebClient(**kwargs, transport=httpx.MockTransport(handler))
        self.session.add_service(80, "http")
        with TemporaryDirectory() as temporary:
            wordlist = Path(temporary) / "words.txt"
            wordlist.write_text("viewer\n", encoding="utf-8")
            pipeline = [
                {"module": "web/dirb", "condition": "has_web", "options": {"wordlist": str(wordlist), "threads": 1}},
                {"module": "web/sqli", "condition": "has_web", "auto_params": {"crawl": True}, "options": {"boolean": False}},
                {"module": "web/lfi", "condition": "has_web", "auto_params": {"crawl": True}},
            ]
            output = io.StringIO()
            with patch("modules.web.dirb.WebClient", factory), patch("modules.web.sqli.WebClient", factory), \
                 patch("modules.web.lfi.WebClient", factory), patch.object(renderer, "console", Console(file=output, width=160, force_terminal=False, markup=False)):
                runner = AutoRunner(self.session, pipeline, "full", ModuleRegistry().discover())
                runner.run()
        self.assertEqual([stage["status"] for stage in runner.results], ["completed"] * 3)
        self.assertTrue(any(item["type"] == "url" and item["value"] == "http://example.test/viewer" for item in self.session.loot))
        self.assertEqual(self.session.params["scan_stats"]["sqli"]["findings"], 1)
        self.assertEqual(self.session.params["scan_stats"]["lfi"]["findings"], 1)
        self.assertTrue(all(httpx.URL(url).host == "example.test" for url in requested))
        self.assertIn("SQLi findings", output.getvalue())
        self.assertIn("LFI findings", output.getvalue())


if __name__ == "__main__":
    unittest.main()
