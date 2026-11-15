"""Отчёт по сессии: Markdown, JSON и запись файлов."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from core import report
from core.session import Session


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("10.0.0.5")
        self.session.add_service(80, "http", "nginx 1.18.0", "nginx")
        self.session.add_finding("Open redirect: next", "http://10.0.0.5/go", severity="high", parameter="next")
        self.session.add_finding("Security header: CSP отсутствует", "http://10.0.0.5/", severity="low")
        self.session.add_loot("url", "http://10.0.0.5/.git/HEAD", "web/exposure")

    def test_markdown_sorts_by_severity_and_lists_sections(self):
        markdown = report.render_markdown(self.session)
        self.assertIn("# squ2ak report — 10.0.0.5", markdown)
        self.assertIn("high: 1", markdown)
        self.assertLess(markdown.index("Open redirect"), markdown.index("CSP отсутствует"))
        self.assertIn("## Services", markdown)
        self.assertIn(".git/HEAD", markdown)

    def test_json_has_counts_and_sorted_findings(self):
        data = json.loads(report.render_json(self.session))
        self.assertEqual(data["severity_counts"], {"high": 1, "low": 1})
        self.assertEqual(data["findings"][0]["severity"], "high")
        self.assertEqual(data["target"], "10.0.0.5")

    def test_write_report_both_formats(self):
        with TemporaryDirectory() as temporary:
            base = Path(temporary) / "out"
            written = report.write_report(self.session, base, "both")
            self.assertEqual({path.suffix for path in written}, {".md", ".json"})
            self.assertTrue((Path(temporary) / "out.md").exists())
            self.assertTrue((Path(temporary) / "out.json").exists())

    def test_dotted_basename_keeps_full_name(self):
        with TemporaryDirectory() as temporary:
            base = Path(temporary) / "report-10.1.2.3"
            written = report.write_report(self.session, base, "both")
            names = {path.name for path in written}
            self.assertEqual(names, {"report-10.1.2.3.md", "report-10.1.2.3.json"})

    def test_explicit_extension_not_duplicated(self):
        with TemporaryDirectory() as temporary:
            base = Path(temporary) / "out.md"
            written = report.write_report(self.session, base, "md")
            self.assertEqual(written[0].name, "out.md")

    def test_invalid_format_rejected(self):
        with self.assertRaises(ValueError):
            report.write_report(self.session, "x", "pdf")

    def test_empty_session_renders_without_error(self):
        self.session.reset()
        self.session.set_target("host")
        markdown = report.render_markdown(self.session)
        self.assertIn("_Находок нет._", markdown)


if __name__ == "__main__":
    unittest.main()
