"""Полный цикл на локальных HTTP/TCP-серверах, без внешних запросов."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
import os
from pathlib import Path
import socket
import socketserver
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from rich.console import Console
import yaml

from core.session import Session
from modules.recon.banner import BannerModule
from modules.recon.portscan import PortScan
from modules.web.dirb import DirbModule
from modules.web.lfi import LFIModule
from modules.web.sqli import SQLiModule
from modules.web.tech import TechModule
from templates.runner import TemplateRunner
from utils import renderer


PROJECT = Path(__file__).resolve().parents[1]
PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
TRAVERSAL = "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"


class LabHTTPHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.server.observed.append(("HEAD", self.path))
        self._reply(200, "", head=True)

    def do_GET(self):
        self.server.observed.append(("GET", self.path))
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if self.path == TRAVERSAL:
            self._reply(200, PASSWD)
        elif parsed.path == "/":
            self._reply(200, '<html><meta name="generator" content="WordPress 6.4.2">'
                        '<a href="/item?id=1">Product</a><a href="/view?file=index.html">File</a></html>')
        elif parsed.path == "/admin":
            self._reply(200, "Administrator dashboard and system settings")
        elif parsed.path == "/private":
            self._reply(403, "Access is forbidden")
        elif parsed.path == "/redirect":
            self._reply(302, "", location="/admin")
        elif parsed.path == "/item":
            value = params.get("id", [""])[0]
            if "'" in value or '"' in value:
                self._reply(500, "You have an error in your SQL syntax near unexpected quote")
            elif "1=2" in value:
                self._reply(200, "No matching products are available")
            else:
                self._reply(200, "Product one: title, full description, price and ordering information")
        elif parsed.path == "/view":
            value = params.get("file", [""])[0]
            self._reply(200, PASSWD if "etc/passwd" in value else "Welcome to the ordinary file viewer")
        elif parsed.path == "/already":
            self._reply(200, PASSWD)
        elif parsed.path == "/reflected":
            self._reply(200, "Search input: " + parsed.query + " — no matching entry was found")
        else:
            # Мягкая 404 возвращает 200 и отражает путь в теле.
            self._reply(200, "No such path: " + parsed.path)

    def _reply(self, status, body, *, head=False, location=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if data and not head:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass


class SSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4\r\n")
        except OSError:
            pass


class LocalTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class LocalIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), LabHTTPHandler)
        cls.http.daemon_threads = True
        cls.http.observed = []
        cls.ssh = LocalTCPServer(("127.0.0.1", 0), SSHHandler)
        cls.http_thread = Thread(target=cls.http.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.ssh_thread = Thread(target=cls.ssh.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.http_thread.start()
        cls.ssh_thread.start()
        cls.web_port = cls.http.server_address[1]
        cls.ssh_port = cls.ssh.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.web_port}"

    @classmethod
    def tearDownClass(cls):
        for server in (cls.http, cls.ssh):
            server.shutdown()
            server.server_close()
        cls.http_thread.join(timeout=2)
        cls.ssh_thread.join(timeout=2)

    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("127.0.0.1")
        self.output = StringIO()
        self.console_patch = patch.object(renderer, "console", Console(file=self.output, width=160, markup=False))
        self.console_patch.start()

    def tearDown(self):
        self.console_patch.stop()

    def module(self, cls, **options):
        module = cls(self.session)
        module.set_option("timeout", 1)
        for name, value in options.items():
            module.set_option(name, value)
        self.assertTrue(module.validate(), self.output.getvalue())
        return module

    def cli(self, directory, *arguments, stdin=None):
        env = {**os.environ, "SQU2AK_HOME": str(Path(directory) / "state"),
               "PYTHONUNBUFFERED": "1", "COLUMNS": "160", "TERM": "dumb"}
        process = subprocess.run([str(PROJECT / "squ2ak"), *arguments], cwd=PROJECT,
                                 env=env, input=stdin, text=True, capture_output=True, timeout=30)
        logs = list((Path(directory) / "state/sessions").glob("*.log"))
        self.assertEqual(len(logs), 1, process.stderr)
        return process, logs[0].read_text(encoding="utf-8")

    def test_tcp_scan_finds_two_servers_and_excludes_closed_port(self):
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            closed_port = closed.getsockname()[1]
            module = self.module(PortScan, scan="connect", threads=4,
                                 ports=f"{self.web_port},{self.ssh_port},{closed_port}")
            module.run()
        self.assertEqual(set(self.session.services), {self.web_port, self.ssh_port})

    def test_banner_uses_head_and_reads_ssh_greeting(self):
        self.session.add_service(self.web_port, name="http")
        self.session.add_service(self.ssh_port)
        self.module(BannerModule).run()
        self.assertEqual(self.session.services[self.web_port]["version"], "nginx 1.18.0")
        self.assertEqual(self.session.services[self.ssh_port]["version"], "OpenSSH 8.2p1")
        self.assertIn(("HEAD", "/"), self.http.observed)

    def test_tech_and_directory_scan_keep_real_paths_only(self):
        self.module(TechModule, url=self.base).run()
        self.assertEqual(self.session.services[self.web_port]["version"], "nginx 1.18.0")
        self.assertTrue(any(item.get("technology") == "WordPress" for item in self.session.findings))
        with TemporaryDirectory() as directory:
            words = Path(directory) / "words.txt"
            words.write_text("admin\nprivate\nredirect\nmissing\n", encoding="utf-8")
            self.module(DirbModule, url=self.base, wordlist=str(words), threads=3).run()
        self.assertEqual({item["value"] for item in self.session.loot if item["type"] == "url"},
                         {self.base + "/admin", self.base + "/private", self.base + "/redirect"})

    def test_sqli_and_lfi_detect_local_lab_payloads(self):
        self.module(SQLiModule, url=self.base + "/item?id=1", boolean=False).run()
        self.module(LFIModule, url=self.base + "/view?file=index.html").run()
        self.assertTrue(any("SQL injection" in item["title"] for item in self.session.findings))
        self.assertTrue(any("Local file read" in item["title"] for item in self.session.findings))
        self.assertTrue(any(item["type"] == "file" and item["value"] == "/etc/passwd" for item in self.session.loot))

    def test_reflection_and_existing_file_are_not_findings(self):
        self.module(SQLiModule, url=self.base + "/reflected?id=1").run()
        self.module(LFIModule, url=self.base + "/reflected?file=index.html").run()
        self.module(LFIModule, url=self.base + "/already?file=index.html").run()
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.session.loot, [])

    def test_yaml_preserves_encoded_traversal_and_finds_match(self):
        self.module(TemplateRunner, url=self.base,
                    templates=str(PROJECT / "templates/examples/apache-path-traversal.yaml")).run()
        self.assertIn(("GET", TRAVERSAL), self.http.observed)
        self.assertTrue(any(item.get("template_id") == "cve-2021-41773" for item in self.session.findings))

    def test_launcher_one_shot_saves_commands_output_and_summary(self):
        with TemporaryDirectory() as directory:
            process, log = self.cli(directory, "--target", "127.0.0.1", "--module", "recon/portscan",
                                    "--ports", str(self.web_port), "--scan", "connect", "--timeout", "1")
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn(str(self.web_port), process.stdout)
            self.assertIn("SUMMARY", process.stdout)
            self.assertIn("CLI --target 127.0.0.1 --module recon/portscan", log)
            self.assertIn("Open TCP ports", log)
            self.assertIn("SUMMARY", log)

    def test_piped_repl_survives_errors_and_logs_python_output(self):
        commands = f"set target {self.base}\nuse web/tech\nrun\nuse missing/nope\npython 1/0\npython print('REPL_SURVIVED')\nsessions\nexit\n"
        with TemporaryDirectory() as directory:
            process, log = self.cli(directory, stdin=commands)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn("REPL_SURVIVED", process.stdout)
            self.assertIn("division by zero", process.stdout)
            self.assertIn("nginx 1.18.0", process.stdout)
            self.assertIn("> use missing/nope", log)
            self.assertIn("> python 1/0", log)
            self.assertIn("REPL_SURVIVED", log)

    def test_auto_continues_after_missing_module_and_respects_condition(self):
        pipeline = [
            {"module": "missing/nope", "condition": "always"},
            {"module": "web/tech", "condition": "always", "options": {"url": self.base}},
            {"module": "misc/ftp_anon", "condition": "has_open_port:1"},
        ]
        with TemporaryDirectory() as directory:
            config = Path(directory) / "pipeline.yaml"
            config.write_text(yaml.safe_dump({"auto_pipeline": pipeline}), encoding="utf-8")
            process, log = self.cli(directory, "--target", "127.0.0.1", "--auto", "full", "--config", str(config))
            self.assertEqual(process.returncode, 1, process.stderr)
            self.assertIn("Stage 2/3: web/tech", process.stdout)
            self.assertIn("Skipped (condition not met)", process.stdout)
            self.assertIn("Technology: nginx 1.18.0", process.stdout)
            self.assertIn("SUMMARY", log)


if __name__ == "__main__":
    unittest.main()
