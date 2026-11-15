"""Контракты core и консоли; команды не выходят в сеть."""

from __future__ import annotations

import importlib.util
import io
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import DEFAULT, Mock, patch

from prompt_toolkit.document import Document

from core.auto import AutoRunner
from core.execution import execute_module
from core.logging_setup import SessionLog
from core.module_base import BaseModule
from core.registry import ModuleRegistry
from core.repl import REPL, Squ2akCompleter, parse_value
from core.session import Session
from utils import renderer


class OptionModule(BaseModule):
    name = "options"
    category = "test"
    description = "Test module"
    options = {
        "token": {"default": None, "required": True, "description": "Required option"},
        "threads": {"default": 4, "required": False, "description": "Worker count"},
        "verify": {"default": True, "required": False, "description": "TLS verify"},
    }

    def run(self):
        self.session.add_loot("test", self.get_option("token"), self.session.target)


class TraceModule(BaseModule):
    category = "test"
    name = "trace"
    description = "Record execution without network"

    def run(self):
        self.session.params.setdefault("executed", []).append(self.name)


class FailureModule(TraceModule):
    name = "fail"

    def run(self):
        super().run()
        raise RuntimeError("fixture failure")


class InterruptedModule(TraceModule):
    name = "interrupt"

    def run(self):
        super().run()
        raise KeyboardInterrupt


def trace_registry() -> ModuleRegistry:
    registry = ModuleRegistry()
    for name in ("a", "b", "c"):
        registry.register(type(f"Trace{name.upper()}", (TraceModule,), {"name": name}))
    registry.register(FailureModule)
    registry.register(InterruptedModule)
    registry.register(OptionModule)
    return registry


class CoreTestCase(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.renderer_patch = patch.multiple(
            renderer, print_info=DEFAULT, print_success=DEFAULT, print_error=DEFAULT,
            print_warn=DEFAULT, print_table=DEFAULT, print_summary=DEFAULT, print_loot=DEFAULT,
        )
        self.output = self.renderer_patch.start()
        self.addCleanup(self.renderer_patch.stop)
        self.addCleanup(self.session.reset)


class SessionTests(CoreTestCase):
    def test_singleton_reset_and_snapshot_independence(self):
        self.assertIs(self.session, Session())
        self.session.set_target("ctf.test")
        self.session.add_service(80, "http", "nginx 1.18", "HTTP fixture")
        self.session.add_loot("flag", "CTF{fixture}", "http://ctf.test")
        snapshot = self.session.snapshot()
        snapshot["services"][80]["version"] = "changed"
        snapshot["loot"][0]["value"] = "changed"
        self.assertEqual(self.session.services[80]["version"], "nginx 1.18")
        self.assertEqual(self.session.loot[0]["value"], "CTF{fixture}")
        self.session.reset()
        self.assertEqual(self.session.snapshot(), {"target": None, "services": {}, "loot": [], "findings": [], "params": {}})

    def test_target_change_clears_findings_without_losing_global_options(self):
        self.session.set_target("first.test")
        self.session.params.update({"threads": 8, "url": "http://first.test/override", "urls": ["http://first.test/a?id=1"]})
        self.session.add_service(80, "http")
        self.session.add_loot("flag", "fixture", "first.test")
        self.session.add_finding("Fixture", "first.test")
        self.session.set_target("first.test")
        self.assertIn(80, self.session.services)
        self.session.set_target("second.test")
        self.assertEqual(self.session.services, {})
        self.assertEqual(self.session.loot, [])
        self.assertEqual(self.session.findings, [])
        self.assertNotIn("urls", self.session.params)
        self.assertNotIn("url", self.session.params)
        self.assertEqual(self.session.params["threads"], 8)

    def test_configured_urls_survive_initial_target_assignment(self):
        initial_urls = {"url": "http://first.test/override", "urls": ["http://first.test/a?id=1"]}
        self.session.params.update(initial_urls)
        self.session.set_target("first.test")
        self.assertEqual(self.session.params, initial_urls)
        self.session.set_target("second.test")
        self.assertNotIn("url", self.session.params)
        self.assertNotIn("urls", self.session.params)

    def test_service_updates_merge_and_loot_deduplicates(self):
        self.session.add_service(22, "ssh", "OpenSSH 8.2", "SSH fixture")
        self.session.add_service(22, banner="SSH new banner")
        self.assertEqual(self.session.services[22], {"name": "ssh", "version": "OpenSSH 8.2", "banner": "SSH new banner"})
        self.session.add_loot("cred", "anonymous:anonymous", "ftp://ctf.test")
        self.session.add_loot("cred", "anonymous:anonymous", "ftp://ctf.test")
        self.assertEqual(len(self.session.loot), 1)
        self.assertIn("timestamp", self.session.loot[0])
        self.session.add_finding("Anonymous FTP", "ftp://ctf.test")
        self.session.add_finding("Anonymous FTP", "ftp://ctf.test")
        self.assertEqual(len(self.session.findings), 1)

    def test_invalid_targets_and_ports_do_not_corrupt_state(self):
        self.session.set_target("ctf.test")
        for target in ("", "two hosts"):
            with self.assertRaises(ValueError):
                self.session.set_target(target)
        for port in (0, 65536):
            with self.assertRaises(ValueError):
                self.session.add_service(port)
        self.assertEqual(self.session.target, "ctf.test")
        self.assertEqual(self.session.services, {})


class ModuleRegistryTests(CoreTestCase):
    def test_default_global_and_local_priority_are_isolated(self):
        first, second = OptionModule(self.session), OptionModule(self.session)
        self.assertEqual(first.get_option("threads"), 4)
        self.session.params["threads"] = "12"
        self.assertEqual(first.get_option("threads"), 12)
        self.assertEqual(second.get_option("threads"), 12)
        first.set_option("threads", "2")
        self.assertEqual(first.get_option("threads"), 2)
        self.assertEqual(second.get_option("threads"), 12)
        self.session.params["threads"] = 16
        self.assertEqual(first.get_option("threads"), 2)
        self.assertEqual(second.get_option("threads"), 16)
        first.options["threads"]["description"] = "changed"
        self.assertNotEqual(second.options["threads"]["description"], "changed")
        first.set_option("target", "ctf.test")
        self.assertEqual(second.get_option("target"), "ctf.test")

    def test_required_and_invalid_options_prevent_execution(self):
        module = OptionModule(self.session)
        self.assertFalse(execute_module(module))
        self.session.set_target("ctf.test")
        self.assertFalse(module.validate())
        module.set_option("token", "fixture")
        self.assertTrue(module.validate())
        module.set_option("threads", 0)
        self.assertFalse(module.validate())
        module.set_option("threads", 4)
        module.set_option("timeout", 0)
        self.assertFalse(module.validate())
        with self.assertRaises(ValueError):
            module.set_option("unknown", "x")
        with self.assertRaises(ValueError):
            module.set_option("verify", "maybe")
        module.set_option("verify", "false")
        self.assertIs(module.get_option("verify"), False)
        self.assertEqual(self.session.loot, [])

    def test_discovery_loads_all_requested_modules(self):
        registry = ModuleRegistry().discover()
        self.assertEqual(set(registry.paths()), {
            "recon/portscan", "recon/banner", "recon/dns", "web/tech", "web/dirb",
            "web/sqli", "web/lfi", "web/cmdi", "web/xss", "web/cors", "web/exposure",
            "web/graphql", "web/http_methods", "web/open_redirect", "web/secheaders",
            "web/ssti", "web/jwt",
            "misc/ftp_anon", "misc/redis_unauth", "templates/runner",
        })
        self.assertEqual(registry.errors, {})
        for path in registry.paths():
            self.assertIs(registry.create(path, self.session).session, self.session)

    def test_duplicate_and_missing_modules_fail_clearly(self):
        registry = ModuleRegistry()
        registry.register(TraceModule)
        registry.register(TraceModule)
        conflicting = type("Conflict", (TraceModule,), {})
        with self.assertRaises(ValueError):
            registry.register(conflicting)
        with self.assertRaisesRegex(ValueError, "missing/module"):
            registry.create("missing/module", self.session)

    def test_fractional_timeout_is_preserved_by_all_modules(self):
        self.session.set_target("ctf.test")
        registry = ModuleRegistry().discover()
        for path in registry.paths():
            with self.subTest(module=path):
                module = registry.create(path, self.session)
                module.set_option("timeout", "0.25")
                self.assertEqual(module.get_option("timeout"), 0.25)
                self.assertTrue(module.validate())

    def test_nonfinite_timeout_is_rejected_by_all_modules(self):
        self.session.set_target("ctf.test")
        registry = ModuleRegistry().discover()
        for path in registry.paths():
            for value in ("nan", "inf", "-inf"):
                with self.subTest(module=path, value=value):
                    module = registry.create(path, self.session)
                    module.set_option("timeout", value)
                    self.assertFalse(module.validate())

    def test_local_web_url_is_discarded_when_target_changes(self):
        self.session.set_target("first.test")
        registry = ModuleRegistry().discover()
        module = registry.create("templates/runner", self.session)
        module.set_option("url", "http://first.test/override")
        self.session.set_target("first.test")
        self.assertEqual(module.get_option("url"), "http://first.test/override")
        self.session.set_target("second.test")
        self.assertIn(module.get_option("url"), (None, ""))
        module.set_option("url", "http://second.test/new")
        self.assertEqual(module.get_option("url"), "http://second.test/new")


class AutoTests(CoreTestCase):
    def setUp(self):
        super().setUp()
        self.session.set_target("ctf.test")
        self.registry = trace_registry()

    def runner(self, names=("a", "b", "c"), mode="full"):
        return AutoRunner(self.session, [{"module": f"test/{name}", "condition": "always"} for name in names], mode, self.registry)

    def test_every_condition_and_invalid_conditions(self):
        runner = self.runner(())
        self.assertTrue(runner._check_condition("always"))
        self.assertFalse(runner._check_condition("has_web"))
        self.session.add_service(22, "OpenSSH")
        self.assertTrue(runner._check_condition("has_service:ssh"))
        self.assertTrue(runner._check_condition("has_service:SSH"))
        self.assertFalse(runner._check_condition("has_service:redis"))
        self.assertTrue(runner._check_condition("has_open_port:22"))
        self.assertFalse(runner._check_condition("has_open_port:80"))
        for port in (80, 443, 8000, 8080, 8443, 3000, 5000):
            self.session.add_service(port)
            self.assertTrue(runner._check_condition("has_web"))
            self.session.services.pop(port)
        with patch("core.auto.os.geteuid", return_value=0, create=True):
            self.assertTrue(runner._check_condition("root"))
        with patch("core.auto.os.geteuid", return_value=1000, create=True):
            self.assertFalse(runner._check_condition("root"))
        for condition in ("unknown", "has_service:", "has_open_port:nope", "has_open_port:0", "has_open_port:65536"):
            with self.subTest(condition=condition), self.assertRaises(ValueError):
                runner._check_condition(condition)

    def test_boolean_finding_and_loot_conditions(self):
        runner = self.runner(())
        self.session.add_service(80, "http")
        self.assertTrue(runner._check_condition("has_web and has_service:http"))
        self.assertFalse(runner._check_condition("has_web and has_service:ssh"))
        self.assertTrue(runner._check_condition("has_service:ssh or has_service:http"))
        self.assertTrue(runner._check_condition("not has_service:ssh"))
        self.assertFalse(runner._check_condition("not has_service:http"))
        self.assertTrue(runner._check_condition("not not has_service:http"))
        self.assertFalse(runner._check_condition("has_finding:sqli"))
        self.session.add_finding("Possible SQL injection: q", "http://x", severity="high", module="web/sqli")
        self.assertTrue(runner._check_condition("has_finding:sql injection"))
        self.assertTrue(runner._check_condition("has_finding:web/sqli"))
        self.assertFalse(runner._check_condition("has_loot:url"))
        self.session.add_loot("url", "http://x/admin", "web/dirb")
        self.assertTrue(runner._check_condition("has_loot:url"))
        for bad in ("", "has_finding:", "has_loot:"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                runner._check_condition(bad)

    def test_top_severity_ranking(self):
        runner = self.runner(())
        self.assertEqual(runner._top_severity(
            [{"severity": "low"}, {"severity": "critical"}, {"severity": "high"}]), "critical")
        self.assertEqual(runner._top_severity([{"severity": "info"}, {"severity": "medium"}]), "medium")
        self.assertIsNone(runner._top_severity([]))

    def test_results_record_metrics_and_print_results_table(self):
        runner = self.runner()
        runner.run()
        for entry in runner.results:
            self.assertEqual({"module", "status", "findings", "severity", "duration"} - set(entry), set())
        titles = [call.args[0] for call in self.output["print_table"].call_args_list]
        self.assertIn("Auto results", titles)

    def test_auto_writes_report_when_report_base_set(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "rep"
            runner = AutoRunner(self.session, [{"module": "test/a", "condition": "always"}],
                                "full", self.registry, report_base=base, report_format="both")
            runner.run()
            self.assertTrue((Path(temporary) / "rep.md").exists())
            self.assertTrue((Path(temporary) / "rep.json").exists())

    def test_auto_without_report_base_writes_no_file(self):
        runner = self.runner()
        runner.run()
        self.assertIsNone(runner.report_base)

    def test_full_pipeline_skips_unmet_conditions(self):
        runner = self.runner()
        runner.pipeline[1]["condition"] = "has_web"
        runner.run()
        self.assertEqual(self.session.params["executed"], ["a", "c"])
        self.assertEqual([entry["status"] for entry in runner.results], ["completed", "skipped", "completed"])
        self.output["print_summary"].assert_called_once_with(self.session)

    def test_module_error_and_missing_module_continue_pipeline(self):
        runner = self.runner(("a", "fail", "missing", "c"))
        with self.assertLogs("squ2ak", level="ERROR"):
            runner.run()
        self.assertEqual(self.session.params["executed"], ["a", "fail", "c"])
        self.assertEqual([entry["status"] for entry in runner.results], ["completed", "failed", "failed", "completed"])
        self.output["print_summary"].assert_called_once()

    def test_unknown_condition_fails_only_its_stage(self):
        runner = self.runner()
        runner.pipeline[1]["condition"] = "unknown"
        with self.assertLogs("squ2ak", level="ERROR"):
            runner.run()
        self.assertEqual(self.session.params["executed"], ["a", "c"])
        self.assertEqual(runner.results[1]["status"], "failed")
        self.assertIn("unknown", runner.results[1]["error"])

    def test_step_skip_next_and_quit(self):
        runner = self.runner(mode="step")
        with patch.object(runner, "_wait_step", side_effect=["skip", "continue", "quit"]) as wait:
            runner.run()
        self.assertEqual(self.session.params["executed"], ["a", "c"])
        self.assertEqual([entry["status"] for entry in runner.results], ["completed", "skipped", "completed"])
        self.assertEqual(wait.call_count, 3)
        self.session.params.pop("executed")
        runner = self.runner(mode="step")
        with patch.object(runner, "_wait_step", return_value="quit"):
            runner.run()
        self.assertEqual(self.session.params["executed"], ["a"])
        self.assertEqual(len(runner.results), 1)

    def test_from_stage_and_unknown_start(self):
        runner = self.runner()
        runner.run("test/b")
        self.assertEqual(self.session.params["executed"], ["b", "c"])
        self.assertEqual([entry["module"] for entry in runner.results], ["test/b", "test/c"])
        with self.assertRaises(ValueError):
            runner.run("test/missing")

    def test_interrupt_stops_auto_but_always_prints_summary(self):
        runner = self.runner(("a", "interrupt", "c"))
        runner.run()
        self.assertEqual(self.session.params["executed"], ["a", "interrupt"])
        self.assertEqual([entry["status"] for entry in runner.results], ["completed", "interrupted"])
        self.output["print_summary"].assert_called_once_with(self.session)

    def test_step_prompt_choices_eof_and_interrupt(self):
        runner = self.runner(mode="step")
        for inputs, expected in ((["bad", ""], "continue"), (["S"], "skip"), (["q"], "quit")):
            with self.subTest(inputs=inputs), patch("builtins.input", side_effect=inputs):
                self.assertEqual(runner._wait_step("test/a"), expected)
        for exception in (EOFError, KeyboardInterrupt):
            with patch("builtins.input", side_effect=exception):
                self.assertEqual(runner._wait_step("test/a"), "quit")

    def test_stage_options_are_applied_and_validation_failure_continues(self):
        pipeline = [
            {"module": "test/options", "options": {"token": "fixture"}},
            {"module": "test/options", "options": {"threads": 0}},
            {"module": "test/a"},
        ]
        runner = AutoRunner(self.session, pipeline, "full", self.registry)
        runner.run()
        self.assertEqual([entry["status"] for entry in runner.results], ["completed", "failed", "completed"])
        self.assertEqual(self.session.loot[0]["value"], "fixture")
        self.assertEqual(self.session.params["executed"], ["a"])

    def test_invalid_pipeline_and_missing_target(self):
        for pipeline in (None, ["test/a"], [{"module": "test/a", "condition": 1}], [{"module": "test/a", "options": []}]):
            with self.subTest(pipeline=pipeline), self.assertRaises(ValueError):
                AutoRunner(self.session, pipeline, "full", self.registry)
        with self.assertRaises(ValueError):
            self.runner(mode="unknown")
        self.session.reset()
        runner = self.runner()
        runner.run()
        self.assertEqual(runner.results, [])
        self.output["print_error"].assert_called()


class REPLTests(CoreTestCase):
    def setUp(self):
        super().setUp()
        self.registry = trace_registry()
        self.log = Mock()
        self.repl = REPL(self.session, self.registry, [], self.log)

    def test_use_local_global_back_and_command_logging(self):
        for command in ("set target ctf.test", "setg threads 10", "use test/options", "set token fixture", "set threads 2", "run"):
            self.assertTrue(self.repl.dispatch(command))
        self.assertEqual(self.repl.active.get_option("threads"), 2)
        self.assertEqual(self.session.params["threads"], 10)
        self.assertEqual(self.session.loot[0]["value"], "fixture")
        self.assertTrue(self.repl.dispatch("back"))
        self.assertIsNone(self.repl.active)
        self.assertEqual(OptionModule(self.session).get_option("threads"), 10)
        self.assertFalse(self.repl.dispatch("exit"))
        self.assertEqual(self.log.command.call_count, 8)

    def test_malformed_commands_and_module_failures_leave_repl_usable(self):
        self.session.set_target("ctf.test")
        for command in ("set", "use missing/module", "use 'unterminated", "unrecognized", "run"):
            with patch("core.repl.logger.exception"):
                self.assertTrue(self.repl.dispatch(command))
        self.assertTrue(self.repl.dispatch("use test/fail"))
        with self.assertLogs("squ2ak", level="ERROR"):
            self.assertTrue(self.repl.dispatch("run"))
        self.assertEqual(self.repl.active.path, "test/fail")
        self.assertTrue(self.repl.dispatch("use test/a"))
        self.assertTrue(self.repl.dispatch("exploit"))
        self.assertEqual(self.session.params["executed"], ["fail", "a"])

    def test_interrupt_returns_to_repl_and_retains_active_module(self):
        self.session.set_target("ctf.test")
        self.repl.dispatch("use test/interrupt")
        self.assertTrue(self.repl.dispatch("run"))
        self.assertEqual(self.repl.active.path, "test/interrupt")
        self.output["print_warn"].assert_called()
        self.assertTrue(self.repl.dispatch("back"))

    def test_python_context_is_persistent_and_preimports_are_available(self):
        self.assertEqual(set(self.repl.python_context), {"session", "requests", "re", "subprocess"})
        self.assertTrue(self.repl.dispatch("python value = 6"))
        self.assertTrue(self.repl.dispatch("python session.params['answer'] = value * 7"))
        self.assertEqual(self.session.params["answer"], 42)
        self.assertTrue(self.repl.dispatch("python\tsession.params['tab'] = 1"))
        self.assertEqual(self.session.params["tab"], 1)
        self.assertTrue(self.repl.dispatch("python raise SystemExit(2)"))
        self.output["print_warn"].assert_called()
        with patch("core.repl.logger.exception"):
            self.assertTrue(self.repl.dispatch("python raise ValueError('fixture')"))
        self.assertTrue(self.repl.dispatch("python session.params['after_error'] = True"))
        self.assertTrue(self.session.params["after_error"])

    def test_completions_cover_commands_modules_auto_and_options(self):
        completer = Squ2akCompleter(self.repl)

        def complete(text):
            return {item.text for item in completer.get_completions(Document(text), None)}

        self.assertIn("help", complete("he"))
        self.assertEqual(complete("use test/f"), {"test/fail"})
        self.assertIn("test/a", complete("auto from test/"))
        self.assertEqual(complete("show "), {"modules", "options"})
        self.assertIn("full", complete("auto "))
        self.repl.dispatch("use test/options")
        self.assertIn("token", complete("set to"))

    def test_non_tty_loop_handles_ctrl_c_and_eof(self):
        with patch("core.repl.sys.stdin.isatty", return_value=False), \
             patch("builtins.input", side_effect=[KeyboardInterrupt, "set target ctf.test", EOFError]):
            self.repl.run()
        self.assertEqual(self.session.target, "ctf.test")
        self.output["print_warn"].assert_called()

    def test_interactive_prompt_uses_persistent_private_history(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch("core.repl.sys.stdin.isatty", return_value=True), \
             patch("core.repl.state_dir", return_value=Path(directory)), \
             patch("core.repl.PromptSession") as prompt:
            prompt.return_value.prompt.side_effect = ["set target ctf.test", "exit"]
            self.repl.run()
            history = prompt.call_args.kwargs["history"]
            self.assertIsInstance(prompt.call_args.kwargs["completer"], Squ2akCompleter)
            self.assertFalse(prompt.call_args.kwargs["complete_while_typing"])
            history_path = Path(directory) / "history"
            self.assertEqual(history_path.stat().st_mode & 0o777, 0o600)
            history.append_string("set target ctf.test")
            self.assertIn("set target ctf.test", history_path.read_text(encoding="utf-8"))
        self.assertEqual(self.session.target, "ctf.test")

    def test_auto_commands_select_modes_and_start_stage(self):
        with patch("core.repl.AutoRunner") as auto:
            self.repl.dispatch("auto")
            self.assertEqual(auto.call_args.args[2], "step")
            auto.return_value.run.assert_called_with(None)
            self.repl.dispatch("auto full")
            self.assertEqual(auto.call_args.args[2], "full")
            self.repl.dispatch("auto from test/b")
            self.assertEqual(auto.call_args.args[2], "step")
            auto.return_value.run.assert_called_with("test/b")
            self.repl.dispatch("auto list")
            auto.return_value.print_pipeline.assert_called_once()

    def test_parse_value_preserves_strings_and_safe_yaml_values(self):
        self.assertEqual(parse_value("80,443"), "80,443")
        self.assertEqual(parse_value("3"), 3)
        self.assertIs(parse_value("false"), False)
        self.assertEqual(parse_value("['http://ctf.test/?id=1']"), ["http://ctf.test/?id=1"])
        self.assertEqual(parse_value("null"), "null")


class LogAndCLIParserTests(unittest.TestCase):
    def test_log_contains_commands_stdout_and_stderr_without_ansi(self):
        logger = logging.getLogger("squ2ak")
        previous_level, previous_propagate = logger.level, logger.propagate
        try:
            with tempfile.TemporaryDirectory() as directory, \
                 patch.dict(os.environ, {"SQU2AK_HOME": directory}), \
                 patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
                with SessionLog() as log:
                    log.command("set target ctf.test")
                    print("\x1b[32mstdout fixture\x1b[0m")
                    import sys
                    print("stderr fixture", file=sys.stderr)
                    logger.warning("log fixture")
                text = log.path.read_text(encoding="utf-8")
                self.assertIn("set target ctf.test", text)
                self.assertIn("stdout fixture", text)
                self.assertIn("stderr fixture", text)
                self.assertIn("log fixture", text)
                self.assertNotIn("\x1b", text)
                self.assertEqual(log.path.stat().st_mode & 0o777, 0o600)
        finally:
            logger.setLevel(previous_level)
            logger.propagate = previous_propagate
            renderer.configure_console()

    def test_one_shot_extra_options_parse_ranges_equals_and_errors(self):
        path = Path(__file__).resolve().parents[1] / "squ2ak.py"
        spec = importlib.util.spec_from_file_location("squ2ak_test_cli", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.extra_options(["--ports", "80,443,8000-8100", "--follow-redirects=false"]),
                         {"ports": "80,443,8000-8100", "follow_redirects": "false"})
        for tokens in (["--ports"], ["80"], ["--"], ["--=x"], ["--ports", "--timeout", "1"]):
            with self.subTest(tokens=tokens), self.assertRaises(ValueError):
                module.extra_options(tokens)
        args, remaining = module.build_parser().parse_known_args(["--target", "ctf.test", "--module", "recon/portscan", "--ports", "80,443"])
        self.assertEqual(args.target, "ctf.test")
        self.assertEqual(args.module, "recon/portscan")
        self.assertEqual(remaining, ["--ports", "80,443"])


if __name__ == "__main__":
    unittest.main()
