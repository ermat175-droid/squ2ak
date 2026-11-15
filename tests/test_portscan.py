"""Выбор режима, fallback и отмена скана без реальных raw-пакетов."""

import io
import socket
import unittest
from unittest.mock import Mock, patch

from rich.console import Console

from core.session import Session
from modules.recon.portscan import PortScan
from utils import renderer


class PortScanTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("ctf.test")
        self.module = PortScan(self.session)
        self.module.set_option("ports", "22,80")
        console = patch.object(renderer, "console", Console(file=io.StringIO()))
        console.start()
        self.addCleanup(console.stop)
        self.addCleanup(self.session.reset)

    def test_non_root_uses_connect_and_preserves_unscanned_ports(self):
        self.session.add_service(21, "ftp")
        self.session.add_service(22, "ssh")
        with patch("modules.recon.portscan.os.geteuid", return_value=1000, create=True), \
             patch("modules.recon.portscan.socket.getaddrinfo"), \
             patch("modules.recon.portscan.tcp_connect", side_effect=lambda host, port, timeout: port == 80) as connect, \
             patch("modules.recon.portscan.syn_scan") as syn, \
             patch.object(renderer, "print_warn") as warn, \
             patch.object(renderer, "print_success"), patch.object(renderer, "print_table"):
            self.module.run()
        syn.assert_not_called()
        self.assertEqual(connect.call_count, 2)
        self.assertEqual(set(self.session.services), {21, 80})
        self.assertEqual(self.session.services[80]["name"], "http")
        self.assertIn("root", warn.call_args.args[0])

    def test_root_auto_uses_syn(self):
        with patch("modules.recon.portscan.os.geteuid", return_value=0, create=True), \
             patch("modules.recon.portscan.socket.getaddrinfo"), \
             patch("modules.recon.portscan.syn_scan", return_value=[22]) as syn, \
             patch("modules.recon.portscan.tcp_connect") as connect, \
             patch.object(renderer, "print_success"), patch.object(renderer, "print_table"):
            self.module.run()
        syn.assert_called_once_with("ctf.test", [22, 80], timeout=1.0)
        connect.assert_not_called()
        self.assertEqual(set(self.session.services), {22})

    def test_scapy_failure_falls_back_to_connect(self):
        class ScapyFailure(Exception):
            pass
        with patch("modules.recon.portscan.os.geteuid", return_value=0, create=True), \
             patch("modules.recon.portscan.socket.getaddrinfo"), \
             patch("modules.recon.portscan.syn_scan", side_effect=ScapyFailure("raw unavailable")), \
             patch("modules.recon.portscan.tcp_connect", return_value=True), \
             patch.object(renderer, "print_warn") as warn, \
             patch.object(renderer, "print_success"), patch.object(renderer, "print_table"):
            self.module.run()
        self.assertEqual(set(self.session.services), {22, 80})
        self.assertIn("TCP connect", warn.call_args.args[0])

    def test_explicit_connect_skips_syn_even_for_root(self):
        self.module.set_option("scan", "connect")
        with patch("modules.recon.portscan.os.geteuid", return_value=0, create=True), \
             patch("modules.recon.portscan.socket.getaddrinfo"), \
             patch("modules.recon.portscan.syn_scan") as syn, \
             patch("modules.recon.portscan.tcp_connect", return_value=False), \
             patch.object(renderer, "print_success"), patch.object(renderer, "print_table"):
            self.module.run()
        syn.assert_not_called()
        self.assertEqual(self.session.services, {})

    def test_invalid_ports_fail_before_network(self):
        self.module.set_option("ports", "80,70000")
        with patch("modules.recon.portscan.socket.getaddrinfo") as resolve:
            with self.assertRaises(ValueError):
                self.module.run()
        resolve.assert_not_called()

    def test_dns_failure_is_an_error_instead_of_no_open_ports(self):
        with patch("modules.recon.portscan.socket.getaddrinfo", side_effect=socket.gaierror("fixture")), \
             patch("modules.recon.portscan.tcp_connect") as connect:
            with self.assertRaises(socket.gaierror):
                self.module.run()
        connect.assert_not_called()

    def test_interrupt_cancels_pending_tasks_and_keeps_previous_results(self):
        self.module.set_option("scan", "connect")
        self.session.add_service(22, "ssh")
        pool = Mock()
        first, second = Mock(), Mock()
        pool.submit.side_effect = [first, second]
        with patch("modules.recon.portscan.socket.getaddrinfo"), \
             patch("modules.recon.portscan.ThreadPoolExecutor", return_value=pool), \
             patch("modules.recon.portscan.as_completed", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.module.run()
        first.cancel.assert_called_once()
        second.cancel.assert_called_once()
        pool.shutdown.assert_called_once_with(wait=False, cancel_futures=True)
        self.assertIn(22, self.session.services)


if __name__ == "__main__":
    unittest.main()
