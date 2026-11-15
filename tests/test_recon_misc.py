"""Регрессии сетевых модулей; внешние цели не используются."""

from __future__ import annotations

import io
import socket
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from core.session import Session
from modules.misc.ftp_anon import FTPAnonymousModule
from modules.misc.redis_unauth import RedisResponseError, RedisUnauthModule, read_response
from modules.recon.banner import BannerModule, parse_service_banner
from modules.recon.dns import DNSModule, bounded_transfer
from utils.net import grab_banner, parse_ports, syn_scan, target_host, tcp_connect


def bulk(value: str) -> bytes:
    encoded = value.encode()
    return f"${len(encoded)}\r\n".encode() + encoded + b"\r\n"


class NetTests(unittest.TestCase):
    def test_ports_deduplicate_sort_and_expand(self):
        self.assertEqual(parse_ports("443,80,8000-8002,80"), [80, 443, 8000, 8001, 8002])
        self.assertEqual(parse_ports([65535, 1, 1]), [1, 65535])

    def test_ports_reject_invalid_ranges_before_scanning(self):
        for value in ("", "0", "65536", "3-1", "1-65536", "80,,443", "abc", "1-2-3", [True]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)

    def test_connect_refused_is_closed(self):
        with patch("utils.net.socket.create_connection", side_effect=ConnectionRefusedError):
            self.assertFalse(tcp_connect("127.0.0.1", 12345, 0.1))

    def test_successful_connect_closes_socket(self):
        connection = MagicMock()
        with patch("utils.net.socket.create_connection", return_value=connection):
            self.assertTrue(tcp_connect("127.0.0.1", 12345, 0.1))
        connection.__exit__.assert_called_once()

    def test_non_root_syn_rejected_without_scapy(self):
        with patch("utils.net.os.geteuid", return_value=1000, create=True):
            with self.assertRaises(PermissionError):
                syn_scan("127.0.0.1", [80])

    def test_syn_only_reports_syn_ack_and_closes_half_open(self):
        sent = MagicMock()
        sent.__getitem__.return_value = SimpleNamespace(dport=8443, sport=49152)
        opened = MagicMock()
        opened.haslayer.return_value = True
        opened.__getitem__.return_value = SimpleNamespace(flags=0x12, ack=123)
        closed = MagicMock()
        closed.haslayer.return_value = True
        closed.__getitem__.return_value = SimpleNamespace(flags=0x14, ack=0)
        packet = MagicMock()
        ip = Mock(return_value=packet)
        tcp_factory = Mock(return_value=packet)
        scapy = types.ModuleType("scapy")
        scapy.__path__ = []
        scapy_all = types.ModuleType("scapy.all")
        scapy_all.IP = ip
        scapy_all.IPv6 = Mock(return_value=packet)
        scapy_all.TCP = tcp_factory
        scapy_all.send = Mock()
        scapy_all.sr = Mock(return_value=([(sent, opened), (sent, closed)], []))
        with patch.dict(sys.modules, {"scapy": scapy, "scapy.all": scapy_all}), patch("utils.net.os.geteuid", return_value=0, create=True):
            self.assertEqual(syn_scan("127.0.0.1", [8443], timeout=0.1), [8443])
        scapy_all.send.assert_called_once()
        self.assertEqual(tcp_factory.call_args_list[-1].kwargs["flags"], "R")
        with patch.dict(sys.modules, {"scapy": scapy, "scapy.all": scapy_all}), patch("utils.net.os.geteuid", return_value=0, create=True):
            self.assertEqual(syn_scan("::1", [8443], timeout=0.1), [8443])
        scapy_all.IPv6.assert_called_with(dst="::1")
        scapy_all.sr.side_effect = Exception("scapy route unavailable")
        with patch.dict(sys.modules, {"scapy": scapy, "scapy.all": scapy_all}), patch("utils.net.os.geteuid", return_value=0, create=True):
            with self.assertRaisesRegex(RuntimeError, "SYN scan failed"):
                syn_scan("127.0.0.1", [8443], timeout=0.1)

    def test_banner_timeout_is_empty(self):
        connection = Mock()
        connection.recv.side_effect = socket.timeout()
        self.assertEqual(grab_banner(connection), "")

    def test_target_urls_and_ipv6(self):
        self.assertEqual(target_host("https://example.test:8443/path"), "example.test")
        self.assertEqual(target_host("http://[::1]:8000/"), "::1")
        self.assertEqual(target_host("[::1]"), "::1")
        self.assertEqual(target_host("[::1]:8080"), "::1")
        self.assertEqual(target_host("::1"), "::1")
        self.assertEqual(target_host("example.test:8080"), "example.test")
        self.assertEqual(target_host("127.0.0.1:8080"), "127.0.0.1")
        with self.assertRaises(ValueError):
            target_host("localhost\r\nInjected: yes")
        with self.assertRaises(ValueError):
            target_host("example.test:99999")


class ModuleTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.reset()
        self.session.set_target("127.0.0.1")
        self.output = patch.multiple("utils.renderer", print_table=Mock(), print_info=Mock(), print_warn=Mock(), print_success=Mock())
        self.output.start()
        self.addCleanup(self.output.stop)

    def test_banner_versions_and_unknown_fallback(self):
        self.assertEqual(parse_service_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4", 22), ("ssh", "OpenSSH 8.2p1"))
        self.assertEqual(parse_service_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0", 443), ("https", "nginx 1.18.0"))
        self.assertEqual(parse_service_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0", 9443, "https"), ("https", "nginx 1.18.0"))
        self.assertEqual(parse_service_banner("220 (vsFTPd 3.0.3)", 21), ("ftp", "vsftpd 3.0.3"))
        self.assertEqual(parse_service_banner("", 12345, "custom"), ("custom", ""))

    def test_banner_preserves_existing_version_and_continues_errors(self):
        self.session.add_service(22, name="ssh")
        self.session.add_service(6379, name="redis", version="6.0.9")
        module = BannerModule(self.session)
        with patch.object(module, "_grab", side_effect=[OSError("refused"), ""]):
            module.run()
        self.assertEqual(self.session.services[22]["name"], "ssh")
        self.assertEqual(self.session.services[6379]["version"], "6.0.9")

    def test_banner_does_not_invent_open_port_when_connection_fails(self):
        module = BannerModule(self.session)
        module.set_option("ports", "12345")
        with patch.object(module, "_grab", side_effect=ConnectionRefusedError("refused")):
            module.run()
        self.assertNotIn(12345, self.session.services)

    def test_http_head_collects_fragmented_headers(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [b"HTTP/1.1 200 OK\r\n", b"Server: Apache/2.4.49\r\n\r\n"]
        module = BannerModule(self.session)
        with patch("modules.recon.banner.socket.create_connection", return_value=connection):
            banner = module._grab("127.0.0.1", 80, 1, "http")
        self.assertIn("Apache/2.4.49", banner)
        request = connection.sendall.call_args.args[0]
        self.assertTrue(request.startswith(b"HEAD / HTTP/1.1"))
        with self.assertRaises(ValueError):
            module._head_request("host\r\nInjected: x", 80)

    def test_unknown_port_http_head_after_brief_greeting_timeout(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [socket.timeout(), b"HTTP/1.1 200 OK\r\nServer: nginx/1.22.0\r\n\r\n"]
        module = BannerModule(self.session)
        with patch("modules.recon.banner.socket.create_connection", return_value=connection):
            banner = module._grab("127.0.0.1", 18080, 1, "unknown")
        self.assertEqual(parse_service_banner(banner, 18080), ("http", "nginx 1.22.0"))
        connection.sendall.assert_called_once()
        self.assertEqual(connection.settimeout.call_args_list[1].args, (0.3,))

    def test_known_redis_is_not_sent_http_probe(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = socket.timeout()
        module = BannerModule(self.session)
        with patch("modules.recon.banner.socket.create_connection", return_value=connection):
            self.assertEqual(module._grab("127.0.0.1", 16379, 1, "redis"), "")
        connection.sendall.assert_not_called()

    def test_ftp_anonymous_success_readonly_and_denied(self):
        import ftplib

        ftp = Mock()
        ftp.connect.return_value = "220 (vsFTPd 3.0.3)"
        with patch("modules.misc.ftp_anon.ftplib.FTP", return_value=ftp):
            FTPAnonymousModule(self.session).run()
        self.assertEqual(self.session.services[21]["version"], "vsftpd 3.0.3")
        self.assertEqual(len(self.session.findings), 1)
        self.assertEqual(self.session.loot[0]["type"], "cred")
        self.assertEqual([call[0] for call in ftp.method_calls], ["connect", "login", "quit"])
        self.session.reset()
        self.session.set_target("127.0.0.1")
        ftp.reset_mock()
        ftp.login.side_effect = ftplib.error_perm("530 Login incorrect")
        with patch("modules.misc.ftp_anon.ftplib.FTP", return_value=ftp):
            FTPAnonymousModule(self.session).run()
        self.assertFalse(self.session.findings)
        self.assertFalse(self.session.loot)
        ftp.quit.assert_called_once()

    def _redis_socket(self, response: bytes):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.makefile.return_value = io.BytesIO(response)
        return connection

    def test_redis_reads_only_and_saves_evidence(self):
        response = b"+PONG\r\n" + bulk("# Server\r\nredis_version:6.0.9\r\n") + b"*2\r\n" + bulk("dir") + bulk("/var/lib/redis")
        connection = self._redis_socket(response)
        with patch("modules.misc.redis_unauth.socket.create_connection", return_value=connection):
            RedisUnauthModule(self.session).run()
        sent = [call.args[0] for call in connection.sendall.call_args_list]
        self.assertEqual(len(sent), 3)
        self.assertIn(b"PING", sent[0])
        self.assertIn(b"INFO", sent[1])
        self.assertIn(b"CONFIG", sent[2])
        self.assertIn(b"GET", sent[2])
        self.assertNotIn(b"SET", b"".join(sent))
        self.assertEqual(self.session.services[6379]["version"], "6.0.9")
        self.assertEqual(self.session.findings[0]["severity"], "high")
        self.assertEqual(self.session.loot[0]["value"]["dir"], "/var/lib/redis")

    def test_redis_noauth_has_no_false_finding(self):
        connection = self._redis_socket(b"-NOAUTH Authentication required.\r\n")
        with patch("modules.misc.redis_unauth.socket.create_connection", return_value=connection):
            RedisUnauthModule(self.session).run()
        self.assertFalse(self.session.findings)
        self.assertFalse(self.session.loot)
        self.assertEqual(connection.sendall.call_count, 1)

    def test_redis_restricted_commands_still_report_ping_only(self):
        connection = self._redis_socket(b"+PONG\r\n-NOPERM INFO denied\r\n-ERR unknown command CONFIG\r\n")
        with patch("modules.misc.redis_unauth.socket.create_connection", return_value=connection):
            RedisUnauthModule(self.session).run()
        self.assertEqual(self.session.findings[0]["severity"], "low")
        self.assertFalse(self.session.findings[0]["info_accessible"])

    def test_redis_target_url_ipv6_and_nondefault_port(self):
        self.session.set_target("http://[::1]:8080/")
        connection = self._redis_socket(b"+PONG\r\n-NOPERM denied\r\n-NOPERM denied\r\n")
        module = RedisUnauthModule(self.session)
        module.set_option("port", 16379)
        with patch("modules.misc.redis_unauth.socket.create_connection", return_value=connection) as connect:
            module.run()
        connect.assert_called_once_with(("::1", 16379), timeout=5.0)
        self.assertIn(16379, self.session.services)
        self.assertEqual(self.session.loot[0]["source"], "redis://[::1]:16379")

    def test_misc_defaults_use_discovered_ports_and_overrides_win(self):
        self.session.add_service(2121, name="ftp")
        self.session.add_service(2021, name="vsftp")
        self.session.add_service(16379, name="redis")
        for cls, expected in ((FTPAnonymousModule, [2021, 2121]), (RedisUnauthModule, [16379])):
            module = cls(self.session)
            with patch.object(module, "_run_port") as run_port:
                module.run()
            self.assertEqual([call.args[1] for call in run_port.call_args_list], expected)
            module.set_option("port", 12345)
            with patch.object(module, "_run_port") as run_port:
                module.run()
            run_port.assert_called_once_with("127.0.0.1", 12345, 5.0)
        self.session.params["port"] = 23456
        with patch.object(RedisUnauthModule, "_run_port") as run_port:
            RedisUnauthModule(self.session).run()
        run_port.assert_called_once_with("127.0.0.1", 23456, 5.0)

    def test_dns_records_and_axfr_use_bounded_timeouts(self):
        import dns.resolver

        self.session.set_target("example.test")
        answers = {
            ("example.test", "A"): ["192.0.2.1"],
            ("example.test", "AAAA"): ["2001:db8::1"],
            ("example.test", "MX"): ["10 mail.example.test."],
            ("example.test", "TXT"): ['"test text"'],
            ("example.test", "NS"): ["ns.example.test."],
            ("ns.example.test", "A"): ["192.0.2.53"],
        }
        resolver = Mock()
        resolver.resolve.side_effect = lambda name, kind, **kwargs: [SimpleNamespace(to_text=lambda value=value: value) for value in answers[(name, kind)]]
        dataset = SimpleNamespace(to_text=lambda: "300 IN A 192.0.2.1")
        zone = SimpleNamespace(nodes={"www": SimpleNamespace(rdatasets=[dataset])})
        with patch("dns.resolver.Resolver", return_value=resolver), patch("dns.query.xfr", return_value=iter(())) as transfer, patch("dns.zone.from_xfr", return_value=zone):
            DNSModule(self.session).run()
        transfer.assert_called_once_with("192.0.2.53", "example.test", timeout=5.0, lifetime=5.0)
        self.assertEqual(len([item for item in self.session.loot if item["type"] == "dns"]), 5)
        self.assertEqual(self.session.findings[0]["title"], "DNS zone transfer allowed")

    def test_dns_no_records_does_not_abort_following_queries(self):
        import dns.resolver

        self.session.set_target("example.test")
        resolver = Mock()
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        with patch("dns.resolver.Resolver", return_value=resolver), patch("dns.query.xfr") as transfer:
            DNSModule(self.session).run()
        self.assertEqual(resolver.resolve.call_count, 5)
        self.assertFalse(self.session.loot)
        transfer.assert_not_called()

    def test_dns_axfr_resource_limit(self):
        messages = [SimpleNamespace(answer=[[1, 2]]), SimpleNamespace(answer=[[3, 4]])]
        self.assertEqual(len(list(bounded_transfer(iter(messages), max_records=4))), 2)
        with self.assertRaisesRegex(ValueError, "record limit"):
            list(bounded_transfer(iter(messages), max_records=3))


class RESPTests(unittest.TestCase):
    def test_simple_integer_null_and_nested_array(self):
        self.assertEqual(read_response(io.BytesIO(b"*3\r\n+OK\r\n:2\r\n$-1\r\n")), ["OK", 2, None])

    def test_error_and_oversized_or_truncated_responses(self):
        with self.assertRaises(RedisResponseError):
            read_response(io.BytesIO(b"-NOAUTH Authentication required\r\n"))
        for payload in (b"$999999999\r\n", b"*999999999\r\n", b"$5\r\nabc\r\n", b"+PONG", b"?unexpected\r\n"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                read_response(io.BytesIO(payload))

    def test_nested_bulk_responses_share_total_size_limit(self):
        body = "x" * (600 * 1024)
        with self.assertRaisesRegex(ValueError, "total size"):
            read_response(io.BytesIO(b"*2\r\n" + bulk(body) + bulk(body)))


if __name__ == "__main__":
    unittest.main()
