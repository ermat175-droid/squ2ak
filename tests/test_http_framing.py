"""Проверки ограниченного восстановления ошибочного Content-Length."""

from __future__ import annotations

import gzip
import unittest
from unittest.mock import patch

import httpx

from utils.web import WebClient, WebRequestError


class InterruptedBody(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes], error: Exception | None = None):
        self.chunks = chunks
        self.error = error
        self.closed = False

    def __iter__(self):
        yield from self.chunks
        if self.error is not None:
            raise self.error

    def close(self):
        self.closed = True


class HttpFramingTests(unittest.TestCase):
    BODY = "<!doctype html><html><body>Полный список файлов</body></html>\n".encode()

    def test_complete_html_is_recovered_once_for_both_transport_errors(self):
        for error_type in (httpx.ReadTimeout, httpx.RemoteProtocolError):
            with self.subTest(error=error_type.__name__):
                calls = []
                streams = []

                def handler(request):
                    calls.append(request)
                    stream = InterruptedBody(
                        [self.BODY[:19], self.BODY[19:]],
                        error_type("declared length too large", request=request),
                    )
                    streams.append(stream)
                    return httpx.Response(
                        200,
                        headers={"Content-Type": "text/html; charset=utf-8",
                                 "Content-Length": str(len(self.BODY) + 12)},
                        extensions={"http_version": b"HTTP/1.1", "fixture": "retained"},
                        stream=stream,
                    )

                with patch("utils.web.time.sleep") as sleep:
                    with self.assertLogs("squ2ak.utils.web", level="WARNING") as logs:
                        with WebClient(retries=2, transport=httpx.MockTransport(handler)) as client:
                            response = client.get("http://ctf.test/ftp?file=readme")
                self.assertEqual(len(calls), 1)
                sleep.assert_not_called()
                self.assertEqual(len(logs.output), 1)
                self.assertIn("Recovered complete HTML", logs.output[0])
                self.assertEqual(response.content, self.BODY)
                self.assertIn("Полный список файлов", response.text)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["content-length"], str(len(self.BODY) + 12))
                self.assertEqual(response.request, calls[0])
                self.assertEqual(response.extensions["fixture"], "retained")
                self.assertTrue(response.extensions["squ2ak_html_framing_recovered"])
                self.assertEqual(response.http_version, "HTTP/1.1")
                self.assertGreaterEqual(response.elapsed.total_seconds(), 0)
                self.assertTrue(streams[0].closed)

    def test_incomplete_or_non_html_content_remains_an_error_and_retries(self):
        cases = [
            (b"<html><body>unfinished", {"Content-Type": "text/html"}, 12),
            (b'{"data":"</html>"}', {"Content-Type": "application/json"}, 12),
            (self.BODY, {"Content-Type": "text/plain"}, 12),
            (self.BODY, {"Content-Type": "text/html"}, 129),
            (self.BODY, {"Content-Type": "text/html"}, -1),
            (self.BODY, {"Content-Type": "text/html"}, 0),
            (self.BODY, {"Content-Type": "text/html", "Content-Encoding": "gzip"}, 12),
            (self.BODY, {"Content-Type": "text/html", "Transfer-Encoding": "chunked"}, 12),
            (b"", {"Content-Type": "text/html"}, 12),
        ]
        for body, headers, gap in cases:
            with self.subTest(headers=headers, gap=gap, body=body[:20]):
                calls = []
                streams = []

                def handler(request):
                    calls.append(request)
                    stream = InterruptedBody([body], httpx.ReadTimeout("broken body", request=request))
                    streams.append(stream)
                    return httpx.Response(
                        200,
                        headers={**headers, "Content-Length": str(len(body) + gap)},
                        stream=stream,
                    )

                with patch("utils.web.time.sleep") as sleep:
                    with WebClient(retries=1, transport=httpx.MockTransport(handler)) as client:
                        with self.assertRaisesRegex(WebRequestError, "ReadTimeout"):
                            client.get("http://ctf.test/ftp")
                self.assertEqual(len(calls), 2)
                sleep.assert_called_once()
                self.assertTrue(all(stream.closed for stream in streams))

    def test_missing_and_invalid_declared_lengths_cannot_be_recovered(self):
        for length in (None, "invalid", b"\xff12", "-1"):
            with self.subTest(length=length):
                def handler(request):
                    headers = {"Content-Type": "text/html"}
                    if length is not None:
                        headers["Content-Length"] = length
                    return httpx.Response(
                        200, headers=headers,
                        stream=InterruptedBody([self.BODY], httpx.RemoteProtocolError("short body", request=request)),
                    )

                with WebClient(retries=0, transport=httpx.MockTransport(handler)) as client:
                    with self.assertRaises(WebRequestError):
                        client.get("http://ctf.test/")

    def test_recovery_can_be_disabled(self):
        def handler(request):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Content-Length": str(len(self.BODY) + 12)},
                stream=InterruptedBody([self.BODY], httpx.ReadTimeout("short body", request=request)),
            )

        with WebClient(retries=0, recover_html=False, transport=httpx.MockTransport(handler)) as client:
            with self.assertRaises(WebRequestError):
                client.get("http://ctf.test/")

    def test_redirect_history_survives_recovery_and_status_is_not_changed(self):
        def handler(request):
            if request.url.path == "/ftp":
                return httpx.Response(301, headers={"Location": "/ftp/"})
            return httpx.Response(
                500,
                headers={"Content-Type": "TEXT/HTML; charset=utf-8", "Content-Length": str(len(self.BODY) + 12)},
                stream=InterruptedBody([self.BODY], httpx.ReadTimeout("short body", request=request)),
            )

        with self.assertLogs("squ2ak.utils.web", level="WARNING"):
            with WebClient(retries=0, transport=httpx.MockTransport(handler)) as client:
                response = client.get("http://ctf.test/ftp")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(str(response.url), "http://ctf.test/ftp/")
        self.assertEqual(len(response.history), 1)
        self.assertEqual(response.history[0].status_code, 301)
        self.assertEqual(str(response.history[0].url), "http://ctf.test/ftp")

    def test_normal_compressed_body_is_decoded_once(self):
        compressed = gzip.compress(self.BODY)

        def handler(request):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8", "Content-Encoding": "gzip",
                         "Content-Length": str(len(compressed))},
                stream=InterruptedBody([compressed[:10], compressed[10:]]),
            )

        with WebClient(transport=httpx.MockTransport(handler)) as client:
            response = client.get("http://ctf.test/")
        self.assertEqual(response.content, self.BODY)
        self.assertIn("Полный список файлов", response.text)
        self.assertEqual(response.headers["content-encoding"], "gzip")
        self.assertNotIn("squ2ak_html_framing_recovered", response.extensions)

    def test_normal_latin_one_text_keeps_encoding(self):
        body = "<html>caf\u00e9</html>".encode("latin-1")

        def handler(request):
            return httpx.Response(200, headers={"Content-Type": "text/html; charset=iso-8859-1"},
                                  stream=InterruptedBody([body]))

        with WebClient(transport=httpx.MockTransport(handler)) as client:
            response = client.get("http://ctf.test/")
        self.assertEqual(response.text, "<html>caf\u00e9</html>")
        self.assertNotIn("content-length", response.headers)

    def test_failed_partial_read_can_retry_to_a_normal_response(self):
        calls = []

        def handler(request):
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/html", "Content-Length": "999"},
                    stream=InterruptedBody([b"<html>truncated"], httpx.ReadTimeout("short body", request=request)),
                )
            return httpx.Response(403, text="denied")

        with patch("utils.web.time.sleep"):
            with WebClient(retries=1, transport=httpx.MockTransport(handler)) as client:
                response = client.request("POST", "http://ctf.test/search", data={"q": "test"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.text, "denied")
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(request.content == b"q=test" for request in calls))


if __name__ == "__main__":
    unittest.main()
