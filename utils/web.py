"""HTTP-клиент и адреса веб-сервисов."""

from __future__ import annotations

import ipaddress
import logging
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx


logger = logging.getLogger("squ2ak.utils.web")
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 squ2ak/0.1"
    ),
    "Accept": "*/*",
}
WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000}
TLS_PORTS = {443, 8443}


class WebRequestError(RuntimeError):
    """Сетевая ошибка после исчерпания повторных попыток."""


def normalize_url(target: str, scheme: str = "http", port: int | None = None) -> str:
    """Добавляет схему и корректно оформляет IPv6, сохраняя путь и query."""
    target = str(target).strip()
    if not target:
        raise ValueError("HTTP target is empty")
    if scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS are supported")

    # Голый IPv6 нельзя разбирать как обычный host:port.
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None
    candidate = f"[{target}]" if address and address.version == 6 else target
    parsed = urlsplit(candidate if "://" in candidate else f"{scheme}://{candidate}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Expected an HTTP(S) URL or hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Put HTTP credentials in request headers, not the target URL")
    try:
        original_port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid port in target URL") from exc
    chosen_port = original_port if port is None else int(port)
    if chosen_port is not None and not 1 <= chosen_port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    hostname = parsed.hostname
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if chosen_port is not None:
        authority += f":{chosen_port}"
    return urlunsplit((parsed.scheme, authority, parsed.path or "", parsed.query, ""))


def service_view(session: Any, ports: str = "") -> SimpleNamespace:
    """Срез сессии для host-модулей: services дополняются портами one-shot.

    Повторяет приём tech/dirb/sqli (локальный ports расширяет обнаруженные
    сервисы), но собран в одном месте, чтобы новые модули его переиспользовали.
    """
    services = dict(getattr(session, "services", {}) or {})
    if ports:
        from utils.net import parse_ports

        for port in parse_ports(str(ports)):
            services[port] = {"name": "https" if port in TLS_PORTS else "http"}
    return SimpleNamespace(
        target=getattr(session, "target", None), services=services,
        params=getattr(session, "params", {}), loot=getattr(session, "loot", []),
    )


def web_urls(session: Any, url: str | None = None) -> list[str]:
    """Возвращает URL обнаруженных HTTP-сервисов или явно заданный URL."""
    if url:
        return [normalize_url(url)]
    target = str(getattr(session, "target", "") or "").strip()
    if not target:
        raise ValueError("Set target before running a web module")
    if "://" in target:
        return [normalize_url(target)]
    base = normalize_url(target)
    if urlsplit(base).port is not None:
        return [base]

    discovered: list[str] = []
    for raw_port, service in sorted(
        getattr(session, "services", {}).items(), key=lambda entry: int(entry[0])
    ):
        port = int(raw_port)
        name = str(service.get("name", "")).lower()
        if port not in WEB_PORTS and "http" not in name:
            continue
        scheme = "https" if port in TLS_PORTS or "https" in name else "http"
        parsed = urlsplit(base)
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        authority = host if (scheme, port) in {("http", 80), ("https", 443)} else f"{host}:{port}"
        discovered.append(urlunsplit((scheme, authority, parsed.path, parsed.query, "")))
    return list(dict.fromkeys(discovered)) or [base]


class WebClient:
    """Переиспользует соединения; proxy из окружения по умолчанию отключены."""

    def __init__(
        self,
        timeout: float = 5,
        retries: int = 1,
        follow_redirects: bool = True,
        verify: bool = True,
        *,
        headers: dict[str, str] | None = None,
        trust_env: bool = False,
        transport: httpx.BaseTransport | None = None,
        recover_html: bool = True,
    ) -> None:
        self.timeout = float(timeout)
        self.retries = int(retries)
        self.recover_html = bool(recover_html)
        if self.timeout <= 0 or self.retries < 0:
            raise ValueError("timeout must be positive and retries must be non-negative")
        self._client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=follow_redirects,
            verify=verify,
            headers={**DEFAULT_HEADERS, **(headers or {})},
            trust_env=trust_env,
            transport=transport,
        )

    def __enter__(self) -> WebClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _complete_html(self, response: httpx.Response, body: bytes) -> bool:
        """Допускает только малую ошибку длины у полностью полученной HTML-страницы."""
        length = response.headers.get("content-length", "").strip()
        if not self.recover_html or not length.isascii() or not length.isdigit():
            return False
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "text/html" or response.headers.get("content-encoding"):
            return False
        # Chunked-ответы проверяет транспорт: их повреждение нельзя маскировать.
        if response.headers.get("transfer-encoding"):
            return False
        gap = int(length) - len(body)
        return bool(body) and 1 <= gap <= 128 and body.rstrip().lower().endswith(b"</html>")

    @staticmethod
    def _buffered_response(response: httpx.Response, body: bytes) -> httpx.Response:
        """Пересоздаёт прочитанный ответ, сохраняя метаданные и HTTP-декодирование."""
        buffered = httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=httpx.ByteStream(body),
            request=response.request,
            history=response.history,
            extensions=response.extensions,
            default_encoding=response.default_encoding,
        )
        buffered.read()
        buffered.next_request = response.next_request
        try:
            buffered.elapsed = response.elapsed
        except RuntimeError:
            pass
        return buffered

    def _request_once(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        with self._client.stream(method, url, **kwargs) as response:
            # MockTransport также может вернуть уже прочитанный ответ.
            if response.is_stream_consumed:
                return response
            chunks: list[bytes] = []
            try:
                for chunk in response.iter_raw():
                    chunks.append(chunk)
            except (httpx.ReadTimeout, httpx.RemoteProtocolError) as exc:
                body = b"".join(chunks)
                if not self._complete_html(response, body):
                    raise
                response.close()
                buffered = self._buffered_response(response, body)
                buffered.extensions["squ2ak_html_framing_recovered"] = True
                logger.warning(
                    "Recovered complete HTML after malformed HTTP framing: %s %s "
                    "status=%s received=%s declared=%s error=%s",
                    method.upper(), response.url, response.status_code, len(body),
                    response.headers["content-length"], type(exc).__name__,
                )
                return buffered
            return self._buffered_response(response, b"".join(chunks))

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self.retries + 1):
            try:
                # Коды 4xx/5xx нужны сканерам как данные, не как исключения.
                return self._request_once(method, url, **kwargs)
            except httpx.RequestError as exc:
                if attempt >= self.retries:
                    raise WebRequestError(
                        f"{method.upper()} {url}: {type(exc).__name__}: {exc}"
                    ) from exc
                time.sleep(min(0.15 * 2**attempt, 2.0))
            except (httpx.InvalidURL, ValueError) as exc:
                raise WebRequestError(f"Invalid HTTP request: {exc}") from exc
        raise WebRequestError("HTTP retries exhausted")

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)
