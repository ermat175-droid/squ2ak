"""Общие кандидаты SQLi/LFI: ссылки и формы того же HTTP-сервиса."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup
import httpx

from utils import renderer
from utils.web import WebClient, WebRequestError, normalize_url, web_urls


def _origin(url: str) -> tuple[str, str | None, int]:
    parsed = urlsplit(url)
    return (
        parsed.scheme.lower(),
        parsed.hostname,
        parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
    )


def _with_query(url: str, params: list[tuple[str, str]]) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(params), ""))


def _normalize(url: str) -> str:
    parsed = urlsplit(normalize_url(url))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


@dataclass
class Candidate:
    """Один запрос; индексы полей сохраняют повторяющиеся имена параметров."""

    url: str
    method: str = "GET"
    params: list[tuple[str, str]] = field(default_factory=list)
    source: str = "link"

    def __post_init__(self) -> None:
        self.url = _normalize(self.url)
        self.method = self.method.upper()
        if self.method not in {"GET", "POST"}:
            raise ValueError("Candidate supports GET and POST only")
        self.params = [(str(name), str(value)) for name, value in self.params]
        if self.method == "GET":
            if not self.params:
                self.params = parse_qsl(urlsplit(self.url).query, keep_blank_values=True)
            self.url = _with_query(self.url, self.params)

    @property
    def key(self) -> tuple[str, str, tuple[tuple[str, str], ...]]:
        return self.url, self.method, tuple(self.params)

    def send(
        self, client: WebClient, index: int | None = None, value: str | None = None
    ) -> httpx.Response:
        fields = list(self.params)
        if index is not None:
            if value is None:
                raise ValueError("Replacement value is required")
            name, _ = fields[index]
            fields[index] = (name, value)
        if self.method == "GET":
            return client.get(_with_query(self.url, fields))
        # httpx data=list[tuple] неоднозначен; urlencode сохраняет дубликаты.
        return client.request(
            "POST", self.url, content=urlencode(fields),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )


def _form_fields(form: Any) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    for control in form.find_all(["input", "select", "textarea"]):
        name = control.get("name")
        if not name or control.has_attr("disabled"):
            continue
        if control.name == "input":
            kind = str(control.get("type", "text")).lower()
            if kind in {"submit", "button", "reset", "image", "file"}:
                continue
            # Поле нужно для валидной формы; готовый пароль из HTML не используем.
            if kind == "password":
                fields.append((str(name), ""))
                continue
            if kind in {"checkbox", "radio"} and not control.has_attr("checked"):
                continue
            default = "on" if kind in {"checkbox", "radio"} else ""
            fields.append((str(name), str(control.get("value", default))))
        elif control.name == "textarea":
            fields.append((str(name), control.get_text()))
        else:
            options = [option for option in control.find_all("option")
                       if not option.has_attr("disabled")]
            selected = [option for option in options if option.has_attr("selected")]
            if not selected and options and not control.has_attr("multiple"):
                selected = options[:1]
            if not control.has_attr("multiple"):
                selected = selected[:1]
            fields.extend((str(name), str(option.get("value", option.get_text())))
                          for option in selected)
    return fields


def collect_candidates(
    session: Any,
    client: WebClient,
    url: str | None = None,
    param: str | None = None,
    method: str = "GET",
    crawl: bool = True,
    max_urls: int = 10,
    max_depth: int = 1,
    lfi_names: set[str] | list[str] | tuple[str, ...] | None = None,
) -> list[Candidate]:
    """Собирает наблюдаемые запросы, не угадывая API и имена параметров."""
    limit = max(1, min(1000, int(max_urls)))
    depth_limit = max(0, min(5, int(max_depth)))
    method = str(method).upper()
    if method not in {"GET", "POST"}:
        raise ValueError("method must be GET or POST")
    bases = [_normalize(base) for base in web_urls(session, url or None)]
    allowed = {_origin(base) for base in bases}
    names = None if lfi_names is None else {str(name).lower() for name in lfi_names}
    candidates: list[Candidate] = []
    seen_candidates: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()

    def safe_url(value: str, base: str | None = None) -> str | None:
        try:
            joined = urljoin(base, str(value).strip()) if base else str(value).strip()
            parsed = urlsplit(joined)
            if parsed.scheme.lower() not in {"http", "https"}:
                return None
            result = _normalize(joined)
            return result if _origin(result) in allowed else None
        except (ValueError, TypeError):
            return None

    def add(candidate: Candidate) -> None:
        if not candidate.params or len(candidates) >= limit:
            return
        if names is not None and "*" not in names:
            if not any(name.lower() in names for name, _ in candidate.params):
                return
        if candidate.key not in seen_candidates:
            seen_candidates.add(candidate.key)
            candidates.append(candidate)

    if param:
        # Явный параметр работает и на URL без query, без лишнего обхода.
        for base in bases:
            query = parse_qsl(urlsplit(base).query, keep_blank_values=True)
            values = [value for name, value in query if name == param]
            if method == "GET":
                fields = query if values else query + [(str(param), "test")]
            else:
                fields = [(str(param), value) for value in values] or [(str(param), "test")]
            add(Candidate(base, method, fields, "parameter"))
        return candidates

    seeds = list(bases)
    configured = getattr(session, "params", {}).get("urls", [])
    if isinstance(configured, str):
        configured = configured.split()
    if not isinstance(configured, (list, tuple)):
        configured = []
    configured = list(configured)
    configured_url = getattr(session, "params", {}).get("url")
    if isinstance(configured_url, str) and configured_url:
        configured.append(configured_url)
    discovered = [item.get("value") for item in getattr(session, "loot", [])
                  if isinstance(item, dict) and item.get("type") == "url"]
    for raw_url in [*configured, *discovered]:
        if isinstance(raw_url, str):
            result = safe_url(raw_url)
            if result and result not in seeds:
                seeds.append(result)
    for seed in seeds:
        add(Candidate(seed, source="session"))
    if not crawl:
        return candidates

    queue = deque((seed, 0) for seed in seeds)
    visited: set[str] = set()
    requests_made = 0
    while queue and requests_made < limit and len(candidates) < limit:
        page_url, depth = queue.popleft()
        if page_url in visited:
            continue
        visited.add(page_url)
        requests_made += 1
        try:
            # Проверяем Location сами, чтобы не уходить на посторонний сервер.
            response = client.get(page_url, follow_redirects=False)
            response_url = safe_url(str(response.url))
            if not response_url:
                continue
            if response.status_code in {301, 302, 303, 307, 308}:
                redirected = safe_url(response.headers.get("location", ""), response_url)
                if redirected and redirected not in visited:
                    queue.appendleft((redirected, depth))
                continue
            soup = BeautifulSoup(response.text[:1_000_000], "html.parser")
            base_tag = soup.find("base", href=True)
            effective_base = safe_url(base_tag["href"], response_url) if base_tag else None
            effective_base = effective_base or response_url
            for anchor in soup.find_all("a", href=True):
                linked = safe_url(anchor["href"], effective_base)
                if not linked:
                    continue
                add(Candidate(linked))
                if depth < depth_limit and linked not in visited:
                    queue.append((linked, depth + 1))
            for form in soup.find_all("form"):
                action = safe_url(str(form.get("action", "")), effective_base)
                form_method = str(form.get("method", "GET")).upper()
                if not action or form_method not in {"GET", "POST"}:
                    continue
                fields = _form_fields(form)
                if form_method == "GET":
                    fields = parse_qsl(urlsplit(action).query, keep_blank_values=True) + fields
                add(Candidate(action, form_method, fields, "form"))
        except (WebRequestError, httpx.HTTPError, ValueError, TypeError) as exc:
            renderer.print_warn(f"Crawl {page_url}: {exc}")
    return candidates
