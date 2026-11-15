"""Сбор и анализ JWT: alg=none и слабый HMAC-секрет (офлайн-брут).

Токены берутся из опции token, из Set-Cookie и тела веб-ответов, а также из
loot/params сессии. Для каждого проверяется небезопасный alg=none и, для HS*,
подбирается секрет по встроенному и пользовательскому словарю.
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
from pathlib import Path

from core.module_base import BaseModule
from utils import renderer
from utils.web import WebClient, WebRequestError, service_view, web_urls

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
DEFAULT_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "key", "jwt", "token",
    "secretkey", "your-256-bit-secret", "s3cr3t", "supersecret", "test", "root",
    "qwerty", "letmein", "default", "private", "signature", "jwtsecret",
]


def _b64url(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


class JwtModule(BaseModule):
    name = "jwt"
    category = "web"
    description = "Сбор JWT и анализ: alg=none и слабый HMAC-секрет"
    options = {
        "url": {"default": "", "required": False, "description": "URL для сбора токенов из Set-Cookie/тела"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot"},
        "token": {"default": "", "required": False, "description": "Явные JWT через пробел/запятую"},
        "wordlist": {"default": "", "required": False, "description": "Словарь секретов для HS*-брута"},
        "max_tokens": {"default": 20, "required": False, "description": "Максимум анализируемых токенов"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
    }

    def run(self):
        rows = []
        secrets_list = self._load_secrets()
        tokens = self._collect_tokens()
        for token in tokens:
            result = self._analyze(token, secrets_list)
            if not result:
                continue
            severity, note, alg = result
            short = token[:24] + "…" if len(token) > 24 else token
            rows.append((short, alg, severity, note))
            self.session.add_finding(f"JWT: {note}", self.session.target or "jwt", severity=severity,
                                     alg=alg, token=token, note=note, module=self.path)
            if severity != "info":
                self.session.add_loot("jwt", token, note)
        renderer.print_table("JWT analysis", ["Token", "Alg", "Severity", "Note"], rows)
        renderer.print_info(f"Проанализировано токенов: {len(tokens)}, находок: {sum(1 for r in rows if r[2] != 'info')}")

    def _load_secrets(self):
        secrets_list = list(DEFAULT_SECRETS)
        value = str(self.get_option("wordlist") or "")
        if value:
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = self.project_dir / path
            if path.stat().st_size > 5 * 1024 * 1024:
                raise ValueError("Словарь секретов превышает 5MiB")
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    secrets_list.append(line)
        return list(dict.fromkeys(secrets_list))[:100_000]

    def _collect_tokens(self):
        limit = max(1, min(1000, int(self.get_option("max_tokens"))))
        found: list[str] = []

        def add(text):
            for match in JWT_RE.findall(str(text)):
                if match not in found:
                    found.append(match)

        for chunk in re.split(r"[\s,]+", str(self.get_option("token") or "")):
            if chunk:
                add(chunk)
        for item in getattr(self.session, "loot", []):
            add(item.get("value", "") if isinstance(item, dict) else item)
        for value in getattr(self.session, "params", {}).values():
            add(value)

        view = service_view(self.session, self.get_option("ports"))
        url_option = self.get_option("url") or None
        if url_option or any("http" in str(info.get("name", "")).lower() for info in view.services.values()) or view.services:
            try:
                with WebClient(timeout=float(self.get_option("timeout")), verify=self.get_option("verify")) as client:
                    for url in web_urls(view, url_option):
                        try:
                            response = client.get(url if url.count("/") > 2 else url.rstrip("/") + "/")
                        except WebRequestError as exc:
                            renderer.print_warn(str(exc))
                            continue
                        for cookie in response.headers.get_list("set-cookie"):
                            add(cookie)
                        add(response.text[:500_000])
            except WebRequestError as exc:
                renderer.print_warn(str(exc))
        return found[:limit]

    def _analyze(self, token, secrets_list):
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(_b64url(parts[0]))
        except (binascii.Error, ValueError, json.JSONDecodeError):
            return None
        alg = str(header.get("alg", "")).strip()
        if alg.lower() == "none":
            return "high", "accepts unsigned token (alg=none)", alg or "none"
        if alg.upper() in HASHES:
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            try:
                signature = _b64url(parts[2])
            except (binascii.Error, ValueError):
                return "info", f"JWT with {alg}, signature unreadable", alg
            digest = HASHES[alg.upper()]
            for secret in secrets_list:
                candidate = hmac.new(secret.encode(), signing_input, digest).digest()
                if hmac.compare_digest(candidate, signature):
                    return "high", f"weak HMAC secret: {secret!r}", alg
            return "info", f"JWT with {alg}, secret not in wordlist", alg
        return "info", f"JWT with alg={alg or 'unknown'}", alg or "unknown"


Jwt = JwtModule
