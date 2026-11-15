"""Технологии по заголовкам, HTML и статике той же цели."""

import re
from html.parser import HTMLParser
from types import SimpleNamespace
from urllib.parse import urljoin, urlsplit

from core.module_base import BaseModule
from utils import renderer
from utils.net import parse_ports
from utils.web import WebClient, WebRequestError, web_urls


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.generators = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        if tag == "meta" and attrs.get("name", "").lower() == "generator":
            self.generators.append(attrs.get("content", ""))


def _origin(url):
    parsed = urlsplit(url)
    return parsed.scheme.lower(), parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


class TechModule(BaseModule):
    name = "tech"
    category = "web"
    description = "Технологии по HTTP-заголовкам, HTML и JS"
    options = {
        "url": {"default": "", "required": False, "description": "URL; иначе веб-порты сессии"},
        "ports": {"default": "", "required": False, "description": "Веб-порты для one-shot, например 3000"},
        "verify": {"default": True, "required": False, "description": "Проверять HTTPS-сертификат"},
        "max_scripts": {"default": 6, "required": False, "description": "Максимум JS-файлов одной страницы"},
        "max_script_bytes": {"default": 524288, "required": False, "description": "Лимит анализируемого JS-файла"},
    }

    def run(self) -> None:
        rows = []
        services = dict(self.session.services)
        if self.get_option("ports"):
            for port in parse_ports(str(self.get_option("ports"))):
                services[port] = {"name": "https" if port in {443, 8443} else "http"}
        view = SimpleNamespace(target=self.session.target, services=services)
        max_scripts = max(0, min(20, self.get_option("max_scripts")))
        max_bytes = max(1, min(4 * 1024 * 1024, self.get_option("max_script_bytes")))
        with WebClient(timeout=self.get_option("timeout"), verify=self.get_option("verify")) as client:
            for url in web_urls(view, self.get_option("url") or None):
                if not urlsplit(url).path:
                    url += "/"
                try:
                    response = client.get(url)
                except WebRequestError as exc:
                    renderer.print_warn(str(exc))
                    continue
                found = dict(self.detect(response.headers, response.text))
                page = _Page()
                page.feed(response.text[:2_000_000])
                scripts = []
                for src in page.scripts:
                    script_url = urljoin(str(response.url), src)
                    if _origin(script_url) == _origin(url) and script_url not in scripts:
                        scripts.append(script_url)
                for script_url in scripts[:max_scripts]:
                    try:
                        script = client.get(script_url)
                        if script.status_code != 200 or _origin(str(script.url)) != _origin(url):
                            continue
                        text = script.content[:max_bytes].decode("utf-8", errors="replace")
                        for name, version in self.detect(script.headers, text):
                            found[name] = version or found.get(name, "")
                    except WebRequestError as exc:
                        renderer.print_warn(str(exc))
                parsed = urlsplit(str(response.url))
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                if parsed.hostname == urlsplit(url).hostname:
                    version = next((f"{name} {value}" for name, value in found.items()
                                    if name in {"nginx", "Apache", "OpenResty"} and value), "")
                    self.session.add_service(port, name=parsed.scheme, version=version,
                                             banner=response.headers.get("server", ""))
                for technology, version in sorted(found.items()):
                    rows.append((str(response.url), technology, version or "—"))
                    self.session.add_finding(f"Technology: {technology}{' ' + version if version else ''}",
                                             str(response.url), technology=technology, version=version)
                    self.session.add_loot("technology", {"name": technology, "version": version}, str(response.url))
                if not found:
                    rows.append((str(response.url), "Не определено", "—"))
        renderer.print_table("Web technologies", ["URL", "Technology", "Version"], rows)

    @staticmethod
    def detect(headers, body: str) -> list[tuple[str, str]]:
        headers = {str(key).lower(): str(value) for key, value in headers.items()}
        text = body[:2_000_000]
        result = {}
        for header in (headers.get("server", ""), headers.get("x-powered-by", "")):
            for name, expression in (
                ("nginx", r"\bnginx(?:/([\w.\-]+))?"),
                ("Apache", r"\bApache(?:/([\w.\-]+))?"),
                ("OpenResty", r"\bopenresty(?:/([\w.\-]+))?"),
                ("PHP", r"\bPHP(?:/([\w.\-]+))?"),
                ("Werkzeug/Flask", r"\bWerkzeug(?:/([\w.\-]+))?"),
                ("Express.js", r"\bExpress(?:/([\w.\-]+))?"),
                ("ASP.NET", r"\bASP\.NET(?:/([\w.\-]+))?"),
            ):
                match = re.search(expression, header, re.I)
                if match:
                    result[name] = match.group(1) or ""
        if re.search(r"(?:^|[;,\s])connect\.sid=", headers.get("set-cookie", ""), re.I):
            result.setdefault("Express.js", "")
        if headers.get("x-aspnet-version"):
            result["ASP.NET"] = headers["x-aspnet-version"]
        page = _Page()
        page.feed(text)
        for generator in page.generators:
            match = re.match(r"(.+?)\s+([\d][\w.\-]*)$", generator[:150])
            if generator:
                result[match.group(1) if match else generator[:150]] = match.group(2) if match else ""
        assets = " ".join(page.scripts)
        angular_bundles = all(re.search(r"(?:^|/)" + name + r"(?:[.\-][\w-]+)?\.js\b", assets)
                              for name in ("main", "polyfills"))
        if angular_bundles and ("<app-root" in text or re.search(r"(?:^|/)runtime[.\-\w]*\.js", assets)):
            result["Angular"] = ""
        markers = {
            "Angular": r"@angular/core|ɵcmp|ɵfac|\bng-version\s*=|\bng-app\b|(?:^|[/\"'])angular(?:[./\-]|\.min\.js)",
            "WordPress": r"wp-content/|wp-includes/",
            "Django": r"csrfmiddlewaretoken|__admin_media_prefix__",
            "Drupal": r"Drupal\.settings|drupalSettings|/sites/default/files/",
            "Joomla": r"/media/system/js/|/templates/[^/]+/.*joomla",
            "React": r"data-reactroot|react-dom|react(?:\.production|\.development)?(?:\.min)?\.js|react\.element",
            "Vue": r"data-v-[\da-f]{6,}|vue(?:\.runtime)?(?:\.min)?\.js|__vue__",
        }
        for name, expression in markers.items():
            if re.search(expression, text, re.I):
                result.setdefault(name, "")
        return list(result.items())


Tech = TechModule
