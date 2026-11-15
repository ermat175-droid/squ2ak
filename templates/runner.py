"""Выполнение небольших nuclei-style YAML-шаблонов."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Literal
from urllib.parse import urlsplit

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.module_base import BaseModule
from utils import renderer
from utils.web import WebClient, WebRequestError, web_urls


logger = logging.getLogger("squ2ak." + __name__)


class TemplateInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    description: str = ""


class Matcher(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    type: Literal["word", "status", "regex"]
    words: list[str] = Field(default_factory=list)
    status: list[int] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    condition: Literal["and", "or"] = "or"
    part: Literal["body", "header", "all"] = "body"
    negative: bool = False
    case_insensitive: bool = Field(default=False, alias="case-insensitive")

    @model_validator(mode="after")
    def validate_content(self) -> Matcher:
        values = {"word": self.words, "status": self.status, "regex": self.regex}[self.type]
        if not values:
            raise ValueError(f"Matcher {self.type} requires a non-empty value list")
        if any(not str(value).strip() for value in values):
            raise ValueError("Matcher values must not be empty")
        if self.type == "status" and any(code < 100 or code > 599 for code in self.status):
            raise ValueError("HTTP status matcher must be between 100 and 599")
        if self.type == "regex":
            for pattern in self.regex:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(f"Invalid matcher regex: {exc}") from exc
        return self

    def matches(self, response: httpx.Response) -> bool:
        header_text = "\n".join(f"{name}: {value}" for name, value in response.headers.items())
        text = {
            "body": response.text,
            "header": header_text,
            "all": header_text + "\n\n" + response.text,
        }[self.part]
        if self.type == "word":
            words = self.words
            if self.case_insensitive:
                text, words = text.casefold(), [word.casefold() for word in words]
            results = [word in text for word in words]
        elif self.type == "status":
            results = [response.status_code == status for status in self.status]
        else:
            flags = re.IGNORECASE if self.case_insensitive else 0
            results = [bool(re.search(pattern, text, flags)) for pattern in self.regex]
        matched = all(results) if self.condition == "and" else any(results)
        return not matched if self.negative else matched


class TemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] = "GET"
    path: list[str]
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    matchers: list[Matcher] = Field(min_length=1)
    matchers_condition: Literal["and", "or"] = Field(default="or", alias="matchers-condition")

    @field_validator("path", mode="before")
    @classmethod
    def normalize_paths(cls, value: object) -> object:
        return [value] if isinstance(value, str) else value

    @field_validator("path")
    @classmethod
    def validate_paths(cls, value: list[str]) -> list[str]:
        if not value or any(not path.strip() for path in value):
            raise ValueError("Request path list must not be empty")
        for path in value:
            _validate_request_path(path)
        return value

    def matches(self, response: httpx.Response) -> bool:
        matches = [matcher.matches(response) for matcher in self.matchers]
        return all(matches) if self.matchers_condition == "and" else any(matches)


class Template(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1)
    info: TemplateInfo
    requests: list[TemplateRequest] = Field(min_length=1)


def load_template(path: Path) -> Template:
    # safe_load не позволяет YAML создавать произвольные Python-объекты.
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Template exceeds the 1 MiB size limit")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Template.model_validate(data)


def template_url(base_url: str, path: str) -> str:
    """Сохраняет traversal-последовательности; urljoin здесь не подходит."""
    _validate_request_path(path)
    parsed = urlsplit(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if path.startswith("{{BaseURL}}"):
        return path.replace("{{BaseURL}}", base_url.split("?", 1)[0].rstrip("/"), 1)
    if path.startswith("/"):
        return origin + path
    return base_url.split("?", 1)[0].rstrip("/") + "/" + path


def _validate_request_path(path: str) -> None:
    clean = path
    if "{{BaseURL}}" in path:
        if not path.startswith("{{BaseURL}}") or path.count("{{BaseURL}}") != 1:
            raise ValueError("BaseURL must appear once at the beginning of a path")
        clean = path[len("{{BaseURL}}") :]
        # Суффикс @host способен поменять адрес назначения через URL userinfo.
        if clean and not clean.startswith(("/", "?")):
            raise ValueError("BaseURL suffix must begin with / or ?")
    if any(character in clean for character in ("\r", "\n", "\x00")):
        raise ValueError("Control characters are not allowed in request paths")
    if "://" in clean or clean.startswith("//"):
        raise ValueError("Template paths must stay on the selected target")


class TemplateRunner(BaseModule):
    name = "runner"
    category = "templates"
    description = "Run validated YAML HTTP checks with word/status/regex matchers"
    options = {
        "target": {"default": None, "required": True, "description": "Target IP, hostname or HTTP URL"},
        "url": {"default": None, "required": False, "description": "Override the discovered web URL"},
        "templates": {"default": "templates/examples", "required": True, "description": "YAML file or directory, relative to project root"},
        "timeout": {"default": 5, "required": True, "description": "HTTP timeout in seconds"},
        "retries": {"default": 1, "required": False, "description": "Retry count after a network error"},
        "verify": {"default": True, "required": False, "description": "Verify HTTPS certificates"},
    }

    def run(self) -> None:
        template_path = Path(str(self.get_option("templates"))).expanduser()
        if not template_path.is_absolute():
            template_path = Path(self.project_dir) / template_path
        if not template_path.exists():
            raise FileNotFoundError(f"Template path does not exist: {template_path}")
        if template_path.is_file():
            paths = [template_path]
        else:
            paths = sorted({*template_path.rglob("*.yaml"), *template_path.rglob("*.yml")})
        if not paths:
            raise ValueError(f"No YAML templates found in {template_path}")
        session_view = SimpleNamespace(target=self.get_option("target"), services=self.session.services)
        urls = web_urls(session_view, self.get_option("url"))
        matches: list[tuple[str, str, str, str]] = []
        valid_templates = 0
        completed_requests = 0
        with WebClient(
            timeout=float(self.get_option("timeout")),
            retries=int(self.get_option("retries")),
            verify=_as_bool(self.get_option("verify")),
        ) as client:
            for path in paths:
                try:
                    template = load_template(path)
                except Exception as exc:
                    logger.exception("Invalid template %s", path)
                    renderer.print_error(f"Invalid template {path.name}: {exc}")
                    continue
                renderer.print_info(f"Template {template.id}: {template.info.name}")
                valid_templates += 1
                for base_url in urls:
                    for request in template.requests:
                        for request_path in request.path:
                            url = template_url(base_url, request_path)
                            try:
                                response = client.request(
                                    request.method, url, headers=request.headers, content=request.body,
                                )
                                completed_requests += 1
                                if not request.matches(response):
                                    continue
                                source = str(response.url)
                                self.session.add_finding(
                                    template.info.name, source, severity=template.info.severity,
                                    template_id=template.id, status=response.status_code,
                                )
                                self.session.add_loot("finding", f"{template.id}: {template.info.name}", source)
                                matches.append((template.id, template.info.severity, template.info.name, source))
                                renderer.print_success(f"[{template.info.severity}] {template.info.name}: {source}")
                            except WebRequestError as exc:
                                logger.warning("Template %s request failed: %s", template.id, exc)
                                renderer.print_warn(str(exc))
                            except Exception as exc:
                                logger.exception("Template %s failed at %s", template.id, url)
                                renderer.print_error(f"Template {template.id}: {exc}")
        if not valid_templates:
            raise ValueError("No valid YAML templates were loaded")
        if not completed_requests:
            raise RuntimeError("All template requests failed")
        if matches:
            renderer.print_table("Template findings", ["ID", "Severity", "Name", "URL"], matches)
        else:
            renderer.print_info("No template match found")


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}
