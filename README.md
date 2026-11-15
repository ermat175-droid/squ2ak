# squ2ak

[![CI](https://github.com/ermat175-droid/squ2ak/actions/workflows/ci.yml/badge.svg)](https://github.com/ermat175-droid/squ2ak/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-224-brightgreen)

A console security-testing framework in Python 3.11+: an `msfconsole`-style REPL,
modular checks, YAML templates and a conditional auto-pipeline. Detection is built
around low false positives — baseline comparison, content markers and proof of
execution (arithmetic echo, time-based blind) rather than blind signature matching.

Built as a personal learning and portfolio project.

> ## ⚠️ Authorized use only
> This tool sends active probes (directory brute-force, SQLi/LFI/command-injection
> payloads, auth checks) to the targets you point it at. Run it **only** against
> systems you own or are **explicitly authorized** to test — your own labs, CTF
> targets, or engagements with written permission. Unauthorized scanning and
> exploitation is illegal in most jurisdictions. You are responsible for how you
> use it. The author assumes no liability for misuse or damage.

## Features

- **REPL** — `use`/`set`/`run` workflow, tab-completion, persistent history, Python context.
- **20 modules** across recon, web, misc and YAML templates (see [Modules](#modules)).
- **Auto-pipeline** — a boolean condition engine (`not`/`and`/`or`) chains modules
  based on what has already been discovered (open ports, services, prior findings, loot).
- **Concurrency** — parameter and path checks run in parallel (`threads`, 1–64)
  with clean `Ctrl+C` cancellation.
- **Reporting** — Markdown / JSON reports from the session snapshot, sorted by severity,
  written automatically at the end of an auto run.
- **Low false positives** — findings require deterministic evidence (reflected markers,
  arithmetic proof of execution, baseline-vs-payload divergence).

## Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
chmod +x squ2ak
./squ2ak
```

The launcher prefers a local `.venv` and resolves through symlinks, so it also works
from `~/.local/bin/squ2ak`. Paths to config, templates and the starter wordlist are
anchored to the project directory, so it can be launched from anywhere.

Optional: SYN scanning needs Scapy (`requirements-optional.txt`). Without root the
scanner falls back to TCP connect with a warning; `--scan connect` forces TCP even as root.

```bash
.venv/bin/python -m pip install scapy==2.8.0
sudo .venv/bin/python squ2ak.py --target 10.10.10.5 --module recon/portscan --ports 1-1024
```

## One-shot (CLI)

```bash
./squ2ak --target 10.10.10.5 --module recon/portscan --ports 80,443,8000-8100
./squ2ak --target 10.10.10.5 --module web/tech --url http://10.10.10.5:8080
./squ2ak --target 10.10.10.5 --module web/dirb --wordlist wordlists/common.txt --threads 16
./squ2ak --target 10.10.10.5 --module web/sqli --url 'http://10.10.10.5/item?id=1'
./squ2ak --target 10.10.10.5 --module web/lfi --url 'http://10.10.10.5/view?page=index'
./squ2ak --target 10.10.10.5 --module misc/redis_unauth --port 6379
./squ2ak --list-modules
./squ2ak --help
```

Any active-module option is passed as `--name value` or `--name=value`; booleans as
`--verify false`. Unknown options error out. `--set KEY=VALUE` sets a global value
(repeatable). Exit codes: `0` finished, `1` error/invalid params, `2` CLI argument
error, `130` interrupted module. No findings is a normal result.

A one-shot starts a fresh session — results from a previous process are not loaded.
To reuse discovered ports across stages, use the REPL or auto mode.

## REPL

```text
set target 10.10.10.5
setg timeout 2
setg ports 21,22,80,443,6379,8080
use recon/portscan
run
use web/dirb
set threads 16
run
sessions
loot
report
exit
```

| Command | Action |
| --- | --- |
| `help` | List commands |
| `show modules` | category / name / description table |
| `use category/name` | Select a module |
| `set param value` | Local option; with no active module, a session param |
| `setg param value` | Global option, inherited by modules |
| `show options` | Values, required, and source: local/global/default/session |
| `run`, `exploit` | Run the active module |
| `back` | Deselect the module |
| `sessions` | Target, services, params, findings and loot |
| `loot` | Collected data |
| `report [path] [md\|json\|both]` | Write a report |
| `python code` | Python in the session context |
| `auto`, `auto step`, `auto full` | Run the pipeline (paused / unpaused) |
| `auto from module/path` | Start from a stage |
| `auto list` | Stage table |
| `clear`, `exit` | Clear screen / quit |

Tab completes commands, module paths and parameter names. History is saved in
`~/.squ2ak/history`. `Ctrl+C` cancels input or the running module and returns to the
REPL; in-flight network requests finish on their own timeout, new work is cancelled.

Parameter precedence: local `set` → global `setg`/config → default. `target` is always
shared. Changing the target clears services, findings, loot, check counters and any
target-bound `url`/`urls`.

## Auto

```bash
./squ2ak --target 10.10.10.5 --auto full --ports 21,22,80,443,6379
./squ2ak --target 10.10.10.5 --auto step
./squ2ak --config ./config.full.yaml --target 10.10.10.5 --auto full
```

The default chain in `config.yaml`: portscan → banner → tech → dirb → SQLi → LFI →
templates → FTP → Redis. `config.full.yaml` is a broader example that runs every web
module. Each stage prints its number and condition; a failure, invalid params or a
missing module is logged and the pipeline continues. A `SUMMARY` is printed at the
end, including after `q`/`Ctrl+C`. When auto finishes it prints an **Auto results**
table: stage, status, new findings, highest severity and time.

In step mode, after each stage:

```text
[Enter] continue  [s] skip next  [q] quit auto  >
```

| Condition | Meaning |
| --- | --- |
| `always` | Always |
| `has_web` | 80/443/8000/8080/8443/3000/5000 detected |
| `has_service:ftp` | Substring `ftp` in a detected service name (case-insensitive) |
| `has_open_port:6379` | Port present in `session.services` |
| `has_finding:sql` | Substring in the title or module of any finding |
| `has_loot:url` | Loot of the given type exists |
| `root` | `os.geteuid() == 0` |

Conditions combine with `not`, `and`, `or` (precedence `not` → `and` → `or`), e.g.
`has_service:http and not has_finding:waf`, so a stage can depend on what was already
found. A stage may carry its own `options`/`auto_params`:

```yaml
auto_pipeline:
  - module: recon/portscan
    condition: always
    options:
      ports: "22,8088"
      scan: connect
  - module: web/sqli
    condition: has_open_port:8088
    auto_params:
      crawl: true
      max_urls: 20
```

`options` takes precedence over `auto_params` on name clashes. Remove stages from your
own config to exclude them.

## Modules

| Module | Check |
| --- | --- |
| `recon/portscan` | TCP/SYN, lists/ranges, concurrency, IPv4/IPv6 |
| `recon/banner` | Banners and HTTP HEAD; OpenSSH/nginx/Apache/FTP/Redis/IIS versions |
| `recon/dns` | A, AAAA, MX, TXT, NS; time-boxed AXFR attempt |
| `web/tech` | Headers, cookies, HTML and JS fingerprinting: Angular/React/Vue/CMS |
| `web/dirb` | 500 paths, redirects, soft-404 filtering, directory recursion |
| `web/sqli` | GET/POST, explicit param or crawled links/forms, SQL errors + stable boolean pair |
| `web/lfi` | GET/POST, explicit param or crawl, passwd/win.ini/PHP base64/environ |
| `web/cmdi` | GET/POST, proof of execution via echo arithmetic + time-based blind (sleep) |
| `web/xss` | GET/POST, reflected XSS: verbatim reflection of a context-breaking marker in HTML |
| `web/open_redirect` | GET/POST, param redirects `Location`/client-side to an external host |
| `web/secheaders` | CSP/HSTS/XCTO/clickjacking/Referrer/Permissions audit, cookie flags, version leaks |
| `web/cors` | Reflected foreign Origin, `null` trust, wildcard, credentials |
| `web/exposure` | Exposed `.git`/`.env`/`.svn`/backups/phpinfo/server-status with content validation |
| `web/graphql` | GraphQL endpoints and enabled schema introspection |
| `web/http_methods` | Dangerous methods (PUT/DELETE/TRACE/CONNECT) via OPTIONS and XST via TRACE |
| `web/ssti` | GET/POST, SSTI expression-evaluation proof (jinja2/twig/freemarker/erb/razor) |
| `web/jwt` | Harvest JWTs (token, Set-Cookie, body, loot); flag `alg=none`, brute weak HMAC secret |
| `misc/ftp_anon` | Anonymous login without uploading/altering files |
| `misc/redis_unauth` | PING, INFO, CONFIG GET dir without modifying Redis |
| `templates/runner` | Validated YAML HTTP checks |

Web modules take a `url`; otherwise they use discovered HTTP ports. Parametric modules
(`sqli`, `lfi`, `cmdi`, `xss`, `ssti`, `open_redirect`) and `exposure` test candidates
in parallel (`threads`, 1–64). `web/dirb` with `recursion true` repeats the wordlist in
discovered directories up to `recursion_depth` levels.

### Reporting

```bash
./squ2ak --config config.full.yaml --target 10.10.10.5 --auto full --report scan-10.10.10.5 --report-format both
```

REPL command `report [path] [md|json|both]` or CLI flags `--report PATH
--report-format md|json|both`. Findings are sorted by severity (critical→info). When
`auto` finishes (REPL and CLI) a report is written automatically next to the logs at
`$SQU2AK_HOME/reports/report-<target>-<timestamp>.md`. Disable with the session param
`auto_report: false`; an explicit `--report` overrides the auto report.

### SQLi / LFI crawling

Both take a base `url` without a payload. `param` adds or replaces just that parameter;
`method` picks GET/POST. Without `param`, crawling collects parameters from the URL, a
global `urls` list, loot, links and HTML forms on the same target. `crawl=false`
disables crawling but still tests the given URLs. `max_urls`/`max_depth`/`max_parameters`
bound the crawl; `payloads_file` (UTF-8, one per line) replaces the built-in set.
Browser JavaScript is not executed: an SPA with no links/forms may yield zero
candidates — point at the API URL and set `param` explicitly.

## YAML templates

```yaml
id: cve-2021-41773
info:
  name: Apache Path Traversal
  severity: high
requests:
  - method: GET
    path: "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["root:x:0:0"]
```

```bash
./squ2ak --target 10.10.10.5 --module templates/runner --templates ./my-check.yaml
```

`path` is a string or list. Supports word/status/regex matchers, `condition: and|or`
inside a matcher, `matchers-condition` between matchers, `part: body|header|all`,
`negative`, `case-insensitive`, request headers and body. `{{BaseURL}}` substitution is
allowed at the start of a path. YAML is parsed via `safe_load` + Pydantic; empty
matchers, unknown fields, external addresses in `path` and invalid regex are rejected.
This is a limited subset, not the full nuclei syntax.

## Extending

Add a Python file under `modules/<category>/` and subclass `BaseModule`:

```python
from core.module_base import BaseModule
from utils import renderer

class Example(BaseModule):
    category = "misc"
    name = "example"
    description = "Example module"
    options = {"message": {"default": "hello", "required": True,
                           "description": "Text to print"}}

    def run(self):
        renderer.print_info(self.get_option("message"))
        self.session.add_loot("note", self.get_option("message"), self.path)
```

`target` and `timeout` are added automatically. Validation runs in a shared dispatcher
before `run`. `add_service`, `add_finding`, `add_loot` are available. Registration
happens on the next run; an import error in one file does not break the others.

## Logs and testing

Each run writes `~/.squ2ak/sessions/<timestamp>.log` (CLI command, REPL commands, rich
output without ANSI, Python prints, errors and tracebacks). Use `SQU2AK_HOME=/tmp/squ2ak`
for a different directory. Log files are `0600`; the directory and history are private.

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Tests use mocked sockets/HTTP/DNS/Scapy and local servers on `127.0.0.1` — no external
targets are needed. 224 tests pass on Python 3.11 and 3.12. (A few integration tests
spawn the launcher and need `requirements.txt` installed in a local `.venv`.)

## License

[MIT](LICENSE) © ermat175-droid
