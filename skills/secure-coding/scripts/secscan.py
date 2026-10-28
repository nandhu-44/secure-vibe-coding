#!/usr/bin/env python3
"""SecureVibe scanner: a fast, dependency-free security linter for AI-generated code.

Usage:
  secscan.py [PATH ...] [--json] [--min-severity low|medium|high] [--fail-on high|medium|low|never]
             [--changed] [--with-external] [--rules DIR] [--list-rules]

It flags the mistakes coding agents make most often: hardcoded secrets, plaintext
endpoints, disabled TLS checks, injection sinks, weak crypto, insecure web config,
unsafe C APIs, unpinned CI/containers, and executing LLM output. Regex rules live in
rules/*.json. Python files also get an AST pass for fewer false positives.

Suppress a reviewed false positive with a comment on the same or the previous line:
  # securevibe: ignore[SV-NET-001] reason
Exit code: 1 if any finding is at or above --fail-on (default: high), else 0.
This is a guardrail, not a proof of security. Pair with review and semgrep/CodeQL.
"""
from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = {"low": 1, "medium": 2, "high": 3}
RULES_DIR = Path(__file__).resolve().parent / "rules"
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next", ".nuxt",
    "vendor", "target", ".tox", ".mypy_cache", ".pytest_cache", "coverage", ".terraform", "bower_components",
    ".idea", ".vscode", "site-packages", ".gradle", "Pods", ".cache", ".turbo", ".svelte-kit", "out",
}
LANG_EXT = {
    "py": {".py", ".pyw"},
    "js": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"},
    "go": {".go"},
    "java": {".java", ".kt", ".kts", ".scala", ".groovy"},
    "cs": {".cs"},
    "rb": {".rb", ".erb", ".rake"},
    "php": {".php"},
    "c": {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".m", ".mm", ".ino"},
    "rs": {".rs"},
    "sh": {".sh", ".bash", ".zsh", ".ps1"},
    "yaml": {".yml", ".yaml"},
    "json": {".json"},
    "tf": {".tf", ".hcl", ".tfvars"},
    "html": {".html", ".htm", ".jinja", ".jinja2", ".j2", ".ejs", ".hbs", ".njk", ".twig", ".liquid", ".cshtml", ".razor"},
    "conf": {".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".gradle", ".env"},
    "doc": {".md", ".txt", ".rst"},
}
GROUPS = {
    "code": {"py", "js", "go", "java", "cs", "rb", "php", "c", "rs", "sh"},
    "config": {"yaml", "json", "tf", "conf", "env", "dockerfile"},
}
TEXT_NAMES = {"Dockerfile", "Containerfile", "Makefile", "Jenkinsfile", "Procfile", "Gemfile", "Vagrantfile"}
# Line-comment prefixes per language. Non-secret rules skip comment lines (docs and URLs in comments are noise).
HASH_COMMENT = re.compile(r"^\s*#(?!!)")
SLASH_COMMENT = re.compile(r"^\s*(//|/\*|\*(?!/)|\*/)")
COMMENT_STYLES = {
    "py": HASH_COMMENT, "rb": HASH_COMMENT, "sh": HASH_COMMENT, "yaml": HASH_COMMENT, "tf": HASH_COMMENT,
    "conf": HASH_COMMENT, "dockerfile": HASH_COMMENT, "env": HASH_COMMENT,
    "js": SLASH_COMMENT, "go": SLASH_COMMENT, "java": SLASH_COMMENT, "cs": SLASH_COMMENT, "c": SLASH_COMMENT,
    "rs": SLASH_COMMENT, "php": SLASH_COMMENT,
    "html": re.compile(r"^\s*<!--"),
}
SUPPRESS_RE = re.compile(r"securevibe:\s*ignore(?:\[([A-Z0-9,\s-]+)\])?", re.I)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str
    cwe: str = ""
    owasp: str = ""
    fix: str = ""
    source: str = "securevibe"
    extra: dict = field(default_factory=dict)


def file_langs(path: Path) -> set[str]:
    name, suffix = path.name, path.suffix.lower()
    langs: set[str] = set()
    if name.startswith("Dockerfile") or name.startswith("Containerfile") or suffix == ".dockerfile":
        langs.add("dockerfile")
    if name == ".env" or name.startswith(".env."):
        langs.add("env")
    for lang, exts in LANG_EXT.items():
        if suffix in exts:
            langs.add(lang)
    parts = path.as_posix()
    if "yaml" in langs and "/.github/workflows/" in "/" + parts:
        langs.add("gha")
    return langs


def rule_applies(rule_langs: list[str], langs: set[str]) -> bool:
    for rl in rule_langs:
        if rl == "*":
            return bool(langs)
        if rl in GROUPS and langs & GROUPS[rl]:
            return True
        if rl in langs:
            return True
    return False


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def load_rules(rules_dir: Path) -> list[dict]:
    rules = []
    for p in sorted(rules_dir.glob("*.json")):
        pack = json.loads(p.read_text(encoding="utf-8"))
        for r in pack["rules"]:
            r["_compiled"] = [re.compile(x) for x in r["patterns"]]
            # one combined, multiline regex per rule: a cheap whole-file prefilter
            r["_any"] = re.compile("|".join(f"(?:{_strip_inline_flags(x)})" for x in r["patterns"]),
                                   re.M | (re.I if any(x.startswith("(?i)") for x in r["patterns"]) else 0))
            r["_unless"] = re.compile(r["unless"]) if r.get("unless") else None
            r["_pack"] = pack.get("pack", p.stem)
            rules.append(r)
    return rules


def _strip_inline_flags(pattern: str) -> str:
    return re.sub(r"\(\?P<\w+>", "(", pattern[4:] if pattern.startswith("(?i)") else pattern)


def is_comment(line: str, langs: set[str]) -> bool:
    return any(COMMENT_STYLES[l].match(line) for l in langs if l in COMMENT_STYLES)


def suppressed(lines: list[str], idx: int, rule_id: str) -> bool:
    for j in (idx, idx - 1):
        if 0 <= j < len(lines):
            m = SUPPRESS_RE.search(lines[j])
            if m and (not m.group(1) or rule_id in {x.strip().upper() for x in m.group(1).split(",")}):
                return True
    return False


def make_finding(rule: dict, path: str, lineno: int, line: str, **kw) -> Finding:
    return Finding(rule_id=rule["id"], title=kw.get("title", rule["title"]), severity=kw.get("severity", rule["severity"]),
                   file=path, line=lineno, snippet=line.strip()[:200], cwe=rule.get("cwe", ""),
                   owasp=rule.get("owasp", ""), fix=rule.get("fix", ""))


# ---------------------------------------------------------------- regex pass
def scan_regex(path: Path, display: str, text: str, lines: list[str], rules: list[dict], langs: set[str]) -> list[Finding]:
    out = []
    applicable = [r for r in rules if rule_applies(r["langs"], langs)]
    if "py" in langs:  # handled precisely by the AST pass
        applicable = [r for r in applicable if r["id"] not in {"SV-INJ-002", "SV-INJ-003"}]
    applicable = [r for r in applicable if r["_any"].search(text)]
    if not applicable:
        return out
    for i, line in enumerate(lines):
        if len(line) > 2000:  # minified bundles
            continue
        comment = is_comment(line, langs)
        for r in applicable:
            if comment and not r.get("comments"):
                continue
            for rx in r["_compiled"]:
                m = rx.search(line)
                if not m:
                    continue
                if r["_unless"] and r["_unless"].search(line):
                    break
                if r.get("min_entropy") and "val" in rx.groupindex:
                    if shannon_entropy(m.group("val") or "") < r["min_entropy"]:
                        break
                if suppressed(lines, i, r["id"]):
                    break
                out.append(make_finding(r, display, i + 1, line))
                break
    return out


# ---------------------------------------------------------------- python AST pass
SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "exec_driver_sql", "mogrify", "text", "extra"}
HTTP_LIBS = {"requests", "httpx"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}


def _is_const_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _is_dynamic_string(node: ast.AST) -> bool:
    """True when a string is assembled from non-constant parts (f-string, +, %, .format)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (_is_const_str(node.left) and _is_const_str(node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def scan_python_ast(display: str, text: str, lines: list[str], rules_by_id: dict) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    out = []

    def add(rule_id: str, node: ast.AST, **kw):
        r = rules_by_id.get(rule_id)
        if not r:
            return
        ln = getattr(node, "lineno", 1)
        if suppressed(lines, ln - 1, rule_id):
            return
        out.append(make_finding(r, display, ln, lines[ln - 1] if ln - 1 < len(lines) else "", **kw))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        short = name.rsplit(".", 1)[-1]
        first = node.args[0] if node.args else None
        kwargs = {k.arg: k.value for k in node.keywords if k.arg}

        if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and first is not None and not _is_const_str(first):
            add("SV-INJ-003", node)
        if name in {"os.system", "os.popen", "commands.getoutput", "os.popen2", "os.popen3"} and first is not None and not _is_const_str(first):
            add("SV-INJ-002", node)
        if name.startswith("subprocess.") and short in SUBPROCESS_FUNCS:
            shell = kwargs.get("shell")
            shell_true = isinstance(shell, ast.Constant) and shell.value is True
            if short in {"getoutput", "getstatusoutput"}:
                shell_true = True
            if shell_true and first is not None and not _is_const_str(first):
                add("SV-INJ-002", node)
            elif shell_true:
                add("SV-INJ-002", node, severity="low", title="shell=True with a constant command (prefer an argument list)")
        if short in SQL_METHODS and isinstance(node.func, ast.Attribute) and first is not None and _is_dynamic_string(first):
            add("SV-INJ-001", node)
        root = name.split(".", 1)[0]
        if root in HTTP_LIBS and short in HTTP_METHODS and "timeout" not in kwargs and name.count(".") == 1:
            add("SV-NET-003", node)
    return out


# ---------------------------------------------------------------- file-level checks
def scan_file_level(display: str, text: str, lines: list[str], langs: set[str], rules_by_id: dict) -> list[Finding]:
    out = []
    if "dockerfile" in langs and re.search(r"(?im)^\s*FROM\s", text) and not re.search(r"(?im)^\s*USER\s+(?!root\b|0\b)\S", text):
        r = rules_by_id.get("SV-INF-002")
        if r and "securevibe: ignore" not in text:
            out.append(make_finding(r, display, 1, lines[0] if lines else "", severity="low",
                                    title="Dockerfile has no non-root USER instruction"))
    if langs & {"py", "js", "go", "java", "rb", "php", "cs"} and not RATE_LIMIT_RE.search(text):
        m = AUTH_ROUTE_RE.search(text)
        r = rules_by_id.get("SV-WEB-009")
        if m and r:
            ln = text.count("\n", 0, m.start())
            if not suppressed(lines, ln, r["id"]):
                out.append(make_finding(r, display, ln + 1, lines[ln]))
    if "gha" in langs and "pull_request_target" in text and re.search(
            r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", text):
        r = rules_by_id.get("SV-CI-004")
        if r:
            ln = next((i for i, l in enumerate(lines) if "pull_request_target" in l), 0)
            out.append(make_finding(r, display, ln + 1, lines[ln]))
    return out


# Route registrations for credential/OTP endpoints in common frameworks.
AUTH_ROUTE_RE = re.compile(
    r"""(?ix)
    (\.(post|route|api_route|add_url_rule|HandleFunc|Handle|POST|Post)\s*\(\s*["'`][^"'`]*/
     |@(app|router|bp|blueprint|api)\.(post|route)\s*\(\s*["'][^"']*/
     |@(Post|Request)Mapping\s*\(\s*(value\s*=\s*)?["'][^"']*/
     |Route::post\s*\(\s*["'][^"']*/
     |\bpath\s*\(\s*["'][^"']*)
    (log-?in|sign-?in|signin|auth/token|token|otp|verify-?otp|2fa|mfa|forgot|password-?reset|reset-?password|register|sign-?up)\b""")
RATE_LIMIT_RE = re.compile(r"(?i)rate.?limit|limiter|throttl|slowapi|express-rate-limit|rate-limiter-flexible|Ratelimit|httprate|bucket4j|django-axes|RateLimiter")

BUILTIN_RULES = [
    {"id": "SV-NET-003", "title": "HTTP request without a timeout", "severity": "low", "cwe": "CWE-400", "owasp": "A06:2025",
     "fix": "Pass timeout= (e.g. timeout=10) so a slow or malicious server cannot hang workers.", "langs": [], "patterns": []},
    {"id": "SV-WEB-009", "title": "Authentication/OTP/reset endpoint with no rate limiting in this file", "severity": "medium",
     "cwe": "CWE-307", "owasp": "A07:2025", "langs": [], "patterns": [],
     "fix": "Rate-limit credential endpoints per IP and per account (e.g. 5 attempts / 15 min) with express-rate-limit, slowapi, "
            "flask-limiter, DRF throttles, Bucket4j or httprate. If limiting is applied elsewhere (gateway/middleware), suppress with a reason."},
    {"id": "SV-CI-004", "title": "pull_request_target workflow checks out untrusted PR code", "severity": "high", "cwe": "CWE-829",
     "owasp": "A03:2025", "fix": "Use pull_request instead, or never check out/execute PR head code in a pull_request_target job with secrets.",
     "langs": [], "patterns": []},
]


# ---------------------------------------------------------------- traversal
def iter_files(paths: list[str]):
    for p in paths:
        path = Path(p)
        if path.is_file():
            yield path
            continue
        if not path.is_dir():
            print(f"secscan: skipping missing path {p}", file=sys.stderr)
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
            for f in files:
                yield Path(root) / f


def changed_files() -> list[str]:
    try:
        tracked = subprocess.run(["git", "diff", "--name-only", "--diff-filter=ACMR", "HEAD"],
                                 capture_output=True, text=True, check=True, timeout=30).stdout.split()
        untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard"],
                                   capture_output=True, text=True, check=True, timeout=30).stdout.split()
    except (subprocess.SubprocessError, FileNotFoundError):
        print("secscan: --changed needs a git repository; scanning '.'", file=sys.stderr)
        return ["."]
    return sorted(set(tracked + untracked))


def scan_paths(paths: list[str], rules: list[dict]) -> list[Finding]:
    rules_by_id = {r["id"]: r for r in rules + BUILTIN_RULES}
    findings: list[Finding] = []
    for path in iter_files(paths):
        langs = file_langs(path)
        if not langs and path.name not in TEXT_NAMES:
            continue
        if path.resolve().parent == RULES_DIR:  # the rule packs themselves contain every pattern
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        display = path.as_posix()
        findings += scan_regex(path, display, text, lines, rules, langs)
        if "py" in langs:
            findings += scan_python_ast(display, text, lines, rules_by_id)
        findings += scan_file_level(display, text, lines, langs, rules_by_id)
    seen, unique = set(), []
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------- external tools
def run_external(paths: list[str]) -> tuple[list[Finding], list[str]]:
    findings, notes = [], []
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    if shutil.which("semgrep"):
        try:
            res = subprocess.run(["semgrep", "scan", "--config", os.environ.get("SECUREVIBE_SEMGREP_CONFIG", "p/default"),
                                  "--json", "--quiet", "--metrics", "off", *paths], capture_output=True, text=True, timeout=600)
            data = json.loads(res.stdout or "{}")
            for r in data.get("results", []):
                ex = r.get("extra", {})
                md = ex.get("metadata", {})
                cwe = md.get("cwe", "")
                findings.append(Finding(rule_id=r.get("check_id", "semgrep"), title=ex.get("message", "")[:160],
                                        severity=sev_map.get(ex.get("severity", "INFO"), "low"), file=r.get("path", ""),
                                        line=r.get("start", {}).get("line", 0), snippet=ex.get("lines", "").strip()[:200],
                                        cwe=", ".join(cwe) if isinstance(cwe, list) else str(cwe), source="semgrep"))
        except (subprocess.SubprocessError, json.JSONDecodeError) as e:
            notes.append(f"semgrep failed: {e}")
    else:
        notes.append("semgrep not found (pip install semgrep / brew install semgrep) - skipped")

    if shutil.which("gitleaks"):
        for p in paths:
            try:
                res = subprocess.run(["gitleaks", "detect", "--no-git", "--source", p, "--report-format", "json",
                                      "--report-path", "/dev/stdout", "--no-banner", "--exit-code", "0"],
                                     capture_output=True, text=True, timeout=600)
                for r in json.loads(res.stdout or "[]"):
                    findings.append(Finding(rule_id=f"gitleaks:{r.get('RuleID', '')}", title=r.get("Description", "secret"),
                                            severity="high", file=r.get("File", ""), line=r.get("StartLine", 0),
                                            snippet="[redacted]", cwe="CWE-798", source="gitleaks"))
            except (subprocess.SubprocessError, json.JSONDecodeError) as e:
                notes.append(f"gitleaks failed: {e}")
    else:
        notes.append("gitleaks not found (https://github.com/gitleaks/gitleaks#installing) - skipped")

    if shutil.which("bandit"):
        try:
            res = subprocess.run(["bandit", "-r", "-f", "json", "-q", *paths], capture_output=True, text=True, timeout=600)
            for r in json.loads(res.stdout or "{}").get("results", []):
                findings.append(Finding(rule_id=f"bandit:{r.get('test_id')}", title=r.get("issue_text", ""),
                                        severity=sev_map.get(r.get("issue_severity", "LOW"), "low"), file=r.get("filename", ""),
                                        line=r.get("line_number", 0), snippet=(r.get("code") or "").strip()[:200],
                                        cwe=f"CWE-{r.get('issue_cwe', {}).get('id', '')}", source="bandit"))
        except (subprocess.SubprocessError, json.JSONDecodeError) as e:
            notes.append(f"bandit failed: {e}")
    return findings, notes


# ---------------------------------------------------------------- output
COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}


def render_text(findings: list[Finding], color: bool) -> str:
    if not findings:
        return "secscan: no findings"
    out = []
    for f in sorted(findings, key=lambda x: (-SEVERITIES[x.severity], x.file, x.line)):
        sev = f.severity.upper()
        if color:
            sev = f"{COLORS[f.severity]}{sev}\033[0m"
        tags = " | ".join(t for t in (f.cwe, f.owasp) if t)
        out.append(f"{sev:<6} {f.file}:{f.line}  {f.rule_id}  {f.title}" + (f" [{tags}]" if tags else ""))
        if f.snippet:
            out.append(f"       > {f.snippet}")
        if f.fix:
            out.append(f"       fix: {f.fix}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    out.append(f"\nsecscan: {len(findings)} finding(s): {counts['high']} high, {counts['medium']} medium, {counts['low']} low")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SecureVibe security scanner for AI-generated code")
    ap.add_argument("paths", nargs="*", default=None)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-severity", choices=list(SEVERITIES), default="low")
    ap.add_argument("--fail-on", choices=[*SEVERITIES, "never"], default="high")
    ap.add_argument("--changed", action="store_true", help="scan files changed vs HEAD plus untracked files")
    ap.add_argument("--with-external", action="store_true", help="also run semgrep, gitleaks and bandit when installed")
    ap.add_argument("--rules", default=str(RULES_DIR), help="directory of rule packs")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)

    rules = load_rules(Path(args.rules))
    if args.list_rules:
        for r in rules + BUILTIN_RULES:
            print(f"{r['id']:<11} {r['severity']:<6} {r.get('cwe', ''):<9} {r['title']}")
        return 0

    paths = changed_files() if args.changed else (args.paths or ["."])
    findings = scan_paths(paths, rules)
    notes: list[str] = []
    if args.with_external:
        ext, notes = run_external(paths)
        findings += ext
    findings = [f for f in findings if SEVERITIES[f.severity] >= SEVERITIES[args.min_severity]]

    if args.json:
        print(json.dumps({"version": VERSION, "findings": [asdict(f) for f in findings], "notes": notes}, indent=2))
    else:
        print(render_text(findings, color=sys.stdout.isatty() and not os.environ.get("NO_COLOR")))
        for n in notes:
            print(f"note: {n}", file=sys.stderr)
    if args.fail_on == "never":
        return 0
    return 1 if any(SEVERITIES[f.severity] >= SEVERITIES[args.fail_on] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
