"""Static analysis: walks a folder/file and applies line-level heuristic rules.

Scope (deliberately): secrets, Supabase RLS/service_role, CORS wildcard, committed
.env, debug mode, SQL built by string concatenation, path traversal sinks,
insecure deserialization, MCP config secrets. This is heuristic (regex) analysis,
not a full SAST engine, and it reports *candidates* a human should confirm.
"""
from __future__ import annotations

import math
import os
import re
from typing import Iterator

from .findings import Finding, redact

# ---- file selection -------------------------------------------------------

TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php",
    ".java", ".kt", ".cs", ".rs", ".sql", ".sh", ".bash", ".zsh", ".yaml",
    ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties",
    ".tf", ".tfvars", ".html", ".vue", ".svelte", ".txt", ".md",
}
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", ".nuxt", "vendor", "target", ".idea", ".vscode", "coverage",
    ".mypy_cache", ".pytest_cache", "site-packages",
}
MAX_FILE_BYTES = 2_000_000  # skip anything larger; likely data/minified blobs

# ---- secret detectors -----------------------------------------------------
# Each is (rule_id, title, severity, cwe, compiled_regex). Capture group 0 or 1
# is the token used for evidence/entropy.

_SECRET_PATTERNS = [
    ("SECR-AWS-AKID", "AWS access key id", "critical", "CWE-798",
     re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("SECR-AWS-SECRET", "Possible AWS secret access key", "critical", "CWE-798",
     re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("SECR-GITHUB", "GitHub token", "critical", "CWE-798",
     re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255})\b")),
    ("SECR-OPENAI", "OpenAI API key", "critical", "CWE-798",
     re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b")),
    ("SECR-ANTHROPIC", "Anthropic API key", "critical", "CWE-798",
     re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b")),
    ("SECR-STRIPE-LIVE", "Stripe live secret key", "critical", "CWE-798",
     re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b")),
    ("SECR-GOOGLE", "Google API key", "high", "CWE-798",
     re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("SECR-SLACK", "Slack token", "high", "CWE-798",
     re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("SECR-SUPABASE-SR", "Supabase service_role secret key", "critical", "CWE-798",
     re.compile(r"\b(sb_secret_[A-Za-z0-9_-]{20,})\b")),
    ("SECR-SENDGRID", "SendGrid API key", "high", "CWE-798",
     re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b")),
    ("SECR-PK", "Private key block", "critical", "CWE-798",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("SECR-JWT", "Hardcoded JWT", "medium", "CWE-798",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("SECR-PG-URL", "Database URL with inline credentials", "critical", "CWE-798",
     re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s:/@]+@[^\s'\"]+)")),
]

# generic "assignment of a secret-looking value", gated by entropy
_GENERIC_SECRET = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:secret|passwd|password|api[_-]?key|access[_-]?token|"
    r"auth[_-]?token|private[_-]?key|client[_-]?secret)[A-Za-z0-9_]*)\s*[=:]\s*"
    r"['\"]([^'\"]{8,})['\"]"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{3,}|changeme|your[_-]?|example|placeholder|dummy|test|sample|"
    r"<[^>]+>|\$\{[^}]+\}|process\.env|os\.environ|null|none|true|false|\d+)"
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---- line-level misconfig rules -------------------------------------------
# (rule_id, title, severity, cwe, regex, recommendation)

_LINE_RULES = [
    ("CFG-CORS-WILDCARD", "Wildcard CORS origin", "high", "CWE-942",
     re.compile(r"(?i)access-control-allow-origin['\"]?\s*[:=,]\s*['\"]\*['\"]"
                r"|allow_origins\s*=\s*\[?\s*['\"]\*['\"]"
                r"|cors\([^)]*origin\s*:\s*['\"]\*['\"]"
                r"|set_?header\s*\(\s*['\"]access-control-allow-origin['\"]\s*,\s*['\"]\*['\"]"),
     "Reflect an explicit allowlist of trusted origins instead of '*', "
     "especially when credentials are allowed."),
    ("CFG-DEBUG-ON", "Debug mode enabled", "medium", "CWE-489",
     re.compile(r"(?i)\bdebug\s*[=:]\s*true\b|app\.run\([^)]*debug\s*=\s*True"
                r"|FLASK_DEBUG\s*[=:]\s*1|DJANGO_DEBUG\s*[=:]\s*True"),
     "Disable debug mode in any non-local environment; it can leak stack traces "
     "and enable interactive consoles."),
    ("CFG-SUPA-SR-CLIENT", "Supabase service_role reference", "critical", "CWE-522",
     re.compile(r"(?i)service_role"),
     "The service_role key bypasses Row-Level Security. Keep it server-side only; "
     "never ship it in client/browser code or commit it."),
    ("DB-SQL-CONCAT", "SQL query built by string concatenation/interpolation", "high", "CWE-89",
     # f-string SQL, '... ' + var, or "... " % (...). Parameterized %s placeholders
     # passed as a separate argument are NOT flagged.
     re.compile(r"(?i)(?:execute|executemany|query|db\.query)\s*\(\s*"
                r"(?:f['\"].*?(?:select|insert|update|delete|drop)\b"           # f-string SQL
                r"|['\"].*?(?:select|insert|update|delete|drop)\b.*?['\"]\s*(?:\+|%[^s(])" # concat / % op
                r"|['\"].*?(?:select|insert|update|delete|drop)\b.*?\{[^}]*\}.*?['\"]\.format)"),  # .format

     "Use parameterized queries / prepared statements; never build SQL by "
     "concatenating or interpolating untrusted input."),
    ("CODE-PATH-TRAVERSAL", "Possible path traversal sink", "high", "CWE-22",
     re.compile(r"(?i)(?:open|readfile|read_file|sendfile|send_file|fs\.read|"
                r"os\.path\.join)\s*\([^)]*(?:req\.|request\.|params|argv|input\(|"
                r"query\[|\.get\()"),
     "Canonicalize and validate the resolved path against an allowed base "
     "directory before reading/serving a user-controlled path."),
    ("CODE-DESERIALIZE", "Insecure deserialization", "high", "CWE-502",
     re.compile(r"(?i)\b(?:pickle\.loads?|yaml\.load\s*\((?![^)]*Loader)"
                r"|marshal\.loads?|cPickle\.loads?)\b"),
     "Avoid deserializing untrusted data. Use yaml.safe_load, JSON, or a signed/"
     "validated format."),
    ("CODE-EVAL", "Dynamic code execution sink", "high", "CWE-95",
     re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*(?:req\.|request\.|params|input\(|"
                r"argv|query\[|\.get\()"),
     "Do not pass user input to eval/exec. Use a safe parser or explicit dispatch."),
    ("CODE-CMD-INJECT", "OS command with shell=True / interpolation", "high", "CWE-78",
     re.compile(r"(?i)(?:os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\([^)]*"
                r"shell\s*=\s*True)"),
     "Avoid shell=True with dynamic input; pass an argument list and validate "
     "inputs to prevent command injection."),
]


def _iter_files(root: str) -> Iterator[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in TEXT_EXTS or fn in (".env", "Dockerfile", ".npmrc", ".pypirc"):
                yield os.path.join(dirpath, fn)


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(root) or ".")
    except ValueError:
        return path


def scan_path(root: str) -> list[Finding]:
    findings: list[Finding] = []
    root = os.path.abspath(root)

    for path in _iter_files(root):
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        rel = _rel(path, root)
        base = os.path.basename(path)

        # Committed .env is a finding on its own (unless it's an example template).
        if base == ".env" or base.startswith(".env.") and not base.endswith((".example", ".sample", ".template")):
            findings.append(Finding(
                rule_id="CFG-ENV-COMMITTED",
                title="Committed .env file",
                severity="high",
                location=rel,
                evidence=base,
                recommendation="Remove the .env from version control, rotate any secrets it held, "
                               "and add it to .gitignore. Ship a .env.example without real values.",
                cwe="CWE-538",
                category="static",
            ))

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except (OSError, UnicodeError):
            continue

        for i, line in enumerate(lines, start=1):
            if len(line) > 4000:  # minified line; skip to limit noise
                continue
            findings.extend(_scan_line(line, rel, i))

    # de-duplicate identical findings (same rule+location+evidence)
    seen = set()
    unique = []
    for f in findings:
        k = (f.rule_id, f.location, f.evidence)
        if k not in seen:
            seen.add(k)
            unique.append(f)
    return unique


def _scan_line(line: str, rel: str, lineno: int) -> list[Finding]:
    out: list[Finding] = []
    loc = f"{rel}:{lineno}"

    for rule_id, title, sev, cwe, rx in _SECRET_PATTERNS:
        m = rx.search(line)
        if m:
            token = m.group(1) if m.groups() else m.group(0)
            out.append(Finding(
                rule_id=rule_id, title=title, severity=sev, location=loc,
                evidence=redact(token), cwe=cwe, category="static",
                recommendation="Remove the hardcoded secret, load it from a secret manager or "
                               "environment variable, and rotate it (assume it is compromised).",
            ))

    gm = _GENERIC_SECRET.search(line)
    if gm:
        name, value = gm.group(1), gm.group(2)
        if not _PLACEHOLDER.match(value) and _shannon_entropy(value) >= 3.2:
            out.append(Finding(
                rule_id="SECR-GENERIC", title=f"Hardcoded secret in '{name}'",
                severity="high", location=loc, evidence=f"{name}={redact(value)}",
                cwe="CWE-798", category="static",
                recommendation="Move the value to an environment variable or secret manager "
                               "and rotate it.",
            ))

    for rule_id, title, sev, cwe, rx, rec in _LINE_RULES:
        if rx.search(line):
            # service_role is only a finding with an assignment or client context
            snippet = line.strip()[:120]
            out.append(Finding(
                rule_id=rule_id, title=title, severity=sev, location=loc,
                evidence=snippet, cwe=cwe, category="static", recommendation=rec,
            ))
    return out
