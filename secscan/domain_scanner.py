"""Passive domain checks. READ-ONLY. No exploit payloads, no destructive probes.

This module performs a small number of ordinary GET requests to a target the
operator has confirmed they own (via the --i-own-this flag, enforced in cli.py):
  - missing/weak security response headers
  - permissive CORS (reflecting Origin / '*', esp. with credentials)
  - cookies without Secure/HttpOnly/SameSite
  - TLS/HTTPS availability
  - secrets and Supabase keys exposed in linked first-party JS bundles

What it deliberately does NOT do: no auth bypass, no RLS exploitation, no fuzzing
of endpoints, no CVE exploitation, no writes. It only reads what any browser
loading the page would already receive.
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from .findings import Finding, redact
from .static_scanner import _SECRET_PATTERNS

_UA = "secscan2026/0.1 (+passive; read-only)"
_TIMEOUT = 12

# security headers we expect on an HTML response
_EXPECTED_HEADERS = {
    "content-security-policy": ("high", "CWE-693",
        "Add a Content-Security-Policy to constrain script sources and mitigate XSS."),
    "strict-transport-security": ("medium", "CWE-319",
        "Add HSTS (Strict-Transport-Security) to force HTTPS."),
    "x-content-type-options": ("low", "CWE-693",
        "Add 'X-Content-Type-Options: nosniff'."),
    "x-frame-options": ("medium", "CWE-1021",
        "Add X-Frame-Options or a CSP frame-ancestors directive to prevent clickjacking."),
    "referrer-policy": ("low", "CWE-200",
        "Set a Referrer-Policy to avoid leaking URLs to third parties."),
}

_SCRIPT_SRC = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.I)
_INLINE_SUPA = re.compile(r"https://([a-z0-9]{10,})\.supabase\.co", re.I)


def _get(url: str, *, method: str = "GET", origin: Optional[str] = None):
    headers = {"User-Agent": _UA, "Accept": "*/*"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, headers=headers, method=method)
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=_TIMEOUT, context=ctx)


def scan_url(target: str, *, max_bundles: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlsplit(target)
    if not parsed.scheme:
        target = "https://" + target
        parsed = urllib.parse.urlsplit(target)

    # 1) HTTPS availability
    if parsed.scheme != "https":
        findings.append(Finding(
            "NET-NO-HTTPS", "Target not using HTTPS", "high", target,
            parsed.scheme, "Serve the site over HTTPS and redirect HTTP to HTTPS.",
            cwe="CWE-319", category="domain"))

    try:
        resp = _get(target)
        body = resp.read(1_500_000).decode("utf-8", "ignore")
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.URLError as e:
        findings.append(Finding(
            "NET-UNREACHABLE", "Could not fetch target", "info", target,
            str(getattr(e, "reason", e))[:120],
            "Confirm the URL is correct and reachable.", category="domain"))
        return findings
    except Exception as e:  # noqa: BLE001
        findings.append(Finding(
            "NET-ERROR", "Error fetching target", "info", target, str(e)[:120],
            "Check connectivity / certificate.", category="domain"))
        return findings

    # 2) security headers
    for h, (sev, cwe, rec) in _EXPECTED_HEADERS.items():
        if h not in hdrs:
            findings.append(Finding(
                f"HDR-MISSING-{h.upper()}", f"Missing header: {h}", sev, target,
                "(absent)", rec, cwe=cwe, category="domain"))

    # 3) CORS reflection (passive: just observe what the server returns)
    aco = hdrs.get("access-control-allow-origin", "")
    acc = hdrs.get("access-control-allow-credentials", "").lower()
    if aco == "*":
        sev = "high" if acc == "true" else "medium"
        findings.append(Finding(
            "DOM-CORS-WILDCARD", "Wildcard CORS on response", sev, target,
            f"ACAO=* ; ACAC={acc or 'unset'}",
            "Return an explicit allowlisted origin, never '*' together with credentials.",
            cwe="CWE-942", category="domain"))
    else:
        try:
            probe = _get(target, origin="https://secscan-probe.example")
            p_aco = probe.headers.get("Access-Control-Allow-Origin", "")
            if p_aco == "https://secscan-probe.example":
                findings.append(Finding(
                    "DOM-CORS-REFLECT", "Server reflects arbitrary Origin", "high", target,
                    f"reflected: {p_aco}",
                    "Validate Origin against an allowlist; do not echo it back unconditionally.",
                    cwe="CWE-942", category="domain"))
        except Exception:  # noqa: BLE001
            pass

    # 4) cookie flags
    for cookie in resp.headers.get_all("Set-Cookie") or []:
        low = cookie.lower()
        name = cookie.split("=", 1)[0]
        missing = [f for f in ("secure", "httponly") if f not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            findings.append(Finding(
                "DOM-COOKIE-FLAGS", f"Cookie '{name}' missing {', '.join(missing)}",
                "medium", target, name,
                "Set Secure, HttpOnly and SameSite on session cookies.",
                cwe="CWE-1004", category="domain"))

    # 5) Supabase project referenced from client
    for m in _INLINE_SUPA.finditer(body):
        findings.append(Finding(
            "DOM-SUPABASE-REF", "Supabase project referenced in client code", "info",
            target, f"{m.group(1)[:6]}….supabase.co",
            "Expected for the anon key, but verify Row-Level Security is ON for every "
            "table and that the service_role key is never shipped to the browser.",
            cwe="CWE-668", category="domain"))
        break

    # 6) secrets in first-party JS bundles
    bundles = []
    for m in _SCRIPT_SRC.finditer(body):
        src = urllib.parse.urljoin(target, m.group(1))
        if urllib.parse.urlsplit(src).netloc == parsed.netloc:
            bundles.append(src)
    for src in bundles[:max_bundles]:
        try:
            js = _get(src).read(1_500_000).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            continue
        for rule_id, title, sev, cwe, rx in _SECRET_PATTERNS:
            jm = rx.search(js)
            if jm:
                token = jm.group(1) if jm.groups() else jm.group(0)
                findings.append(Finding(
                    f"DOM-{rule_id}", f"{title} exposed in client bundle",
                    "critical" if sev == "critical" else "high", src,
                    redact(token), cwe=cwe, category="domain",
                    recommendation="Secrets must never be in client-side JS. Remove it, rotate it, "
                                   "and proxy the call through your backend."))
    return findings
