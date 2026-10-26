"""Render findings to Markdown and JSON."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import Finding, SEVERITY_ORDER

_SEV_LABEL = {
    "critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM",
    "low": "🔵 LOW", "info": "⚪ INFO",
}


def _counts(findings: list[Finding]) -> dict[str, int]:
    c = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def to_json(findings: list[Finding], target: str, mode: str) -> str:
    return json.dumps({
        "tool": "secscan2026",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "target": target,
        "summary": _counts(findings),
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2, ensure_ascii=False)


def to_markdown(findings: list[Finding], target: str, mode: str) -> str:
    findings = sorted(findings, key=lambda f: f.sort_key())
    c = _counts(findings)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# secscan2026 — Security Report",
        "",
        f"- **Target:** `{target}`",
        f"- **Mode:** {mode}",
        f"- **Generated:** {ts}",
        f"- **Total findings:** {len(findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| 🔴 Critical | {c['critical']} |",
        f"| 🟠 High | {c['high']} |",
        f"| 🟡 Medium | {c['medium']} |",
        f"| 🔵 Low | {c['low']} |",
        f"| ⚪ Info | {c['info']} |",
        "",
    ]

    if not findings:
        lines += ["✅ No findings for the enabled checks. "
                  "This is not proof the target is secure — these are heuristic checks.", ""]
    else:
        lines += ["## Findings", ""]
        for i, f in enumerate(findings, 1):
            cwe = f" · {f.cwe}" if f.cwe else ""
            lines += [
                f"### {i}. {_SEV_LABEL.get(f.severity, f.severity)} — {f.title}",
                f"- **Rule:** `{f.rule_id}`{cwe} · _{f.category}_",
                f"- **Location:** `{f.location}`",
                f"- **Evidence:** `{f.evidence}`",
                f"- **Fix:** {f.recommendation}",
                "",
            ]

    lines += [
        "---",
        "_Heuristic scan. Confirm each finding manually. Not a substitute for a full "
        "SAST/DAST/SCA review (e.g. Semgrep, pip-audit, npm audit, osv-scanner, OWASP ZAP)._",
    ]
    return "\n".join(lines)
