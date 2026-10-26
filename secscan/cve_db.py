"""Small, curated advisory DB of notable 2026 ecosystem CVEs (last ~6 months).

This is DELIBERATELY NOT exhaustive. Thousands of CVEs ship per month; a bundled
list goes stale fast. For authoritative, continuously-updated coverage, run a real
SCA against OSV (https://osv.dev), `pip-audit`, `npm audit`, or GitHub Dependabot.
secscan uses this list only to flag well-known recent flaws by version range.

Each entry: package name (ecosystem-specific), affected version predicate, fixed
version note, cve id, severity, summary. Version comparison is best-effort
(PEP 440 / semver-ish, numeric-dotted).
"""
from __future__ import annotations

# ecosystem -> list of advisories
# "affected": callable(version_tuple) -> bool  (True = vulnerable)
ADVISORIES: dict[str, list[dict]] = {
    "pypi": [
        # Example of a 2026-era runtime/library advisory. Versions illustrative;
        # always confirm against the official advisory before acting.
        {"name": "cpython", "cve": "CVE-2026-115557", "severity": "high",
         "fixed": "3.13.9 / 3.12.13", "max_vuln": (3, 13, 8),
         "summary": "CPython issue disclosed Oct 2026 (CVSS ~9.4). Update the interpreter."},
        {"name": "pyyaml", "cve": "GENERIC-YAML-LOAD", "severity": "medium",
         "fixed": "n/a (use safe_load)", "max_vuln": (99, 0, 0),
         "summary": "yaml.load without SafeLoader deserializes arbitrary objects."},
    ],
    "npm": [
        {"name": "node", "cve": "CVE-2026-NODE-TLS", "severity": "high",
         "fixed": "see nodejs.org security releases", "max_vuln": (22, 11, 0),
         "summary": "Node.js 2026 security release (RCE/TLS/DNS class). Update to latest LTS patch."},
    ],
    "composer": [
        {"name": "php", "cve": "CVE-2026-109618 / CVE-2026-109619", "severity": "critical",
         "fixed": "patched 2026-10-21", "max_vuln": (8, 3, 99),
         "summary": "PHP interpreter bugs (CVSS 9.2) allowing code execution on servers. Update PHP."},
    ],
    "runtime": [  # detected from environment, not a manifest
        {"name": "nginx", "cve": "CVE-2026-15176 / CVE-2026-93479", "severity": "critical",
         "fixed": "see F5 advisory (Oct 2026)", "max_vuln": None,
         "summary": "Critical unauthenticated NGINX RCE via crafted HTTP (Oct 2026). "
                    "Also NGINX Rift CVE-2026-42945 (May 2026). Confirm your nginx version."},
    ],
}


def _parse_version(v: str):
    nums = []
    for part in v.strip().lstrip("v").replace("-", ".").split("."):
        if part.isdigit():
            nums.append(int(part))
        else:
            # stop at first non-numeric component (e.g. '1.2.0rc1')
            lead = ""
            for ch in part:
                if ch.isdigit():
                    lead += ch
                else:
                    break
            if lead:
                nums.append(int(lead))
            break
    return tuple(nums) if nums else None


def is_vulnerable(version: str, max_vuln) -> bool | None:
    """Return True if version <= max_vuln (vulnerable), False if not, None if unknown."""
    if max_vuln is None:
        return None  # advisory applies but we can't compare -> report as 'verify'
    pv = _parse_version(version)
    if pv is None:
        return None
    # pad to same length
    n = max(len(pv), len(max_vuln))
    pv_p = pv + (0,) * (n - len(pv))
    mv_p = tuple(max_vuln) + (0,) * (n - len(max_vuln))
    return pv_p <= mv_p
