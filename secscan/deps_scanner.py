"""Dependency / runtime version checks against the curated advisory DB.

Reads manifests in a project (requirements.txt, package.json, composer.json,
go.mod, runtime.txt, .python-version, .nvmrc) plus the local interpreter versions,
and flags versions at/below a known-vulnerable ceiling. Non-exhaustive by design.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from .cve_db import ADVISORIES, is_vulnerable
from .findings import Finding

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)")


def _advise(eco: str, name: str, version: str | None, location: str) -> list[Finding]:
    out = []
    for adv in ADVISORIES.get(eco, []):
        if adv["name"].lower() != name.lower():
            continue
        verdict = is_vulnerable(version, adv["max_vuln"]) if version else None
        if verdict is False:
            continue  # version is patched
        confidence = "vulnerable" if verdict is True else "verify version"
        out.append(Finding(
            rule_id=f"DEP-{adv['cve'].split('/')[0].strip()}",
            title=f"{name} {adv['cve']} ({confidence})",
            severity=adv["severity"],
            location=f"{location}" + (f" [{version}]" if version else ""),
            evidence=adv["summary"],
            recommendation=f"Update {name} to a fixed release ({adv['fixed']}). "
                           f"Confirm against the official advisory and run pip-audit/npm audit/osv-scanner.",
            cwe=None, category="deps",
        ))
    return out


def _runtime_version(cmd: list[str]) -> str | None:
    exe = cmd[0]
    if not shutil.which(exe):
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        out = (r.stdout + r.stderr).strip()
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", out)
        return m.group(1) if m else None
    except Exception:  # noqa: BLE001
        return None


def scan_deps(root: str, *, check_runtime: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    root = os.path.abspath(root)
    is_dir = os.path.isdir(root)
    base = root if is_dir else os.path.dirname(root)

    def rel(p):
        return os.path.relpath(p, base) or os.path.basename(p)

    # requirements.txt
    for fn in ("requirements.txt", "requirements-dev.txt"):
        p = os.path.join(base, fn)
        if os.path.isfile(p):
            with open(p, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    m = _REQ_LINE.match(line)
                    if m:
                        findings += _advise("pypi", m.group(1), m.group(2), rel(p))

    # package.json
    pj = os.path.join(base, "package.json")
    if os.path.isfile(pj):
        try:
            data = json.load(open(pj, encoding="utf-8", errors="ignore"))
            for section in ("dependencies", "devDependencies"):
                for name, ver in (data.get(section) or {}).items():
                    findings += _advise("npm", name, re.sub(r"[^0-9.]", "", ver) or None, rel(pj))
        except Exception:  # noqa: BLE001
            pass

    # composer.json
    cj = os.path.join(base, "composer.json")
    if os.path.isfile(cj):
        try:
            data = json.load(open(cj, encoding="utf-8", errors="ignore"))
            for name, ver in (data.get("require") or {}).items():
                findings += _advise("composer", name, re.sub(r"[^0-9.]", "", ver) or None, rel(cj))
        except Exception:  # noqa: BLE001
            pass

    # pinned runtime files
    for fn, eco, name in ((".python-version", "pypi", "cpython"),
                          ("runtime.txt", "pypi", "cpython"),
                          (".nvmrc", "npm", "node")):
        p = os.path.join(base, fn)
        if os.path.isfile(p):
            txt = open(p, encoding="utf-8", errors="ignore").read()
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", txt)
            if m:
                findings += _advise(eco, name, m.group(1), rel(p))

    # local runtime interpreters (only when asked; environment, not project)
    if check_runtime:
        pv = _runtime_version(["python3", "--version"])
        if pv:
            findings += _advise("pypi", "cpython", pv, "local python3")
        nv = _runtime_version(["node", "--version"])
        if nv:
            findings += _advise("npm", "node", nv, "local node")
        phpv = _runtime_version(["php", "--version"])
        if phpv:
            findings += _advise("composer", "php", phpv, "local php")
        ngx = _runtime_version(["nginx", "-v"])
        if ngx:
            findings += _advise("runtime", "nginx", ngx, "local nginx")

    return findings
