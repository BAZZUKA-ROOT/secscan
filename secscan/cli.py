"""secscan2026 CLI.

Two execution modes, as requested:
  secscan path <folder-or-file>     # static analysis + dependency/version checks
  secscan url  <https://your-site>  # passive, read-only domain checks (consent required)

Design choices, on purpose:
  * No exploit/attack module. Domain mode only reads what a browser would.
  * Domain mode requires --i-own-this to affirm authorization.
  * Does not require admin/root. If run as root, it warns.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .report import to_json, to_markdown
from .findings import Finding


def _warn_if_root():
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            print("⚠️  Running as root is unnecessary for a read-only scanner and is "
                  "discouraged. Continuing with reduced-privilege recommended.",
                  file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass


def _write_reports(findings, target, mode, out_prefix):
    md = to_markdown(findings, target, mode)
    js = to_json(findings, target, mode)
    md_path = out_prefix + ".md"
    js_path = out_prefix + ".json"
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(js_path, "w", encoding="utf-8") as fh:
        fh.write(js)
    return md_path, js_path, md


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(
        prog="secscan",
        description="secscan2026 — static + passive security scanner for 2026-era "
                    "code/config/dependency flaws. Read-only. No exploits.")
    p.add_argument("--version", action="version", version=f"secscan2026 {__version__}")
    sub = p.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("path", help="Scan a local folder or file (static + deps).")
    sp.add_argument("target", help="Path to a project folder or a single file.")
    sp.add_argument("--no-runtime", action="store_true",
                    help="Do not inspect local interpreter versions (python/node/php/nginx).")
    sp.add_argument("-o", "--output", default="secscan-report",
                    help="Output prefix (writes .md and .json). Default: secscan-report")

    su = sub.add_parser("url", help="Passively scan a domain you own (read-only).")
    su.add_argument("target", help="https URL of a site you are authorized to test.")
    su.add_argument("--i-own-this", action="store_true",
                    help="Required. Affirms you own or are authorized to test this target.")
    su.add_argument("-o", "--output", default="secscan-report",
                    help="Output prefix (writes .md and .json). Default: secscan-report")

    args = p.parse_args(argv)
    _warn_if_root()
    findings: list[Finding] = []

    if args.mode == "path":
        if not os.path.exists(args.target):
            print(f"error: path not found: {args.target}", file=sys.stderr)
            return 2
        from .static_scanner import scan_path
        from .deps_scanner import scan_deps
        print(f"Scanning path: {args.target}", file=sys.stderr)
        findings += scan_path(args.target)
        findings += scan_deps(args.target, check_runtime=not args.no_runtime)
        target = os.path.abspath(args.target)

    elif args.mode == "url":
        if not args.i_own_this:
            print("refused: passive domain scanning requires --i-own-this to affirm you "
                  "are authorized to test this target. Scanning a site you do not own may "
                  "be illegal.", file=sys.stderr)
            return 3
        from .domain_scanner import scan_url
        print(f"Passively scanning (read-only): {args.target}", file=sys.stderr)
        findings += scan_url(args.target)
        target = args.target

    md_path, js_path, md = _write_reports(findings, target, args.mode, args.output)
    print("\n" + md + "\n", file=sys.stderr)
    print(f"Reports written: {md_path} , {js_path}", file=sys.stderr)

    # exit code: 1 if any critical/high, else 0 (useful in CI)
    bad = any(f.severity in ("critical", "high") for f in findings)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
