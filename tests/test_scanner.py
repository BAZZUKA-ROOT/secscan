"""Smoke tests for secscan2026 static engine. Run: python -m pytest -q"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secscan.static_scanner import scan_path  # noqa: E402

FIX_VULN = os.path.join(os.path.dirname(__file__), "fixture_vuln")
FIX_CLEAN = os.path.join(os.path.dirname(__file__), "fixture_clean")


def _ids(findings):
    return {f.rule_id for f in findings}


def test_vuln_fixture_detects_core_rules():
    ids = _ids(scan_path(FIX_VULN))
    for expected in {
        "SECR-OPENAI", "SECR-GITHUB", "SECR-STRIPE-LIVE", "SECR-SUPABASE-SR",
        "SECR-PG-URL", "CFG-ENV-COMMITTED", "CFG-CORS-WILDCARD", "CFG-DEBUG-ON",
        "CFG-SUPA-SR-CLIENT", "DB-SQL-CONCAT", "CODE-PATH-TRAVERSAL",
        "CODE-DESERIALIZE",
    }:
        assert expected in ids, f"missing rule {expected}"


def test_clean_fixture_has_no_findings():
    findings = scan_path(FIX_CLEAN)
    assert findings == [], [f.rule_id for f in findings]


def test_parameterized_sql_not_flagged():
    ids = _ids(scan_path(FIX_CLEAN))
    assert "DB-SQL-CONCAT" not in ids
