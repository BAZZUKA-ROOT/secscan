"""Smoke tests for secscan2026 static engine. Run: python -m pytest -q"""
import os
import sys
import shutil
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secscan.static_scanner import scan_path  # noqa: E402

FIX_VULN = os.path.join(os.path.dirname(__file__), "fixture_vuln")
FIX_CLEAN = os.path.join(os.path.dirname(__file__), "fixture_clean")


def _ids(findings):
    return {f.rule_id for f in findings}


def test_vuln_fixture_detects_core_rules(tmp_path):
    test_path = tmp_path / "fixture_vuln"
    shutil.copytree(FIX_VULN, test_path)

    # Dados sinteticos montados somente em pasta temporaria: nao sao credenciais.
    tokens = {
        "__OPENAI_TEST_KEY__": "sk-" + "X" * 36,
        "__GITHUB_TEST_KEY__": "ghp_" + "Y" * 36,
        "__STRIPE_TEST_KEY__": "sk_" + "live_" + "Z" * 32,
        "__SUPABASE_TEST_KEY__": "sb_" + "secret_" + "R" * 36,
        "__GOOGLE_TEST_KEY__": "AIza" + "Q" * 35,
        "__DATABASE_TEST_URL__": "postgresql://" + "test_user:test_pass" + "@localhost/testdb",
    }
    for src in test_path.rglob("*"):
        if not src.is_file():
            continue
        data = src.read_text(encoding="utf-8")
        for placeholder, synthetic in tokens.items():
            data = data.replace(placeholder, synthetic)
        src.write_text(data, encoding="utf-8")
    (test_path / ".env").write_text(
        (test_path / "env.template").read_text(encoding="utf-8"),
        encoding="utf-8"
    )
    ids = _ids(scan_path(str(test_path)))
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
