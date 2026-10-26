"""Finding model and severity ordering shared across scanners."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    location: str
    evidence: str
    recommendation: str
    cwe: Optional[str] = None
    category: str = "static"

    def sort_key(self) -> tuple:
        return (SEVERITY_ORDER.get(self.severity, 99), self.rule_id, self.location)

    def to_dict(self) -> dict:
        return asdict(self)


def redact(secret: str, keep: int = 4) -> str:
    s = secret.strip()
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "…" + "*" * min(6, max(0, len(s) - keep))
