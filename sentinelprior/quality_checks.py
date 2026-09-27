"""Final checks that prevent unsupported or incomplete reports."""

from __future__ import annotations

from .models import EnrichedFinding


def validate_findings(findings: list[EnrichedFinding]) -> list[str]:
    warnings: list[str] = []
    if not findings:
        raise ValueError("No prioritized findings are available for the report")

    for item in findings:
        if item.priority is None or item.risk_score is None:
            raise ValueError(f"{item.finding.cve_id} has no calculated priority")
        if not item.reasons:
            raise ValueError(f"{item.finding.cve_id} has no priority explanation")
        if not item.nvd.available:
            warnings.append(f"{item.finding.cve_id}: NVD evidence unavailable")
        if not item.kev.catalog_available:
            warnings.append(f"{item.finding.cve_id}: CISA KEV catalog unavailable")
        if not item.epss.available:
            warnings.append(f"{item.finding.cve_id}: EPSS evidence unavailable")
    return sorted(set(warnings))
