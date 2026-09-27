"""Read and validate a simple vulnerability-scanner CSV export."""

from __future__ import annotations

import csv
from pathlib import Path

from pydantic import ValidationError

from ..models import ScanFinding, ScanReadResult, ValidationIssue


REQUIRED_COLUMNS = {
    "asset_id",
    "asset_name",
    "cve_id",
    "internet_exposed",
    "business_criticality",
    "environment",
}


def _parse_boolean(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    raise ValueError("internet_exposed must be true or false")


def read_scan_csv(path: Path) -> ScanReadResult:
    if not path.exists():
        raise FileNotFoundError(f"Scanner file not found: {path}")

    findings: list[ScanFinding] = []
    issues: list[ValidationIssue] = []
    seen: set[tuple[str, str]] = set()
    duplicates = 0

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        columns = set(reader.fieldnames or [])
        missing = sorted(REQUIRED_COLUMNS - columns)
        if missing:
            raise ValueError(f"Missing required CSV columns: {', '.join(missing)}")

        for row_number, row in enumerate(reader, start=2):
            try:
                prepared = dict(row)
                prepared["internet_exposed"] = _parse_boolean(
                    prepared.get("internet_exposed", "")
                )
                finding = ScanFinding.model_validate(prepared)
                unique_key = (finding.asset_id.lower(), finding.cve_id)
                if unique_key in seen:
                    duplicates += 1
                    issues.append(
                        ValidationIssue(
                            row_number=row_number,
                            message="Duplicate asset/CVE finding was removed",
                            raw_row=dict(row),
                        )
                    )
                    continue
                seen.add(unique_key)
                findings.append(finding)
            except (ValidationError, ValueError) as error:
                issues.append(
                    ValidationIssue(
                        row_number=row_number,
                        message=str(error),
                        raw_row=dict(row),
                    )
                )

    if not findings:
        raise ValueError("The scanner file contains no valid findings")

    return ScanReadResult(
        findings=findings,
        issues=issues,
        duplicates_removed=duplicates,
    )
