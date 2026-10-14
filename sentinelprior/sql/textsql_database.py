"""Create the structured SQLite table used by the TextSQL query layer."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelprior.paths import DATA_DIR


DEFAULT_INPUT = DATA_DIR / "enriched_cves.json"
DEFAULT_DATABASE = DATA_DIR / "sentinelprior_textsql.db"


CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    state TEXT,
    published_at TEXT,
    updated_at TEXT,
    nvd_status TEXT,
    description TEXT,
    vendor TEXT,
    product TEXT,
    affected_products TEXT,
    cvss_version TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    cvss_vector TEXT,
    attack_vector TEXT,
    attack_complexity TEXT,
    privileges_required TEXT,
    user_interaction TEXT,
    scope TEXT,
    confidentiality_impact TEXT,
    integrity_impact TEXT,
    availability_impact TEXT,
    exploitability_score REAL,
    impact_score REAL,
    epss_score REAL,
    epss_percentile REAL,
    epss_date TEXT,
    cisa_kev_listed INTEGER NOT NULL,
    cisa_date_added TEXT,
    cisa_due_date TEXT,
    known_ransomware_use TEXT,
    cisa_required_action TEXT,
    cwes TEXT,
    source_path TEXT,
    enriched_text_card TEXT,
    affected_json TEXT NOT NULL,
    nvd_json TEXT NOT NULL,
    enriched_at TEXT,
    loaded_at TEXT NOT NULL
)
"""


UPSERT = """
INSERT INTO cves (
    cve_id, state, published_at, updated_at, nvd_status, description,
    vendor, product, affected_products, cvss_version, cvss_score,
    cvss_severity, cvss_vector, attack_vector, attack_complexity,
    privileges_required, user_interaction, scope, confidentiality_impact,
    integrity_impact, availability_impact, exploitability_score, impact_score,
    epss_score, epss_percentile, epss_date, cisa_kev_listed,
    cisa_date_added, cisa_due_date, known_ransomware_use,
    cisa_required_action, cwes, source_path, enriched_text_card,
    affected_json, nvd_json, enriched_at, loaded_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT(cve_id) DO UPDATE SET
    state=excluded.state,
    published_at=excluded.published_at,
    updated_at=excluded.updated_at,
    nvd_status=excluded.nvd_status,
    description=excluded.description,
    vendor=excluded.vendor,
    product=excluded.product,
    affected_products=excluded.affected_products,
    cvss_version=excluded.cvss_version,
    cvss_score=excluded.cvss_score,
    cvss_severity=excluded.cvss_severity,
    cvss_vector=excluded.cvss_vector,
    attack_vector=excluded.attack_vector,
    attack_complexity=excluded.attack_complexity,
    privileges_required=excluded.privileges_required,
    user_interaction=excluded.user_interaction,
    scope=excluded.scope,
    confidentiality_impact=excluded.confidentiality_impact,
    integrity_impact=excluded.integrity_impact,
    availability_impact=excluded.availability_impact,
    exploitability_score=excluded.exploitability_score,
    impact_score=excluded.impact_score,
    epss_score=excluded.epss_score,
    epss_percentile=excluded.epss_percentile,
    epss_date=excluded.epss_date,
    cisa_kev_listed=excluded.cisa_kev_listed,
    cisa_date_added=excluded.cisa_date_added,
    cisa_due_date=excluded.cisa_due_date,
    known_ransomware_use=excluded.known_ransomware_use,
    cisa_required_action=excluded.cisa_required_action,
    cwes=excluded.cwes,
    source_path=excluded.source_path,
    enriched_text_card=excluded.enriched_text_card,
    affected_json=excluded.affected_json,
    nvd_json=excluded.nvd_json,
    enriched_at=excluded.enriched_at,
    loaded_at=excluded.loaded_at
"""


def text(value: Any) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def distinct(values: list[str | None]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value.casefold() not in seen:
            result.append(value)
            seen.add(value.casefold())
    return result


def affected_summary(record: dict) -> tuple[str | None, str | None, str | None]:
    affected = [item for item in record.get("affected") or [] if isinstance(item, dict)]
    nvd_affected = [item for item in record.get("nvdAffectedProducts") or [] if isinstance(item, dict)]
    vendors = distinct([text(item.get("vendor")) for item in affected + nvd_affected])
    products = distinct(
        [text(item.get("product") or item.get("packageName")) for item in affected + nvd_affected]
    )
    readable: list[str] = []
    for item in affected:
        identity = " / ".join(
            value
            for value in (
                text(item.get("vendor")),
                text(item.get("product")),
                text(item.get("packageName")),
            )
            if value
        )
        if identity and identity not in readable:
            readable.append(identity)
    return (
        ", ".join(vendors) or None,
        ", ".join(products) or None,
        "; ".join(readable) or None,
    )


def row_values(record: dict, loaded_at: str) -> tuple:
    cvss = record.get("cvss") or {}
    epss = record.get("epss") or {}
    kev = record.get("cisaKev") or {}
    kev_details = kev.get("details") or {}
    nvd = record.get("nvd") or {}
    vendor, product, affected_products = affected_summary(record)
    affected = record.get("affected") or []
    cwes = distinct([text(value) for value in record.get("cwes") or []])

    return (
        record.get("cveId"),
        record.get("state"),
        record.get("datePublished") or nvd.get("published"),
        record.get("dateUpdated") or nvd.get("lastModified"),
        nvd.get("vulnStatus"),
        record.get("description"),
        vendor,
        product,
        affected_products,
        cvss.get("version"),
        cvss.get("score"),
        cvss.get("severity"),
        cvss.get("vector"),
        cvss.get("attackVector"),
        cvss.get("attackComplexity"),
        cvss.get("privilegesRequired"),
        cvss.get("userInteraction"),
        cvss.get("scope"),
        cvss.get("confidentialityImpact"),
        cvss.get("integrityImpact"),
        cvss.get("availabilityImpact"),
        cvss.get("exploitabilityScore"),
        cvss.get("impactScore"),
        epss.get("epss"),
        epss.get("percentile"),
        epss.get("date"),
        int(bool(kev.get("listed"))),
        kev_details.get("dateAdded"),
        kev_details.get("dueDate"),
        kev_details.get("knownRansomwareCampaignUse"),
        kev_details.get("requiredAction"),
        ", ".join(cwes),
        record.get("sourcePath"),
        record.get("enrichedTextCard"),
        json.dumps(affected, ensure_ascii=False),
        json.dumps(nvd, ensure_ascii=False),
        record.get("enrichedAt"),
        loaded_at,
    )


def load_enriched_cves(
    input_path: Path = DEFAULT_INPUT,
    database_path: Path = DEFAULT_DATABASE,
) -> int:
    """Upsert every enriched record into one TextSQL-friendly CVE table."""
    payload = json.loads(input_path.read_text(encoding="utf-8-sig"))
    records = payload.get("records") or []
    database_path.parent.mkdir(parents=True, exist_ok=True)
    loaded_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(database_path) as connection:
        connection.execute(CREATE_TABLE)
        count = 0
        for record in records:
            if not record.get("cveId"):
                continue
            connection.execute(UPSERT, row_values(record, loaded_at))
            count += 1
        connection.commit()
    return count


def main() -> None:
    if not DEFAULT_INPUT.exists():
        raise SystemExit(f"Missing {DEFAULT_INPUT}. Run enrichment.py first.")
    count = load_enriched_cves()
    print(f"Loaded {count} enriched CVEs into {DEFAULT_DATABASE.resolve()}")


if __name__ == "__main__":
    main()
