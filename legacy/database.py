"""Load enriched CVE records into a local SQLite database."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_INPUT = "data/enriched_cves.json"
DEFAULT_DATABASE = "sentinelprior.db"


CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    published TEXT,
    cvss_score REAL,
    severity TEXT,
    cwes_json TEXT NOT NULL,
    affected_products_json TEXT NOT NULL,
    epss_score REAL,
    epss_percentile REAL,
    cisa_kev_listed INTEGER NOT NULL,
    nvd_json TEXT NOT NULL,
    epss_json TEXT,
    cisa_kev_json TEXT,
    enriched_at TEXT,
    loaded_at TEXT NOT NULL
)
"""


def first_cvss(nvd: dict) -> tuple[float | None, str | None]:
    """Return the primary NVD CVSS score and severity when available."""
    metrics = nvd.get("metrics") or {}
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_name) or []
        primary = next((item for item in metric_list if item.get("type") == "Primary"), None)
        item = primary or (metric_list[0] if metric_list else None)
        if item:
            data = item.get("cvssData") or {}
            return data.get("baseScore"), data.get("baseSeverity")
    return None, None


def cwes(nvd: dict) -> list[str]:
    values = []
    for weakness in nvd.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            value = item.get("value")
            if value and value not in values:
                values.append(value)
    return values


def affected_products(nvd: dict) -> list[dict]:
    products = []
    for group in nvd.get("affected") or []:
        for product in group.get("affectedData") or []:
            products.append({
                "vendor": product.get("vendor"),
                "product": product.get("product"),
                "versions": product.get("versions") or [],
            })
    return products


def create_database(connection: sqlite3.Connection) -> None:
    connection.execute(CREATE_TABLE)
    connection.commit()


def load(input_path: str = DEFAULT_INPUT, database_path: str = DEFAULT_DATABASE) -> int:
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    records = payload.get("records") or []
    now = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(database_path) as connection:
        create_database(connection)
        for record in records:
            cve_id = record.get("cveId")
            if not cve_id:
                continue
            nvd = record.get("nvd") or {}
            epss = record.get("epss") or {}
            kev = record.get("cisaKev") or {}
            score, severity = first_cvss(nvd)
            connection.execute(
                """
                INSERT INTO cves (
                    cve_id, description, published, cvss_score, severity,
                    cwes_json, affected_products_json, epss_score,
                    epss_percentile, cisa_kev_listed, nvd_json, epss_json,
                    cisa_kev_json, enriched_at, loaded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description=excluded.description,
                    published=excluded.published,
                    cvss_score=excluded.cvss_score,
                    severity=excluded.severity,
                    cwes_json=excluded.cwes_json,
                    affected_products_json=excluded.affected_products_json,
                    epss_score=excluded.epss_score,
                    epss_percentile=excluded.epss_percentile,
                    cisa_kev_listed=excluded.cisa_kev_listed,
                    nvd_json=excluded.nvd_json,
                    epss_json=excluded.epss_json,
                    cisa_kev_json=excluded.cisa_kev_json,
                    enriched_at=excluded.enriched_at,
                    loaded_at=excluded.loaded_at
                """,
                (
                    cve_id,
                    record.get("description"),
                    nvd.get("published"),
                    score,
                    severity,
                    json.dumps(cwes(nvd)),
                    json.dumps(affected_products(nvd)),
                    epss.get("epss") if epss else None,
                    epss.get("percentile") if epss else None,
                    int(bool(kev.get("listed"))),
                    json.dumps(nvd),
                    json.dumps(epss) if epss else None,
                    json.dumps(kev.get("details")) if kev.get("details") else None,
                    record.get("enrichedAt"),
                    now,
                ),
            )
        connection.commit()
    return len(records)


if __name__ == "__main__":
    count = load()
    print(f"Loaded {count} enriched CVE records into {DEFAULT_DATABASE}")
