"""Retrieve useful CVE results from the local SQLite database."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path


DATABASE = Path(__file__).with_name("sentinelprior.db")


def _vendor_product(nvd: dict) -> tuple[str | None, str | None]:
    for group in nvd.get("affected") or []:
        for item in group.get("affectedData") or []:
            return item.get("vendor"), item.get("product")
    for config in nvd.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 4 and parts[0:3] == ["cpe", "2.3", "a"]:
                    return parts[3], parts[4]
    return None, None


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    results = []
    for row in rows:
        item = dict(row)
        item["cwes"] = json.loads(item.pop("cwes_json") or "[]")
        item["affectedProducts"] = json.loads(item.pop("affected_products_json") or "[]")
        item["nvd"] = json.loads(item.pop("nvd_json") or "{}")
        item["epss"] = json.loads(item.pop("epss_json") or "null")
        item["cisaKev"] = json.loads(item.pop("cisa_kev_json") or "null")
        item["cisaKevListed"] = bool(item["cisa_kev_listed"])
        del item["cisa_kev_listed"]
        results.append(item)
    return results


def top_by_cvss(limit: int = 5) -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM cves ORDER BY cvss_score DESC NULLS LAST LIMIT ?", (limit,)
        ).fetchall()
    return rows_to_dicts(rows)


def top_by_epss(limit: int = 5) -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM cves ORDER BY epss_score DESC NULLS LAST LIMIT ?", (limit,)
        ).fetchall()
    return rows_to_dicts(rows)


def cves_by_cvss(score: float, limit: int = 20) -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM cves WHERE cvss_score = ? ORDER BY epss_score DESC NULLS LAST LIMIT ?",
            (score, limit),
        ).fetchall()
    return rows_to_dicts(rows)


def vendors_by_highest_cvss(limit: int = 5) -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM cves ORDER BY cvss_score DESC NULLS LAST LIMIT ?", (limit * 5,)).fetchall()
    results = []
    for item in rows_to_dicts(rows):
        vendor, product = _vendor_product(item.get("nvd") or {})
        if vendor:
            results.append({**item, "vendor": vendor, "product": product})
    return results[:limit]


def cves_by_vendor(vendor: str, limit: int = 20) -> list[dict]:
    pattern = f'%"vendor": "{vendor}"%'
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM cves WHERE affected_products_json LIKE ? ORDER BY cvss_score DESC NULLS LAST LIMIT ?",
            (pattern, limit),
        ).fetchall()
    return rows_to_dicts(rows)


def cves_by_product(product: str, limit: int = 20) -> list[dict]:
    pattern = f'%"product": "{product}"%'
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM cves WHERE affected_products_json LIKE ? ORDER BY cvss_score DESC NULLS LAST LIMIT ?",
            (pattern, limit),
        ).fetchall()
    return rows_to_dicts(rows)


def cves_published_after(date_text: str, limit: int = 50) -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM cves WHERE published >= ? ORDER BY published DESC LIMIT ?",
            (date_text, limit),
        ).fetchall()
    return rows_to_dicts(rows)


def critical_cves() -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM cves WHERE severity = 'CRITICAL' ORDER BY cvss_score DESC"
        ).fetchall()
    return rows_to_dicts(rows)


def kev_cves(limit: int = 20) -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM cves WHERE cisa_kev_listed = 1 ORDER BY cvss_score DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return rows_to_dicts(rows)


def search(text: str, limit: int = 20) -> list[dict]:
    pattern = f"%{text}%"
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT * FROM cves
            WHERE cve_id LIKE ? OR description LIKE ? OR nvd_json LIKE ?
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT ?
            """,
            (pattern, pattern, pattern, limit),
        ).fetchall()
    return rows_to_dicts(rows)


if __name__ == "__main__":
    print(json.dumps(top_by_cvss(), indent=2))
