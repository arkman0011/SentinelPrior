"""Enrich cleaned CVEs with compact NVD, FIRST EPSS, and CISA KEV evidence.

This stage reads ``data/clean_cves.json`` and writes
``data/enriched_cves.json``. It does not collect or clean CVEs, and it does
not calculate an invented risk score.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelprior.paths import DATA_DIR, ENV_FILE


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_INPUT = str(DATA_DIR / "clean_cves.json")
DEFAULT_OUTPUT = str(DATA_DIR / "enriched_cves.json")


def load_dotenv() -> None:
    """Load simple KEY=VALUE entries from the project .env file."""
    env_path = ENV_FILE
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def get_json(url: str, headers: dict[str, str] | None = None) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "SentinelPrior/1.0", **(headers or {})})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read())
    return payload if isinstance(payload, dict) else {}


def nvd_records(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch NVD objects while preserving the collector's API behavior."""
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    result: dict[str, dict] = {}
    for cve_id in cve_ids:
        query = urllib.parse.urlencode({"cveId": cve_id})
        try:
            data = get_json(f"{NVD_URL}?{query}", headers)
            vulnerabilities = data.get("vulnerabilities") or []
            if vulnerabilities:
                result[cve_id] = vulnerabilities[0].get("cve", {})
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.7 if not os.getenv("NVD_API_KEY") else 0.1)
    return result


def epss_records(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch FIRST EPSS results in one request for the supplied CVE IDs."""
    if not cve_ids:
        return {}
    query = urllib.parse.urlencode({"cve": ",".join(cve_ids)})
    try:
        data = get_json(f"{EPSS_URL}?{query}")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return {}
    return {item["cve"]: item for item in data.get("data", []) if item.get("cve")}


def kev_records() -> dict[str, dict]:
    """Download CISA's Known Exploited Vulnerabilities catalog once."""
    try:
        data = get_json(KEV_URL)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return {}
    return {item["cveID"]: item for item in data.get("vulnerabilities", []) if item.get("cveID")}


def remove_empty(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {key: remove_empty(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item not in (None, "", [], {})}
    if isinstance(value, list):
        cleaned = [remove_empty(item) for item in value]
        return [item for item in cleaned if item not in (None, "", [], {})]
    return value


def nvd_description(record: dict) -> str | None:
    descriptions = record.get("descriptions") or []
    return next(
        (
            str(item.get("value")).strip()
            for item in descriptions
            if item.get("lang") == "en" and str(item.get("value") or "").strip()
        ),
        None,
    )


def cvss_details(nvd: dict) -> dict:
    """Return the best available NVD CVSS metric in a convenient form."""
    metrics = nvd.get("metrics") or {}
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = [item for item in metrics.get(metric_name) or [] if isinstance(item, dict)]
        metric = next((item for item in candidates if item.get("type") == "Primary"), None)
        metric = metric or (candidates[0] if candidates else None)
        if not metric:
            continue
        data = metric.get("cvssData") or {}
        return remove_empty(
            {
                "version": data.get("version"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or metric.get("baseSeverity"),
                "vector": data.get("vectorString"),
                "attackVector": data.get("attackVector") or data.get("accessVector"),
                "attackComplexity": data.get("attackComplexity") or data.get("accessComplexity"),
                "privilegesRequired": data.get("privilegesRequired") or data.get("authentication"),
                "userInteraction": data.get("userInteraction"),
                "scope": data.get("scope"),
                "confidentialityImpact": data.get("confidentialityImpact"),
                "integrityImpact": data.get("integrityImpact"),
                "availabilityImpact": data.get("availabilityImpact"),
                "exploitabilityScore": metric.get("exploitabilityScore"),
                "impactScore": metric.get("impactScore"),
                "source": metric.get("source"),
                "type": metric.get("type"),
            }
        )
    return {}


def nvd_cwes(nvd: dict) -> list[str]:
    result: list[str] = []
    for weakness in nvd.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            value = str(item.get("value") or "").strip()
            if value and value not in result:
                result.append(value)
    return result


def nvd_affected_products(nvd: dict) -> list[dict]:
    """Flatten vulnerable CPE and version-range information from NVD."""
    result: list[dict] = []
    seen: set[str] = set()
    for configuration in nvd.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = str(match.get("criteria") or "")
                parts = criteria.split(":")
                entry = remove_empty(
                    {
                        "criteria": criteria,
                        "vendor": parts[3] if len(parts) > 4 else None,
                        "product": parts[4] if len(parts) > 4 else None,
                        "version": parts[5] if len(parts) > 5 and parts[5] != "*" else None,
                        "versionStartIncluding": match.get("versionStartIncluding"),
                        "versionStartExcluding": match.get("versionStartExcluding"),
                        "versionEndIncluding": match.get("versionEndIncluding"),
                        "versionEndExcluding": match.get("versionEndExcluding"),
                    }
                )
                marker = json.dumps(entry, sort_keys=True)
                if entry and marker not in seen:
                    result.append(entry)
                    seen.add(marker)
    return result


def compact_nvd(nvd: dict) -> dict:
    """Keep useful NVD evidence without unrelated response metadata."""
    english_descriptions = [
        item
        for item in nvd.get("descriptions") or []
        if isinstance(item, dict) and item.get("lang") == "en" and item.get("value")
    ]
    return remove_empty(
        {
            "id": nvd.get("id"),
            "sourceIdentifier": nvd.get("sourceIdentifier"),
            "published": nvd.get("published"),
            "lastModified": nvd.get("lastModified"),
            "vulnStatus": nvd.get("vulnStatus"),
            "descriptions": english_descriptions,
            # Retain official metrics for traceability and the existing loader.
            "metrics": nvd.get("metrics") or {},
            "weaknesses": nvd.get("weaknesses") or [],
            "configurations": nvd.get("configurations") or [],
            "references": nvd.get("references") or [],
        }
    )


def normalize_epss(item: dict | None) -> dict:
    if not item:
        return {}
    try:
        score = float(item["epss"])
        percentile = float(item["percentile"])
    except (KeyError, TypeError, ValueError):
        return {}
    return remove_empty(
        {
            "epss": score,
            "percentile": percentile,
            "date": item.get("date"),
            "source": "FIRST EPSS",
        }
    )


def normalize_kev(item: dict | None) -> dict:
    """Represent KEV membership; CISA KEV is a catalog, not a score."""
    return {
        "listed": bool(item),
        "details": remove_empty(
            {
                "vendorProject": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerabilityName": item.get("vulnerabilityName"),
                "dateAdded": item.get("dateAdded"),
                "shortDescription": item.get("shortDescription"),
                "requiredAction": item.get("requiredAction"),
                "dueDate": item.get("dueDate"),
                "knownRansomwareCampaignUse": item.get("knownRansomwareCampaignUse"),
                "notes": item.get("notes"),
            }
        )
        if item
        else {},
    }


def enriched_text_card(record: dict) -> str:
    lines = [str(record.get("textCard") or f"CVE ID: {record.get('cveId', '')}")]
    cvss = record.get("cvss") or {}
    epss = record.get("epss") or {}
    kev = record.get("cisaKev") or {}
    if cvss:
        lines.append(
            f"NVD CVSS: {cvss.get('score')} ({cvss.get('severity', 'UNKNOWN')}), "
            f"version {cvss.get('version', 'unknown')}, vector {cvss.get('vector', 'not provided')}"
        )
    if epss:
        lines.append(f"FIRST EPSS: {epss.get('epss')} probability; percentile {epss.get('percentile')}")
    lines.append(f"CISA KEV listed: {'Yes' if kev.get('listed') else 'No'}")
    if kev.get("details", {}).get("requiredAction"):
        lines.append(f"CISA required action: {kev['details']['requiredAction']}")
    return "\n".join(lines)


def enrich(input_path: str = DEFAULT_INPUT, output_path: str = DEFAULT_OUTPUT) -> dict:
    """Attach official NVD, EPSS, and CISA KEV intelligence to cleaned CVEs."""
    load_dotenv()
    source = json.loads(Path(input_path).read_text(encoding="utf-8-sig"))
    records = source.get("records") or []
    ids = [str(item.get("cveId")) for item in records if item.get("cveId")]

    nvd_by_id = nvd_records(ids)
    epss_by_id = epss_records(ids)
    kev_by_id = kev_records()
    enriched_at = datetime.now(timezone.utc).isoformat()
    enriched: list[dict] = []
    errors: list[dict[str, str]] = []

    for clean_record in records:
        cve_id = str(clean_record.get("cveId") or "")
        if not cve_id:
            errors.append({"cveId": "unknown", "error": "clean record has no cveId"})
            continue

        nvd_raw = nvd_by_id.get(cve_id) or {}
        epss = normalize_epss(epss_by_id.get(cve_id))
        kev = normalize_kev(kev_by_id.get(cve_id))
        cvss = cvss_details(nvd_raw)

        missing: list[str] = []
        if not nvd_raw:
            missing.append("NVD record")
        if not cvss:
            missing.append("NVD CVSS")
        if not epss:
            missing.append("FIRST EPSS")
        if missing:
            errors.append({"cveId": cve_id, "error": f"Missing during enrichment: {', '.join(missing)}"})

        record = {
            **clean_record,
            "description": nvd_description(nvd_raw) or clean_record.get("description"),
            "cvss": cvss,
            "epss": epss,
            "cisaKev": kev,
            "cwes": nvd_cwes(nvd_raw)
            or [item.get("id") for item in clean_record.get("weaknesses") or [] if item.get("id")],
            "nvdAffectedProducts": nvd_affected_products(nvd_raw),
            "nvd": compact_nvd(nvd_raw),
            "enrichedAt": enriched_at,
        }
        record["enrichedTextCard"] = enriched_text_card(record)
        enriched.append(remove_empty(record))

    payload = {
        "stage": "enriched",
        "source": source.get("source", "CVEProject/cvelistV5"),
        "enrichmentSources": {"nvd": NVD_URL, "epss": EPSS_URL, "cisaKev": KEV_URL},
        "enrichedAt": enriched_at,
        "count": len(enriched),
        "records": enriched,
        "errors": errors,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return payload


if __name__ == "__main__":
    result = enrich()
    print(f"Enriched {result['count']} cleaned CVE records; {len(result['errors'])} enrichment warning(s)")
