"""Collect up to 50 mature, enrichment-ready CVEs from CVEProject/cvelistV5."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sentinelprior.paths import DATA_DIR


REPOSITORY = "CVEProject/cvelistV5"
RAW_ROOT = f"https://raw.githubusercontent.com/{REPOSITORY}/main/"
DELTA_LOG_URL = f"{RAW_ROOT}cves/deltaLog.json"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def fetch_json(url: str, headers: dict[str, str] | None = None) -> object:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "SentinelPrior/1.0", **(headers or {})},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def cve_paths_from_delta_log(changed_on: date) -> list[tuple[str, str]]:
    """Read newly added CVE paths for one exact UTC date from the delta log.

    Unlike the GitHub commits API, the raw delta log does not consume one API
    request per commit and therefore avoids the unauthenticated API rate limit.
    """
    delta_log = fetch_json(DELTA_LOG_URL)
    if not isinstance(delta_log, list):
        raise ValueError("CVEProject deltaLog.json did not contain a list")

    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    # deltaLog is newest first. Only the `new` group is relevant because the
    # user wants the CVEs introduced on one exact day, not older records that
    # happened to be updated on that day.
    for change_set in delta_log:
        if not isinstance(change_set, dict):
            continue
        fetch_time = str(change_set.get("fetchTime") or "")
        try:
            change_date = datetime.fromisoformat(fetch_time.replace("Z", "+00:00")).date()
        except ValueError:
            continue
        if change_date != changed_on:
            continue
        for item in change_set.get("new") or []:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cveId") or "").upper()
            match = CVE_PATTERN.fullmatch(cve_id)
            if not match or cve_id in seen:
                continue
            github_link = str(item.get("githubLink") or "")
            marker = "/main/"
            source_path = github_link.split(marker, 1)[1] if marker in github_link else cve_path(cve_id)
            unique.append((cve_id, source_path))
            seen.add(cve_id)
    return unique


def cve_path(cve_id: str) -> str:
    year, number = cve_id.split("-")[1:]
    return f"cves/{year}/{number[:3]}xxx/{cve_id}.json"


def download_record(cve_id: str, source_path: str | None = None) -> dict:
    """Download a CVE record from its exact repository path."""
    path = source_path or cve_path(cve_id)
    url = RAW_ROOT + urllib.parse.quote(path, safe="/-._")
    try:
        payload = fetch_json(url)
    except urllib.error.HTTPError:
        # The API discovered the exact path in a commit; this fallback lets callers
        # use a known CVE ID even when a path convention changes.
        raise RuntimeError(f"Could not download {cve_id} from CVEProject")
    if not isinstance(payload, dict):
        raise ValueError(f"CVEProject returned a non-object record for {cve_id}")
    return payload


def published_at(record: dict) -> datetime | None:
    value = ((record.get("cveMetadata") or {}).get("datePublished"))
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def has_affected_product(record: dict) -> bool:
    """Confirm that the source record identifies an affected product or version."""
    cna = ((record.get("containers") or {}).get("cna") or {})
    for item in cna.get("affected") or []:
        if not isinstance(item, dict):
            continue
        if item.get("product") or item.get("packageName") or item.get("versions"):
            return True
    return False


def has_english_nvd_description(record: dict) -> bool:
    return any(
        item.get("lang") == "en" and str(item.get("value") or "").strip()
        for item in record.get("descriptions") or []
        if isinstance(item, dict)
    )


def has_nvd_cvss(record: dict) -> bool:
    """Accept a populated CVSS v4, v3.1, v3.0, or v2 metric."""
    metrics = record.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key) or []:
            if not isinstance(metric, dict):
                continue
            data = metric.get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            if score is not None and severity:
                return True
    return False


def readiness_reasons(source: dict, nvd: dict | None, epss: dict | None) -> list[str]:
    """Reject only when information required by the project is missing."""
    reasons: list[str] = []
    if not has_affected_product(source):
        reasons.append("missing affected product or version")
    if not nvd:
        reasons.append("missing NVD record")
        return reasons
    if not has_english_nvd_description(nvd):
        reasons.append("missing NVD English description")
    if not has_nvd_cvss(nvd):
        reasons.append("missing NVD CVSS score or severity")
    if not epss or epss.get("epss") in (None, "") or epss.get("percentile") in (None, ""):
        reasons.append("missing EPSS score or percentile")
    return reasons


def collect(
    limit: int = 50,
    minimum_age_days: int = 30,
    output_path: str = str(DATA_DIR / "raw_cves.json"),
) -> dict:
    """Collect enrichment-ready CVEs published on the exact 30th day back."""
    if limit < 1 or limit > 50:
        raise ValueError("limit must be between 1 and 50")
    if minimum_age_days < 0:
        raise ValueError("minimum_age_days cannot be negative")

    # Import here so collector.py stays focused on selection while reusing the
    # same official NVD and FIRST EPSS clients as the later enrichment stage.
    from sentinelprior.ingestion.enrichment import epss_records, load_dotenv, nvd_records

    load_dotenv()
    target_date = datetime.now(timezone.utc).date() - timedelta(days=minimum_age_days)
    candidates = cve_paths_from_delta_log(target_date)
    target_date_candidates: list[tuple[datetime, str, str, dict]] = []
    records: list[dict] = []
    errors: list[dict[str, str]] = []
    rejected_counts: dict[str, int] = {}

    print(f"Target CVE publication date (UTC): {target_date}")
    print(f"Found {len(candidates)} new CVE candidate(s) in deltaLog.json for that date")

    for position, (cve_id, source_path) in enumerate(candidates, start=1):
        try:
            source = download_record(cve_id, source_path)
            published = published_at(source)
            if published is None or published.astimezone(timezone.utc).date() != target_date:
                rejected_counts["publication date does not match target date"] = (
                    rejected_counts.get("publication date does not match target date", 0) + 1
                )
                continue
            target_date_candidates.append((published, cve_id, source_path, source))
        except Exception as error:
            errors.append({"cveId": cve_id, "error": str(error)})
        finally:
            if position % 25 == 0 or position == len(candidates):
                print(f"Downloaded {position}/{len(candidates)} target-day candidate records")
            time.sleep(0.1)

    target_date_candidates.sort(key=lambda item: item[0], reverse=True)

    # EPSS supports multiple IDs per request. Query in small batches to keep the
    # request URL manageable, then avoid NVD requests for IDs with no EPSS data.
    epss_by_id: dict[str, dict] = {}
    candidate_ids = [item[1] for item in target_date_candidates]
    for start in range(0, len(candidate_ids), 75):
        epss_by_id.update(epss_records(candidate_ids[start : start + 75]))

    for position, (_published, cve_id, source_path, source) in enumerate(target_date_candidates, start=1):
        if position == 1 or position % 10 == 0:
            print(
                f"Checking NVD/EPSS {position}/{len(target_date_candidates)}; "
                f"accepted {len(records)}/{limit}"
            )
        epss_item = epss_by_id.get(cve_id)
        if not epss_item:
            rejected_counts["missing EPSS score or percentile"] = (
                rejected_counts.get("missing EPSS score or percentile", 0) + 1
            )
            continue

        nvd_item = nvd_records([cve_id]).get(cve_id)
        reasons = readiness_reasons(source, nvd_item, epss_item)
        if reasons:
            for reason in reasons:
                rejected_counts[reason] = rejected_counts.get(reason, 0) + 1
            continue

        # Store the untouched CVEProject record. NVD, EPSS and CISA data are
        # fetched again and attached only during the later enrichment stage.
        records.append({"cveId": cve_id, "sourcePath": source_path, "source": source})
        if position % 10 == 0 or len(records) == limit:
            print(
                f"Validated {position}/{len(target_date_candidates)} records; "
                f"accepted {len(records)}/{limit}"
            )
        if len(records) >= limit:
            break

    payload = {
        "source": REPOSITORY,
        "candidateSource": "cves/deltaLog.json",
        "selectionPolicy": {
            "daysBack": minimum_age_days,
            "targetPublicationDateUtc": target_date.isoformat(),
            "dateRule": "exact UTC publication date, not a 1-to-30-day range",
            "required": [
                "NVD record",
                "affected product or version",
                "NVD English description",
                "NVD CVSS score and severity",
                "FIRST EPSS score and percentile",
            ],
            "nvdStatusRule": "Recorded during enrichment but never used to reject a CVE",
            "cisaKev": "Checked during enrichment; KEV membership is optional",
        },
        "candidateCount": len(candidates),
        "publicationDateMatchedCount": len(target_date_candidates),
        "count": len(records),
        "records": records,
        "rejectedCounts": rejected_counts,
        "errors": errors,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


if __name__ == "__main__":
    raw_path = DATA_DIR / "raw_cves.json"
    result = collect(output_path=str(raw_path))
    print(f"Collected {result['count']} CVE records; {len(result['errors'])} errors")

    from sentinelprior.ingestion.clean_cves import clean_file

    clean_summary = clean_file(
        input_path=raw_path,
        output_path=DATA_DIR / "clean_cves.json",
        comparison_dir=DATA_DIR / "comparison",
    )
    print(
        f"Cleaned {clean_summary['cleanRecordCount']} CVE records; "
        f"size reduction {clean_summary['sizeReductionPercent']}%"
    )
