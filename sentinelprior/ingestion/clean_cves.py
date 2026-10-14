"""Flatten raw CVEProject JSON into compact CVE records and text cards.

This is a cleaning step only. It does not call NVD, FIRST EPSS, CISA KEV,
or an LLM, and it does not calculate risk scores.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable

from sentinelprior.paths import DATA_DIR


DEFAULT_INPUT = DATA_DIR / "raw_cves.json"
DEFAULT_OUTPUT = DATA_DIR / "clean_cves.json"
DEFAULT_COMPARISON_DIR = DATA_DIR / "comparison"
CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)


def compact_text(value: Any) -> str | None:
    """Return readable single-spaced text or None for an empty value."""
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    return cleaned or None


def unique_strings(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = compact_text(value)
        if cleaned and cleaned.casefold() not in seen:
            result.append(cleaned)
            seen.add(cleaned.casefold())
    return result


def remove_empty(value: Any) -> Any:
    """Recursively remove null, empty string, empty list, and empty dict values."""
    if isinstance(value, dict):
        cleaned = {key: remove_empty(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item not in (None, "", [], {})}
    if isinstance(value, list):
        cleaned = [remove_empty(item) for item in value]
        return [item for item in cleaned if item not in (None, "", [], {})]
    if isinstance(value, str):
        return compact_text(value)
    return value


def english_description(descriptions: Any) -> str | None:
    if not isinstance(descriptions, list):
        return None
    candidates = [item for item in descriptions if isinstance(item, dict)]
    for language in ("en", "en-US", "en-GB"):
        for item in candidates:
            if item.get("lang") == language:
                value = compact_text(item.get("value") or item.get("description"))
                if value:
                    return value
    for item in candidates:
        value = compact_text(item.get("value") or item.get("description"))
        if value:
            return value
    return None


def clean_problem_types(problem_types: Any) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(problem_types, list):
        return result

    for group in problem_types:
        descriptions = group.get("descriptions", []) if isinstance(group, dict) else []
        for item in descriptions if isinstance(descriptions, list) else []:
            if not isinstance(item, dict):
                continue
            description = compact_text(item.get("description") or item.get("value"))
            cwe_id = compact_text(item.get("cweId"))
            if not cwe_id and description:
                match = CWE_PATTERN.search(description)
                cwe_id = match.group(0).upper() if match else None
            entry = remove_empty({"id": cwe_id, "description": description})
            key = (str(entry.get("id", "")).casefold(), str(entry.get("description", "")).casefold())
            if entry and key not in seen:
                result.append(entry)
                seen.add(key)
    return result


def clean_versions(versions: Any) -> list[dict[str, Any]]:
    allowed = (
        "version",
        "status",
        "versionType",
        "lessThan",
        "lessThanOrEqual",
    )
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for version in versions if isinstance(versions, list) else []:
        if not isinstance(version, dict):
            continue
        entry = remove_empty({key: version.get(key) for key in allowed})
        marker = json.dumps(entry, sort_keys=True)
        if entry and marker not in seen:
            result.append(entry)
            seen.add(marker)
    return result


def clean_affected(affected: Any) -> list[dict[str, Any]]:
    scalar_fields = ("vendor", "product", "packageName", "repo", "collectionURL", "defaultStatus")
    list_fields = ("platforms", "modules", "programFiles", "cpes")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in affected if isinstance(affected, list) else []:
        if not isinstance(item, dict):
            continue
        entry: dict[str, Any] = {key: item.get(key) for key in scalar_fields}
        for key in list_fields:
            entry[key] = unique_strings(item.get(key, []) if isinstance(item.get(key), list) else [])
        entry["versions"] = clean_versions(item.get("versions"))

        routines = item.get("programRoutines")
        if isinstance(routines, list):
            entry["programRoutines"] = unique_strings(
                routine.get("name") if isinstance(routine, dict) else routine for routine in routines
            )

        entry = remove_empty(entry)
        marker = json.dumps(entry, sort_keys=True)
        if entry and marker not in seen:
            result.append(entry)
            seen.add(marker)
    return result


def clean_references(references: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for item in references if isinstance(references, list) else []:
        if not isinstance(item, dict):
            continue
        url = compact_text(item.get("url"))
        if not url or url in seen_urls:
            continue
        entry = remove_empty(
            {
                "url": url,
                "name": compact_text(item.get("name")),
                "tags": unique_strings(item.get("tags", []) if isinstance(item.get("tags"), list) else []),
            }
        )
        result.append(entry)
        seen_urls.add(url)
    return result


def version_label(version: dict[str, Any]) -> str:
    start = version.get("version")
    end_exclusive = version.get("lessThan")
    end_inclusive = version.get("lessThanOrEqual")
    status = version.get("status")
    parts = [str(start)] if start else []
    if end_exclusive:
        parts.append(f"to before {end_exclusive}")
    elif end_inclusive:
        parts.append(f"through {end_inclusive}")
    if status:
        parts.append(f"({status})")
    return " ".join(parts)


def build_text_card(record: dict[str, Any]) -> str:
    """Build compact evidence text for later keyword/vector indexing."""
    lines = [f"CVE ID: {record['cveId']}"]
    for label, key in (
        ("Title", "title"),
        ("Status", "state"),
        ("Published", "datePublished"),
        ("Updated", "dateUpdated"),
        ("Description", "description"),
    ):
        if record.get(key):
            lines.append(f"{label}: {record[key]}")

    weaknesses = record.get("weaknesses", [])
    if weaknesses:
        values = [item.get("description") or item.get("id") for item in weaknesses]
        lines.append(f"Weaknesses: {'; '.join(value for value in values if value)}")

    for item in record.get("affected", []):
        identity = " / ".join(
            str(value) for value in (item.get("vendor"), item.get("product"), item.get("packageName")) if value
        )
        versions = [version_label(version) for version in item.get("versions", [])]
        detail = f"; versions: {', '.join(value for value in versions if value)}" if versions else ""
        if identity:
            lines.append(f"Affected: {identity}{detail}")

    reference_urls = [item.get("url") for item in record.get("references", [])[:5] if item.get("url")]
    if reference_urls:
        lines.append(f"References: {'; '.join(reference_urls)}")
    return "\n".join(lines)


def unwrap_record(item: Any) -> tuple[dict[str, Any], str | None, str | None]:
    """Return CVE source, wrapper CVE ID, and repository path."""
    if not isinstance(item, dict):
        return {}, None, None
    if isinstance(item.get("source"), dict):
        return item["source"], compact_text(item.get("cveId")), compact_text(item.get("sourcePath"))
    return item, compact_text(item.get("cveId")), compact_text(item.get("sourcePath"))


def clean_record(item: Any) -> dict[str, Any]:
    source, wrapper_id, source_path = unwrap_record(item)
    metadata = source.get("cveMetadata") if isinstance(source.get("cveMetadata"), dict) else {}
    containers = source.get("containers") if isinstance(source.get("containers"), dict) else {}
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
    cve_id = compact_text(metadata.get("cveId")) or wrapper_id
    if not cve_id:
        raise ValueError("CVE record has no cveId")

    record = remove_empty(
        {
            "cveId": cve_id.upper(),
            "state": compact_text(metadata.get("state")),
            "dateReserved": compact_text(metadata.get("dateReserved")),
            "datePublished": compact_text(metadata.get("datePublished")),
            "dateUpdated": compact_text(metadata.get("dateUpdated")),
            "assigner": compact_text(metadata.get("assignerShortName")),
            "title": compact_text(cna.get("title")),
            "description": english_description(cna.get("descriptions")),
            "weaknesses": clean_problem_types(cna.get("problemTypes")),
            "affected": clean_affected(cna.get("affected")),
            "references": clean_references(cna.get("references")),
            "sourcePath": source_path,
        }
    )
    record["textCard"] = build_text_card(record)
    return record


def source_records(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise ValueError("Input must be a CVE object, a list, or an object containing records")
    if isinstance(payload.get("records"), list):
        return payload["records"]
    if "cveMetadata" in payload:
        return [payload]
    raise ValueError("Input does not contain CVE records")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def clean_file(input_path: Path, output_path: Path, comparison_dir: Path) -> dict[str, Any]:
    raw_bytes_before = input_path.read_bytes()
    raw_payload = json.loads(raw_bytes_before.decode("utf-8-sig"))
    raw_records = source_records(raw_payload)

    cleaned: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for index, item in enumerate(raw_records):
        try:
            cleaned.append(clean_record(item))
        except (TypeError, ValueError) as error:
            errors.append({"recordIndex": str(index), "error": str(error)})

    clean_payload = {
        "stage": "clean",
        "source": raw_payload.get("source", "CVEProject/cvelistV5") if isinstance(raw_payload, dict) else "CVEProject/cvelistV5",
        "count": len(cleaned),
        "records": cleaned,
        "errors": errors,
    }
    clean_payload = remove_empty(clean_payload)
    write_json(output_path, clean_payload)

    # Keep a side-by-side sample and numerical summary for physical inspection.
    comparison_dir.mkdir(parents=True, exist_ok=True)
    # Prevent a zero-result run from displaying samples left by an older run.
    (comparison_dir / "raw_sample.json").unlink(missing_ok=True)
    (comparison_dir / "clean_sample.json").unlink(missing_ok=True)
    if raw_records and cleaned:
        write_json(comparison_dir / "raw_sample.json", raw_records[0])
        write_json(comparison_dir / "clean_sample.json", cleaned[0])

    raw_size = len(raw_bytes_before)
    clean_size = output_path.stat().st_size
    reduction = round((1 - clean_size / raw_size) * 100, 2) if raw_size else 0.0
    summary = {
        "rawFile": str(input_path.resolve()),
        "cleanFile": str(output_path.resolve()),
        "rawRecordCount": len(raw_records),
        "cleanRecordCount": len(cleaned),
        "failedRecordCount": len(errors),
        "rawBytes": raw_size,
        "cleanBytes": clean_size,
        "sizeReductionPercent": reduction,
        "rawFileUnchanged": input_path.read_bytes() == raw_bytes_before,
        "removedOrDeferred": [
            "CVE schema labels such as dataType and dataVersion",
            "provider UUID metadata and generator metadata",
            "credits and CNA workflow metadata",
            "non-English duplicate descriptions",
            "duplicate references and empty values",
            "ADP containers and source metrics; NVD, EPSS and CISA KEV belong to enrichment",
        ],
    }
    write_json(comparison_dir / "summary.json", summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clean raw CVEProject JSON without enriching it")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="raw CVE JSON input")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="clean CVE JSON output")
    parser.add_argument(
        "--comparison-dir",
        type=Path,
        default=DEFAULT_COMPARISON_DIR,
        help="folder for raw sample, clean sample, and size summary",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.input.exists():
        raise SystemExit(
            f"Raw file not found: {args.input}. Run collector.py first or pass --input with a raw CVE JSON file."
        )
    summary = clean_file(args.input, args.output, args.comparison_dir)
    print(f"Cleaned {summary['cleanRecordCount']} of {summary['rawRecordCount']} CVE records")
    print(f"Raw file:   {summary['rawFile']}")
    print(f"Clean file: {summary['cleanFile']}")
    print(f"Size reduction: {summary['sizeReductionPercent']}%")
    print(f"Comparison: {(args.comparison_dir / 'summary.json').resolve()}")


if __name__ == "__main__":
    main()
