"""Prepare compact, source-grounded CVE documents for the future RAG track.

This module reads the existing enriched CVE JSON and writes a separate file.
It does not modify the enriched input, SQLite database, or TextSQL pipeline.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable

from sentinelprior.paths import DATA_DIR


DEFAULT_INPUT = DATA_DIR / "enriched_cves.json"
DEFAULT_OUTPUT = DATA_DIR / "rag_cve_documents.json"


def clean_text(value: Any) -> str:
    """Collapse repeated whitespace without changing the source wording."""
    return re.sub(r"\s+", " ", str(value or "")).strip()


def unique_text(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = clean_text(value)
        marker = text.casefold()
        if text and marker not in seen:
            result.append(text)
            seen.add(marker)
    return result


def version_text(version: dict[str, Any]) -> str:
    start = clean_text(version.get("version"))
    status = clean_text(version.get("status"))
    boundaries = (
        ("versionStartIncluding", "from"),
        ("versionStartExcluding", "after"),
        ("lessThan", "before"),
        ("versionEndExcluding", "before"),
        ("lessThanOrEqual", "through"),
        ("versionEndIncluding", "through"),
    )
    parts = [start] if start and start not in {"0", "*"} else []
    for key, label in boundaries:
        value = clean_text(version.get(key))
        if value:
            parts.append(f"{label} {value}")
    if status:
        parts.append(f"({status})")
    return " ".join(parts) or "affected version range not specified"


def affected_lines(record: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    lines: list[str] = []
    vendors: list[str] = []
    products: list[str] = []

    for item in record.get("affected") or []:
        if not isinstance(item, dict):
            continue
        vendor = clean_text(item.get("vendor"))
        product = clean_text(item.get("product"))
        package = clean_text(item.get("packageName"))
        vendors.extend([vendor] if vendor else [])
        products.extend([product] if product else [])
        identity = " / ".join(part for part in (vendor, product, package) if part)
        versions = [version_text(version) for version in item.get("versions") or [] if isinstance(version, dict)]
        modules = unique_text(item.get("modules") or [])
        details = []
        if versions:
            details.append("versions: " + "; ".join(versions))
        if modules:
            details.append("components: " + "; ".join(modules))
        line = identity or "Affected product not named"
        if details:
            line += " — " + "; ".join(details)
        lines.append(line)

    # Some NVD records provide additional vulnerable CPE products that are not
    # present in the CVEProject affected list. Keep only their readable fields.
    for item in record.get("nvdAffectedProducts") or []:
        if not isinstance(item, dict):
            continue
        vendor = clean_text(item.get("vendor"))
        product = clean_text(item.get("product"))
        vendors.extend([vendor] if vendor else [])
        products.extend([product] if product else [])
        identity = " / ".join(part for part in (vendor, product) if part)
        ranges = []
        for key, label in (
            ("version", "version"),
            ("versionStartIncluding", "from"),
            ("versionStartExcluding", "after"),
            ("versionEndIncluding", "through"),
            ("versionEndExcluding", "before"),
        ):
            value = clean_text(item.get(key))
            if value:
                ranges.append(f"{label} {value}")
        if identity:
            lines.append(identity + (" — " + ", ".join(ranges) if ranges else ""))

    return unique_text(lines), unique_text(vendors), unique_text(products)


def weakness_lines(record: dict[str, Any]) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    ids: list[str] = []
    for item in record.get("weaknesses") or []:
        if not isinstance(item, dict):
            continue
        cwe_id = clean_text(item.get("id"))
        description = clean_text(item.get("description"))
        if cwe_id:
            ids.append(cwe_id)
        if cwe_id or description:
            if cwe_id and description.casefold().startswith(cwe_id.casefold()):
                description = description[len(cwe_id) :].lstrip(" :-")
            lines.append(" — ".join(part for part in (cwe_id, description) if part))
    ids.extend(record.get("cwes") or [])
    for cwe_id in unique_text(ids):
        if not any(cwe_id.casefold() in line.casefold() for line in lines):
            lines.append(cwe_id)
    return unique_text(lines), unique_text(ids)


def cvss_sections(cvss: dict[str, Any]) -> tuple[str, str]:
    attack_parts = []
    for label, key in (
        ("Attack vector", "attackVector"),
        ("Attack complexity", "attackComplexity"),
        ("Privileges required", "privilegesRequired"),
        ("User interaction", "userInteraction"),
        ("Scope", "scope"),
    ):
        value = clean_text(cvss.get(key))
        if value:
            attack_parts.append(f"{label}: {value}")

    impact_parts = []
    for label, key in (
        ("Confidentiality", "confidentialityImpact"),
        ("Integrity", "integrityImpact"),
        ("Availability", "availabilityImpact"),
    ):
        value = clean_text(cvss.get(key))
        if value:
            impact_parts.append(f"{label}: {value}")
    return "; ".join(attack_parts), "; ".join(impact_parts)


def reference_urls(record: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in record.get("references") or []:
        if isinstance(item, dict):
            values.append(item.get("url"))
        else:
            values.append(item)
    for item in (record.get("nvd") or {}).get("references") or []:
        if isinstance(item, dict):
            values.append(item.get("url"))
    return unique_text(values)


def guidance_text(value: Any) -> list[str]:
    """Read explicit solution-like text without inventing missing guidance."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(guidance_text(item))
        return unique_text(values)
    if isinstance(value, dict):
        values = []
        for key in ("value", "text", "description", "action", "solution", "remediation"):
            if key in value:
                values.extend(guidance_text(value.get(key)))
        return unique_text(values)
    return []


def remediation_lines(record: dict[str, Any]) -> list[str]:
    """Build source-grounded actions from explicit guidance and affected ranges."""
    lines: list[str] = []
    for key in ("solutions", "solution", "remediations", "remediation", "mitigations", "workarounds"):
        lines.extend(guidance_text(record.get(key)))

    kev_details = ((record.get("cisaKev") or {}).get("details") or {})
    required_action = clean_text(kev_details.get("requiredAction"))
    if required_action:
        lines.append(f"CISA required action: {required_action}")

    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        vendor = clean_text(affected.get("vendor"))
        product = clean_text(affected.get("product"))
        identity = " / ".join(part for part in (vendor, product) if part) or "the affected product"
        for version in affected.get("versions") or []:
            if not isinstance(version, dict) or clean_text(version.get("status")).casefold() != "affected":
                continue
            # An exclusive upper boundary is direct evidence that the named
            # boundary itself is outside this published affected range.
            fixed_boundary = clean_text(
                version.get("lessThan") or version.get("versionEndExcluding")
            )
            if fixed_boundary:
                lines.append(
                    f"Upgrade {identity} to version {fixed_boundary} or a later vendor-supported release; "
                    f"the published affected range ends before {fixed_boundary}."
                )
    return unique_text(lines)


def vendor_solution_lines(record: dict[str, Any]) -> list[str]:
    """Keep official patch, advisory, and release-note references as fix evidence."""
    solution_tags = {
        "patch",
        "release-notes",
        "vendor-advisory",
        "mitigation",
        "workaround",
    }
    lines: list[str] = []
    references = list(record.get("references") or [])
    references.extend((record.get("nvd") or {}).get("references") or [])
    for item in references:
        if not isinstance(item, dict):
            continue
        tags = {clean_text(tag).casefold() for tag in item.get("tags") or []}
        if not tags.intersection(solution_tags):
            continue
        url = clean_text(item.get("url"))
        if not url:
            continue
        name = clean_text(item.get("name"))
        label = name or ", ".join(sorted(tags.intersection(solution_tags)))
        lines.append(f"{label}: {url}" if label else url)
    return unique_text(lines)


def add_section(parts: list[str], heading: str, content: str | list[str]) -> None:
    if isinstance(content, list):
        text = "\n".join(f"- {item}" for item in content if item)
    else:
        text = clean_text(content)
    if text:
        parts.append(f"{heading}:\n{text}")


def rag_document(record: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = clean_text(record.get("cveId"))
    description = clean_text(record.get("description"))
    if not cve_id or not description:
        return None

    cvss = record.get("cvss") or {}
    epss = record.get("epss") or {}
    kev = record.get("cisaKev") or {}
    kev_details = kev.get("details") or {}
    affected, vendors, products = affected_lines(record)
    weaknesses, cwe_ids = weakness_lines(record)
    attack_conditions, security_impact = cvss_sections(cvss)
    remediation = remediation_lines(record)
    vendor_solutions = vendor_solution_lines(record)
    sources = reference_urls(record)

    content_parts = [f"CVE ID: {cve_id}"]
    add_section(content_parts, "Summary", description)
    add_section(content_parts, "Affected systems", affected)
    add_section(content_parts, "Weaknesses", weaknesses)
    add_section(content_parts, "Attack conditions", attack_conditions)
    add_section(content_parts, "Security impact", security_impact)
    add_section(content_parts, "Remediation", remediation)
    add_section(content_parts, "Vendor solution", vendor_solutions)
    add_section(content_parts, "CISA KEV vulnerability", clean_text(kev_details.get("vulnerabilityName")))
    add_section(content_parts, "CISA required action", clean_text(kev_details.get("requiredAction")))
    add_section(content_parts, "CISA notes", clean_text(kev_details.get("notes")))
    add_section(content_parts, "Official references", sources)

    metadata = {
        "cveId": cve_id,
        "description": description,
        "vendors": vendors,
        "products": products,
        "cweIds": cwe_ids,
        "cvssScore": cvss.get("score"),
        "severity": cvss.get("severity"),
        "cvssVector": cvss.get("vector"),
        "epssScore": epss.get("epss"),
        "epssPercentile": epss.get("percentile"),
        "kevListed": bool(kev.get("listed")),
        "publishedDate": record.get("datePublished") or (record.get("nvd") or {}).get("published"),
        "updatedDate": record.get("dateUpdated") or (record.get("nvd") or {}).get("lastModified"),
        "remediation": remediation,
        "vendorSolutions": vendor_solutions,
        "source": "CVEProject + NVD + FIRST EPSS + CISA KEV",
    }
    # Keep false and numeric zero values; remove only absent or empty values.
    metadata = {key: value for key, value in metadata.items() if value not in (None, "", [])}
    return {
        "documentId": cve_id,
        "content": "\n\n".join(content_parts),
        "metadata": metadata,
    }


def prepare_rag_documents(input_path: Path = DEFAULT_INPUT, output_path: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    source = json.loads(input_path.read_text(encoding="utf-8-sig"))
    records = source.get("records") if isinstance(source, dict) else None
    if not isinstance(records, list):
        raise ValueError(f"Expected a top-level records list in {input_path}")

    documents: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, dict):
            skipped.append({"cveId": "unknown", "reason": "record is not an object"})
            continue
        document = rag_document(record)
        if document is None:
            skipped.append(
                {
                    "cveId": clean_text(record.get("cveId")) or "unknown",
                    "reason": "missing CVE ID or description",
                }
            )
            continue
        documents.append(document)

    try:
        source_file = input_path.resolve().relative_to(DATA_DIR.parent).as_posix()
    except ValueError:
        source_file = str(input_path.resolve())

    payload = {
        "stage": "rag-prepared",
        "sourceFile": source_file,
        "count": len(documents),
        "documents": documents,
        "skipped": skipped,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare clean CVE documents for the SentinelPrior RAG track")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="enriched CVE JSON input")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="clean RAG document JSON output")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    payload = prepare_rag_documents(args.input, args.output)
    print(f"Prepared {payload['count']} RAG document(s).")
    print(f"Skipped {len(payload['skipped'])} record(s).")
    print(f"Saved: {args.output.resolve()}")


if __name__ == "__main__":
    main()
