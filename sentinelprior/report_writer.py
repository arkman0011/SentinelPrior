"""Write human-readable and machine-readable assessment artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from .models import RunResult


def write_outputs(result: RunResult, output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "vulnerability_report.json"
    markdown_path = output_dir / "vulnerability_report.md"
    log_path = output_dir / "execution_log.json"
    transcript_path = output_dir / "run_transcript.md"

    json_path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    log_path.write_text(
        json.dumps(
            [event.model_dump(mode="json") for event in result.events], indent=2
        ),
        encoding="utf-8",
    )
    markdown_path.write_text(_build_markdown(result), encoding="utf-8")
    transcript_path.write_text(_build_transcript(result), encoding="utf-8")
    return {
        "markdown": markdown_path,
        "json": json_path,
        "log": log_path,
        "transcript": transcript_path,
    }


def _build_markdown(result: RunResult) -> str:
    lines = [
        "# SentinelPrior Vulnerability Triage Report",
        "",
        f"**Run ID:** `{result.run_id}`  ",
        f"**Goal:** {result.goal}  ",
        f"**AI mode:** {result.ai_mode}  ",
        f"**Input file:** `{result.input_file}`  ",
        "",
        "> Safety boundary: this tool prioritizes scanner findings. It does not scan, exploit, patch, or modify systems. A qualified human must verify applicability and approve remediation.",
        "",
        "## Executive Summary",
        "",
        result.executive_summary,
        "",
        f"**Overall recommendation:** {result.overall_recommendation}",
        "",
        "## Input Summary",
        "",
        f"- Valid findings: {result.input_summary['valid_findings']}",
        f"- Invalid rows: {result.input_summary['invalid_rows']}",
        f"- Duplicates removed: {result.input_summary['duplicates_removed']}",
        f"- Findings selected: {len(result.findings)}",
        "",
        "## Prioritized Findings",
        "",
        "| Rank | CVE | Asset | Priority | Score | Confidence | KEV | EPSS |",
        "|---:|---|---|---|---:|---|---|---:|",
    ]
    for rank, item in enumerate(result.findings, start=1):
        kev = "Yes" if item.kev.known_exploited is True else "No" if item.kev.known_exploited is False else "Unknown"
        epss = f"{item.epss.score:.1%}" if item.epss.score is not None else "Unavailable"
        lines.append(
            f"| {rank} | {item.finding.cve_id} | {item.finding.asset_name} | "
            f"{item.priority} | {item.risk_score} | {item.confidence} | {kev} | {epss} |"
        )

    for rank, item in enumerate(result.findings, start=1):
        lines.extend(
            [
                "",
                f"### {rank}. {item.finding.cve_id} on {item.finding.asset_name}",
                "",
                f"- **Priority:** {item.priority}",
                f"- **Risk score:** {item.risk_score}/100",
                f"- **Evidence confidence:** {item.confidence}",
                f"- **Internet exposed:** {item.finding.internet_exposed}",
                f"- **Business criticality:** {item.finding.business_criticality.value}",
                f"- **Environment:** {item.finding.environment}",
                f"- **NVD severity:** {item.nvd.severity or 'Unavailable'}",
                f"- **NVD CVSS:** {item.nvd.cvss_score if item.nvd.cvss_score is not None else 'Unavailable'}",
                f"- **CISA KEV:** {_kev_text(item.kev.known_exploited, item.kev.catalog_available)}",
                f"- **EPSS:** {f'{item.epss.score:.1%}' if item.epss.score is not None else 'Unavailable'}",
                "",
                "**Why it received this priority**",
                "",
                *[f"- {reason}" for reason in item.reasons],
                "",
                "**Recommended defensive actions**",
                "",
                *[f"- {action}" for action in item.remediation],
                "",
                "**Sources**",
                "",
                f"- [NVD]({item.nvd.source_url})",
                f"- [CISA KEV]({item.kev.source_url})",
                f"- [FIRST EPSS]({item.epss.source_url})",
            ]
        )
        errors = [item.nvd.error, item.kev.error, item.epss.error]
        errors = [error for error in errors if error]
        if errors:
            lines.extend(["", "**Missing-data notes**", "", *[f"- {error}" for error in errors]])

    lines.extend(["", "## Warnings", ""])
    lines.extend([f"- {warning}" for warning in result.warnings] or ["- None"])
    lines.extend(
        [
            "",
            "## Synthetic Data Disclosure",
            "",
            "The included sample assets, exposure values, environments, and business criticalities are fictional. Real public CVE identifiers are used only to exercise live NVD, CISA KEV, and FIRST EPSS enrichment. The samples do not represent Xiarch, any Xiarch customer, or any real production environment.",
            "",
            "## Limitations",
            "",
            "- A CVE in a scanner row does not prove that the asset is actually vulnerable.",
            "- Absence from CISA KEV does not prove that exploitation has never occurred.",
            "- EPSS is a probability estimate, not a guarantee.",
            "- The demonstration priority rules must be reviewed before production use.",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_transcript(result: RunResult) -> str:
    lines = [
        f"# Run Transcript - {result.run_id}",
        "",
        "## Visible Plan",
        "",
    ]
    for step in result.plan.steps:
        lines.append(f"{step.number}. **{step.action}** - {step.purpose}")
    lines.extend(["", "## Tool and Control Trace", ""])
    for event in result.events:
        details = f" - `{json.dumps(event.details)}`" if event.details else ""
        lines.append(
            f"- `{event.timestamp}` **{event.stage}/{event.status}**: {event.message}{details}"
        )
    lines.extend(
        [
            "",
            "## Final Result",
            "",
            f"Generated {len(result.findings)} prioritized findings using {result.ai_mode}.",
        ]
    )
    return "\n".join(lines) + "\n"


def _kev_text(value: bool | None, catalog_available: bool) -> str:
    if not catalog_available:
        return "Unknown - catalog unavailable"
    if value is True:
        return "Yes - confirmed in catalog"
    return "Not found in catalog at retrieval time"
