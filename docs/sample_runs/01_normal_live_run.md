# Sample Run 1 - Normal Live Enrichment

**Executed:** 2026-09-27
**Run ID:** `RUN-20260927-132527-64FD43`
**Mode:** Deterministic AI fallback because no assessment API key was stored
**Live tools verified:** NVD, CISA KEV, FIRST EPSS

## Goal

> Analyse this vulnerability scan for our internet-facing payment application, identify the five findings requiring immediate action, and prepare an evidence-backed remediation report.

## Visible plan

1. Validate the scanner CSV.
2. Retrieve NVD evidence.
3. Check CISA KEV.
4. Retrieve FIRST EPSS.
5. Apply priority rules.
6. Run quality checks.
7. Write Markdown and JSON reports.

## Representative execution trace

```text
[INPUT]          SUCCESS  Accepted 5 findings
[CISA KEV]       START    Downloading the current KEV catalog
[EPSS]           START    Requesting 5 scores in one batch
[ENRICH]         SUCCESS  Prioritized CVE-2021-44228
[ENRICH]         SUCCESS  Prioritized CVE-2024-3400
[ENRICH]         SUCCESS  Prioritized CVE-2022-42889
[ENRICH]         SUCCESS  Prioritized CVE-2021-44832
[ENRICH]         SUCCESS  Prioritized CVE-2024-3094
[PRIORITIZATION] SUCCESS  Selected the top 5 findings
[QA]             SUCCESS  Final evidence and schema checks passed
```

## Final structured result summary

| CVE | Priority | Score | KEV | EPSS available | Confidence |
|---|---|---:|---|---|---|
| CVE-2021-44228 | P0 - Emergency | 100 | Yes | Yes | High |
| CVE-2024-3400 | P0 - Emergency | 100 | Yes | Yes | High |
| CVE-2022-42889 | P1 - Urgent | 65 | No | Yes | High |
| CVE-2024-3094 | P3 - Normal | 35 | No | Yes | High |
| CVE-2021-44832 | P3 - Normal | 33 | No | Yes | High |

All three public sources returned usable live evidence and the report contained no source-availability warnings.
