# Sample Run 3 - Invalid and Duplicate Input

**Executed:** 2026-09-27
**Run ID:** `RUN-20260927-132641-3B37AE`

## Goal

> Show the top 2 urgent vulnerabilities.

## Input problems

The synthetic input contained:

- One duplicated asset/CVE row
- One malformed CVE identifier
- One invalid `internet_exposed` value
- Two valid findings

## Execution trace

```text
[INPUT] SUCCESS Accepted 2 findings
  invalid_rows: 3
  duplicates_removed: 1
[CISA KEV] START Downloading the current KEV catalog
[EPSS] START Requesting 2 scores in one batch
[ENRICH] SUCCESS Prioritized CVE-2021-44228
[ENRICH] SUCCESS Prioritized CVE-2023-44487
[PRIORITIZATION] SUCCESS Selected the top 2 findings
[QA] SUCCESS Final evidence and schema checks passed
```

The invalid rows were preserved in `validation_issues` in the JSON output. They did not stop the two valid rows from being enriched and reported.
