# Sample Run 2 - Deliberately Induced EPSS Failure

**Executed:** 2026-09-27
**Run ID:** `RUN-20260927-132608-54AC37`
**Command option:** `--simulate-epss-failure`

## Visible plan

The agent used the same seven-step operational plan as the normal run, but the EPSS tool was deliberately instructed to raise a timeout.

## Failure and recovery trace

```text
[EPSS] RETRY Attempt 1/3 failed
  error: Timeout: deliberately simulated timeout
[EPSS] RETRY Attempt 2/3 failed
  error: Timeout: deliberately simulated timeout
[EPSS] RETRY Attempt 3/3 failed
  error: Timeout: deliberately simulated timeout

[ENRICH] SUCCESS Prioritized CVE-2021-44228
[ENRICH] SUCCESS Prioritized CVE-2024-3400
[ENRICH] SUCCESS Prioritized CVE-2022-42889
[ENRICH] SUCCESS Prioritized CVE-2021-44832
[ENRICH] SUCCESS Prioritized CVE-2024-3094
[QA]     SUCCESS Final evidence and schema checks passed
```

## Recovery result

- Every EPSS score remained `null`; no value was invented.
- Every finding received an explicit EPSS-unavailable warning.
- Evidence confidence changed from `high` to `medium`.
- Priorities were recalculated using NVD, CISA KEV, and asset context.
- The Markdown and JSON reports were still produced successfully.

Example JSON state:

```json
{
  "available": false,
  "score": null,
  "error": "Timeout: deliberately simulated timeout"
}
```
