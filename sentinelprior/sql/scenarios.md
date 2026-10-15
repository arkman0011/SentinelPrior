# SentinelPrior TextSQL guidance

## Database scope

The SQLite database contains one table named `cves`. Each row represents one
enriched CVE record. Answer factual database questions from this table only.

## Column meanings

- `cve_id` is the unique CVE identifier.
- `vendor` and `product` may contain comma-separated values when a CVE affects
  more than one vendor or product.
- `cvss_score` is technical severity from 0 to 10.
- `cvss_severity` is normally LOW, MEDIUM, HIGH, or CRITICAL.
- `epss_score` is an exploitation probability from 0 to 1. A value of 0.82
  means 82 percent.
- `epss_percentile` is a relative ranking from 0 to 1.
- `cisa_kev_listed` is 1 when CISA lists the CVE as known exploited and 0 when
  it does not.
- `known_ransomware_use` records CISA's known ransomware campaign assessment.
- `remediation` contains source-grounded corrective guidance when available.
- `vendor_solutions` contains official patch, advisory, or release-note links.
- `cisa_required_action` contains instructions only for CISA KEV records and
  must not be treated as the only remediation source.
- `published_at` and `updated_at` are ISO date-time strings.
- `cwes` contains comma-separated CWE identifiers.

## Meaning of company

When the user says company, organization, manufacturer, or publisher in an
affected-product question, use the `vendor` column unless the wording clearly
asks for something else.

## Meaning of most dangerous

For "most dangerous", "highest risk", or similar wording, order by:

1. `cisa_kev_listed DESC`
2. `cvss_score DESC`
3. `epss_score DESC`

Do not say that a high CVSS or EPSS score proves exploitation.

## Top CVSS CVEs

Question: Which five CVEs have the highest CVSS score?

    SELECT cve_id, vendor, product, cvss_score, cvss_severity,
           epss_score, cisa_kev_listed
    FROM cves
    WHERE cvss_score IS NOT NULL
    ORDER BY cvss_score DESC, epss_score DESC
    LIMIT 5;

## Top EPSS CVEs

Question: Show the five CVEs most likely to be exploited according to EPSS.

    SELECT cve_id, vendor, product, epss_score, epss_percentile,
           cvss_score, cisa_kev_listed
    FROM cves
    WHERE epss_score IS NOT NULL
    ORDER BY epss_score DESC
    LIMIT 5;

## Vendor with highest CVSS

Question: Which vendor has the vulnerability with the highest CVSS score?

    SELECT vendor, cve_id, product, cvss_score, cvss_severity
    FROM cves
    WHERE vendor IS NOT NULL AND cvss_score IS NOT NULL
    ORDER BY cvss_score DESC, epss_score DESC
    LIMIT 1;

## CVEs at a requested score

Question: Which CVEs have a CVSS score of 6?

Use a numeric comparison and do not interpret the requested number as a CVE
identifier.

    SELECT cve_id, vendor, product, cvss_score, cvss_severity
    FROM cves
    WHERE cvss_score = 6.0
    ORDER BY epss_score DESC;

## CISA KEV records

Question: Show all known exploited vulnerabilities.

    SELECT cve_id, vendor, product, cvss_score, epss_score,
           cisa_date_added, cisa_due_date, cisa_required_action
    FROM cves
    WHERE cisa_kev_listed = 1
    ORDER BY cisa_date_added DESC;

## Counts by severity

Question: How many CVEs are in each severity category?

    SELECT cvss_severity, COUNT(*) AS cve_count
    FROM cves
    GROUP BY cvss_severity
    ORDER BY cve_count DESC;

## Exact CVE lookup

Question: Tell me about CVE-2026-12345.

    SELECT cve_id, description, vendor, product, published_at, nvd_status,
           cvss_score, cvss_severity, cvss_vector, epss_score,
           epss_percentile, cisa_kev_listed, cwes
    FROM cves
    WHERE UPPER(cve_id) = UPPER('CVE-2026-12345');

## CVEs with remediation

Question: Which CVE IDs have remediation or an official vendor solution?

    SELECT cve_id, remediation, vendor_solutions, cisa_required_action
    FROM cves
    WHERE NULLIF(remediation, '') IS NOT NULL
       OR NULLIF(vendor_solutions, '') IS NOT NULL
       OR NULLIF(cisa_required_action, '') IS NOT NULL
    ORDER BY cve_id;

## Remediation for one CVE

Question: What remediation is available for CVE-2026-12345?

    SELECT cve_id, remediation, vendor_solutions, cisa_required_action
    FROM cves
    WHERE UPPER(cve_id) = UPPER('CVE-2026-12345');
