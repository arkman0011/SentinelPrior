"""Retrieve CVE descriptions and CVSS scores from NVD."""

from __future__ import annotations

import time

from ..models import NvdEvidence
from ..run_logger import RunLogger
from .http_client import HttpClient


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdClient:
    def __init__(
        self,
        http: HttpClient,
        logger: RunLogger,
        api_key: str | None = None,
    ) -> None:
        self.http = http
        self.logger = logger
        self.api_key = api_key

    def fetch(self, cve_id: str) -> NvdEvidence:
        headers = {"apiKey": self.api_key} if self.api_key else None
        try:
            data = self.http.get_json(
                NVD_API_URL,
                stage="NVD",
                params={"cveId": cve_id},
                headers=headers,
            )
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return NvdEvidence(
                    available=False,
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    error="NVD returned no matching vulnerability",
                )

            cve = vulnerabilities[0]["cve"]
            description = next(
                (
                    item.get("value")
                    for item in cve.get("descriptions", [])
                    if item.get("lang") == "en"
                ),
                None,
            )
            score, severity = _extract_cvss(cve.get("metrics", {}))
            return NvdEvidence(
                available=True,
                description=description,
                cvss_score=score,
                severity=severity,
                published=cve.get("published"),
                last_modified=cve.get("lastModified"),
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        except RuntimeError as error:
            return NvdEvidence(
                available=False,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                error=str(error),
            )

    def polite_pause(self) -> None:
        """Respect NVD's lower unauthenticated request rate."""
        time.sleep(0.6 if self.api_key else 6.1)


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        values = metrics.get(metric_name) or []
        if not values:
            continue
        cvss_data = values[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or values[0].get("baseSeverity")
        return score, severity
    return None, None
