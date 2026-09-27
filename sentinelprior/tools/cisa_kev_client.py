"""Retrieve CISA's Known Exploited Vulnerabilities catalog."""

from __future__ import annotations

from ..models import KevEvidence
from .http_client import HttpClient


CISA_KEV_JSON = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CISA_KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


class CisaKevClient:
    def __init__(self, http: HttpClient) -> None:
        self.http = http
        self._catalog: dict[str, dict] | None = None
        self._error: str | None = None

    def load_catalog(self) -> None:
        try:
            data = self.http.get_json(CISA_KEV_JSON, stage="CISA KEV")
            self._catalog = {
                item["cveID"].upper(): item
                for item in data.get("vulnerabilities", [])
                if item.get("cveID")
            }
        except RuntimeError as error:
            self._error = str(error)
            self._catalog = None

    def lookup(self, cve_id: str) -> KevEvidence:
        if self._catalog is None and self._error is None:
            self.load_catalog()

        if self._catalog is None:
            return KevEvidence(
                catalog_available=False,
                known_exploited=None,
                source_url=CISA_KEV_PAGE,
                error=self._error or "CISA KEV catalog unavailable",
            )

        item = self._catalog.get(cve_id)
        if not item:
            return KevEvidence(
                catalog_available=True,
                known_exploited=False,
                source_url=CISA_KEV_PAGE,
            )

        return KevEvidence(
            catalog_available=True,
            known_exploited=True,
            vulnerability_name=item.get("vulnerabilityName"),
            date_added=item.get("dateAdded"),
            required_action=item.get("requiredAction"),
            known_ransomware_use=item.get("knownRansomwareCampaignUse"),
            source_url=CISA_KEV_PAGE,
        )
