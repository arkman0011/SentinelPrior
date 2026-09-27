"""Retrieve current EPSS exploitation probabilities in one batch request."""

from __future__ import annotations

from ..models import EpssEvidence
from .http_client import HttpClient


EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_INFO_URL = "https://www.first.org/epss/"


class EpssClient:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    def fetch_many(
        self, cve_ids: list[str], *, simulate_failure: bool = False
    ) -> dict[str, EpssEvidence]:
        try:
            data = self.http.get_json(
                EPSS_API_URL,
                stage="EPSS",
                params={"cve": ",".join(cve_ids)},
                simulate_failure=simulate_failure,
            )
        except RuntimeError as error:
            return {
                cve_id: EpssEvidence(
                    available=False,
                    source_url=EPSS_INFO_URL,
                    error=str(error),
                )
                for cve_id in cve_ids
            }

        returned = {item.get("cve", "").upper(): item for item in data.get("data", [])}
        results: dict[str, EpssEvidence] = {}
        for cve_id in cve_ids:
            item = returned.get(cve_id)
            if not item:
                results[cve_id] = EpssEvidence(
                    available=False,
                    source_url=EPSS_INFO_URL,
                    error="EPSS returned no score for this CVE",
                )
                continue
            results[cve_id] = EpssEvidence(
                available=True,
                score=float(item["epss"]),
                percentile=float(item["percentile"]),
                score_date=item.get("date"),
                source_url=EPSS_INFO_URL,
            )
        return results
