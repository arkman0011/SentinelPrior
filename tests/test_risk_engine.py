from sentinelprior.models import (
    EnrichedFinding,
    EpssEvidence,
    KevEvidence,
    NvdEvidence,
    ScanFinding,
)
from sentinelprior.risk_engine import prioritize


def make_finding(*, kev: bool | None, epss: float | None, internet: bool):
    return EnrichedFinding(
        finding=ScanFinding(
            asset_id="AST-001",
            asset_name="payment-api",
            cve_id="CVE-2021-44228",
            internet_exposed=internet,
            business_criticality="critical",
            environment="production",
        ),
        nvd=NvdEvidence(available=True, cvss_score=10.0, severity="CRITICAL"),
        kev=KevEvidence(catalog_available=True, known_exploited=kev),
        epss=EpssEvidence(available=epss is not None, score=epss),
    )


def test_known_exploited_internet_facing_critical_asset_is_p0() -> None:
    result = prioritize(make_finding(kev=True, epss=0.90, internet=True))

    assert result.priority == "P0 - Emergency"
    assert result.risk_score == 100
    assert result.confidence == "high"


def test_missing_epss_reduces_confidence_without_inventing_score() -> None:
    result = prioritize(make_finding(kev=False, epss=None, internet=False))

    assert result.epss.score is None
    assert result.confidence == "medium"
    assert "EPSS score is unavailable" in result.reasons
