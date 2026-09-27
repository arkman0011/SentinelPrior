from sentinelprior.models import EnrichedFinding, EpssEvidence, KevEvidence, NvdEvidence, ScanFinding
from sentinelprior.quality_checks import validate_findings


def test_missing_live_source_becomes_visible_warning() -> None:
    item = EnrichedFinding(
        finding=ScanFinding(
            asset_id="AST-001",
            asset_name="server",
            cve_id="CVE-2021-44228",
            internet_exposed=True,
            business_criticality="high",
            environment="production",
        ),
        nvd=NvdEvidence(available=True),
        kev=KevEvidence(catalog_available=True, known_exploited=False),
        epss=EpssEvidence(available=False, error="timeout"),
        priority="P1 - Urgent",
        risk_score=70,
        confidence="medium",
        reasons=["EPSS score is unavailable"],
        remediation=["Review vendor guidance"],
    )

    assert validate_findings([item]) == ["CVE-2021-44228: EPSS evidence unavailable"]
