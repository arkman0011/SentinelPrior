"""Transparent and testable vulnerability-priority rules."""

from __future__ import annotations

from .models import Criticality, EnrichedFinding


def prioritize(item: EnrichedFinding) -> EnrichedFinding:
    """Add score, priority, confidence, reasons and safe remediation guidance."""
    score = 0
    reasons: list[str] = []

    if item.kev.known_exploited is True:
        score += 40
        reasons.append("CISA KEV confirms exploitation in the wild")
    elif item.kev.known_exploited is False:
        reasons.append("Not listed in CISA KEV at retrieval time")
    else:
        reasons.append("CISA KEV status is unavailable")

    if item.epss.score is not None:
        if item.epss.score >= 0.70:
            score += 25
            reasons.append(f"EPSS exploitation probability is high ({item.epss.score:.1%})")
        elif item.epss.score >= 0.30:
            score += 18
            reasons.append(f"EPSS exploitation probability is elevated ({item.epss.score:.1%})")
        elif item.epss.score >= 0.10:
            score += 10
            reasons.append(f"EPSS exploitation probability is notable ({item.epss.score:.1%})")
        else:
            reasons.append(f"EPSS exploitation probability is currently low ({item.epss.score:.1%})")
    else:
        reasons.append("EPSS score is unavailable")

    if item.finding.internet_exposed:
        score += 15
        reasons.append("The fictional asset context marks the system as internet-facing")

    criticality_points = {
        Criticality.critical: 15,
        Criticality.high: 10,
        Criticality.medium: 5,
        Criticality.low: 0,
    }
    score += criticality_points[item.finding.business_criticality]
    reasons.append(
        f"Business criticality is {item.finding.business_criticality.value}"
    )

    if item.finding.environment.lower() == "production":
        score += 5
        reasons.append("The fictional asset context marks the system as production")

    if item.nvd.cvss_score is not None:
        if item.nvd.cvss_score >= 9.0:
            score += 10
        elif item.nvd.cvss_score >= 7.0:
            score += 7
        elif item.nvd.cvss_score >= 4.0:
            score += 3
        reasons.append(
            f"NVD CVSS score is {item.nvd.cvss_score:.1f} ({item.nvd.severity or 'unrated'})"
        )
    else:
        reasons.append("NVD CVSS score is unavailable")

    score = min(score, 100)
    high_value_asset = item.finding.business_criticality in {
        Criticality.high,
        Criticality.critical,
    }
    if (
        item.kev.known_exploited is True
        and item.finding.internet_exposed
        and high_value_asset
    ) or score >= 85:
        priority = "P0 - Emergency"
    elif item.kev.known_exploited is True or score >= 65:
        priority = "P1 - Urgent"
    elif score >= 40:
        priority = "P2 - High"
    else:
        priority = "P3 - Normal"

    missing_sources = sum(
        [
            not item.nvd.available,
            not item.kev.catalog_available,
            not item.epss.available,
        ]
    )
    confidence = "high" if missing_sources == 0 else "medium" if missing_sources == 1 else "low"

    remediation = []
    if item.kev.required_action:
        remediation.append(
            "CISA KEV catalog action (review applicability to your organization): "
            + item.kev.required_action
        )
    else:
        remediation.append("Review the vendor advisory and apply the supported patch or mitigation")
    if item.finding.internet_exposed:
        remediation.append("Restrict unnecessary internet exposure until remediation is verified")
    remediation.extend(
        [
            "Review logs for signs of exploitation",
            "Rescan the asset after remediation",
        ]
    )

    return item.model_copy(
        update={
            "risk_score": score,
            "priority": priority,
            "confidence": confidence,
            "reasons": reasons,
            "remediation": remediation,
        }
    )
