"""Shared data models.

Pydantic keeps inputs and outputs predictable without hiding the data flow.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Criticality(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class PlanStep(BaseModel):
    number: int
    action: str
    purpose: str


class ExecutionPlan(BaseModel):
    interpreted_goal: str
    requested_top_n: int = Field(default=5, ge=1, le=50)
    steps: list[PlanStep]


class ScanFinding(BaseModel):
    asset_id: str
    asset_name: str
    cve_id: str
    internet_exposed: bool
    business_criticality: Criticality
    environment: str

    @field_validator("asset_id", "asset_name", "environment")
    @classmethod
    def must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, value: str) -> str:
        import re

        value = value.strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", value):
            raise ValueError("must use the format CVE-YYYY-NNNN")
        return value


class ValidationIssue(BaseModel):
    row_number: int
    message: str
    raw_row: dict[str, Any]


class ScanReadResult(BaseModel):
    findings: list[ScanFinding]
    issues: list[ValidationIssue]
    duplicates_removed: int = 0


class NvdEvidence(BaseModel):
    available: bool
    description: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    published: str | None = None
    last_modified: str | None = None
    source_url: str | None = None
    error: str | None = None


class KevEvidence(BaseModel):
    catalog_available: bool
    known_exploited: bool | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    required_action: str | None = None
    known_ransomware_use: str | None = None
    source_url: str | None = None
    error: str | None = None


class EpssEvidence(BaseModel):
    available: bool
    score: float | None = None
    percentile: float | None = None
    score_date: str | None = None
    source_url: str | None = None
    error: str | None = None


class EnrichedFinding(BaseModel):
    finding: ScanFinding
    nvd: NvdEvidence
    kev: KevEvidence
    epss: EpssEvidence
    priority: str | None = None
    risk_score: int | None = None
    confidence: str | None = None
    reasons: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class ExecutiveNarrative(BaseModel):
    executive_summary: str
    overall_recommendation: str


class RunEvent(BaseModel):
    timestamp: str
    stage: str
    status: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def create(
        cls, stage: str, status: str, message: str, **details: Any
    ) -> "RunEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            stage=stage,
            status=status,
            message=message,
            details=details,
        )


class RunResult(BaseModel):
    run_id: str
    goal: str
    plan: ExecutionPlan
    ai_mode: str
    started_at: str
    completed_at: str
    input_file: str
    input_summary: dict[str, int]
    findings: list[EnrichedFinding]
    validation_issues: list[ValidationIssue]
    executive_summary: str
    overall_recommendation: str
    warnings: list[str]
    events: list[RunEvent]
