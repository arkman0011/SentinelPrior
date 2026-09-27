"""Optional OpenAI-powered planning and report narration.

The project remains runnable without an API key. In that case, the same public
data tools and deterministic risk engine are used with a clearly labelled
fallback plan and summary.
"""

from __future__ import annotations

import json
import re

from .models import (
    EnrichedFinding,
    ExecutionPlan,
    ExecutiveNarrative,
    PlanStep,
)
from .run_logger import RunLogger


class AIHelper:
    def __init__(
        self,
        api_key: str | None,
        model: str,
        logger: RunLogger,
        disabled: bool = False,
    ) -> None:
        self.model = model
        self.logger = logger
        self.client = None
        self.ai_used = False

        if api_key and not disabled:
            from openai import OpenAI

            self.client = OpenAI(api_key=api_key)

    @property
    def mode(self) -> str:
        return f"OpenAI Responses API ({self.model})" if self.ai_used else "deterministic fallback"

    def create_plan(self, goal: str) -> ExecutionPlan:
        if self.client:
            try:
                response = self.client.responses.parse(
                    model=self.model,
                    input=[
                        {
                            "role": "system",
                            "content": (
                                "You are the planning component of a defensive vulnerability "
                                "triage agent. Convert the goal into a short operational plan. "
                                "Use only these capabilities: validate a scanner CSV, query NVD, "
                                "query CISA KEV, query FIRST EPSS, apply deterministic priority "
                                "rules, and write reports. Do not include hidden chain-of-thought. "
                                "Return concise actions and purposes."
                            ),
                        },
                        {"role": "user", "content": goal},
                    ],
                    text_format=ExecutionPlan,
                )
                if response.output_parsed:
                    self.ai_used = True
                    self.logger.log("PLANNER", "SUCCESS", "AI created a structured plan")
                    return response.output_parsed
            except Exception as error:  # API errors must not stop defensive analysis.
                self.logger.log(
                    "PLANNER",
                    "FALLBACK",
                    "AI planning failed; using the documented fallback plan",
                    error=str(error),
                )

        self.logger.log("PLANNER", "FALLBACK", "Using the deterministic plan")
        return _fallback_plan(goal)

    def create_narrative(
        self, goal: str, findings: list[EnrichedFinding]
    ) -> ExecutiveNarrative:
        facts = [
            {
                "cve_id": item.finding.cve_id,
                "asset": item.finding.asset_name,
                "priority": item.priority,
                "risk_score": item.risk_score,
                "confidence": item.confidence,
                "reasons": item.reasons,
            }
            for item in findings
        ]

        if self.client:
            try:
                response = self.client.responses.parse(
                    model=self.model,
                    input=[
                        {
                            "role": "system",
                            "content": (
                                "You write concise defensive cybersecurity reports for managers. "
                                "Use only the supplied facts. Do not add scores, incidents, affected "
                                "products, or remediation claims. Clearly preserve uncertainty."
                            ),
                        },
                        {
                            "role": "user",
                            "content": json.dumps({"goal": goal, "findings": facts}),
                        },
                    ],
                    text_format=ExecutiveNarrative,
                )
                if response.output_parsed:
                    self.ai_used = True
                    self.logger.log("REPORT AI", "SUCCESS", "AI wrote the executive narrative")
                    return response.output_parsed
            except Exception as error:
                self.logger.log(
                    "REPORT AI",
                    "FALLBACK",
                    "AI narrative failed; using the deterministic summary",
                    error=str(error),
                )

        return _fallback_narrative(findings)


def _fallback_plan(goal: str) -> ExecutionPlan:
    match = re.search(r"\b(?:top|identify|show)\s+(\d+)\b", goal, flags=re.IGNORECASE)
    requested_top_n = int(match.group(1)) if match else 5
    requested_top_n = max(1, min(requested_top_n, 50))
    actions = [
        ("Validate the scanner CSV", "Reject malformed rows and remove duplicates"),
        ("Retrieve NVD evidence", "Collect descriptions and CVSS severity"),
        ("Check CISA KEV", "Identify confirmed real-world exploitation"),
        ("Retrieve FIRST EPSS", "Collect current exploitation probability"),
        ("Apply priority rules", "Combine security evidence with asset context"),
        ("Run quality checks", "Make missing evidence and failures visible"),
        ("Write Markdown and JSON reports", "Provide human- and machine-readable results"),
    ]
    return ExecutionPlan(
        interpreted_goal=goal.strip(),
        requested_top_n=requested_top_n,
        steps=[
            PlanStep(number=index, action=action, purpose=purpose)
            for index, (action, purpose) in enumerate(actions, start=1)
        ],
    )


def _fallback_narrative(findings: list[EnrichedFinding]) -> ExecutiveNarrative:
    counts: dict[str, int] = {}
    for item in findings:
        counts[item.priority or "Unknown"] = counts.get(item.priority or "Unknown", 0) + 1
    count_text = ", ".join(f"{key}: {value}" for key, value in sorted(counts.items()))
    highest = findings[0] if findings else None
    if highest:
        summary = (
            f"The agent selected {len(findings)} prioritized findings ({count_text}). "
            f"The highest-ranked item is {highest.finding.cve_id} on "
            f"{highest.finding.asset_name}, rated {highest.priority} with "
            f"{highest.confidence} evidence confidence."
        )
    else:
        summary = "No findings were available for prioritization."
    return ExecutiveNarrative(
        executive_summary=summary,
        overall_recommendation=(
            "A qualified security analyst should verify asset applicability, follow vendor "
            "guidance, remediate the highest priorities first, and rescan affected assets."
        ),
    )
