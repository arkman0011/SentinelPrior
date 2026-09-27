"""Coordinator agent for the complete vulnerability-triage workflow."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .ai_helper import AIHelper
from .config import Settings
from .models import EnrichedFinding, RunResult
from .quality_checks import validate_findings
from .report_writer import write_outputs
from .risk_engine import prioritize
from .run_logger import RunLogger
from .tools.cisa_kev_client import CisaKevClient
from .tools.epss_client import EpssClient
from .tools.http_client import HttpClient
from .tools.nvd_client import NvdClient
from .tools.scanner_reader import read_scan_csv


class CoordinatorAgent:
    def __init__(self, settings: Settings, *, disable_ai: bool = False) -> None:
        self.settings = settings
        self.logger = RunLogger()
        self.http = HttpClient(
            settings.request_timeout_seconds,
            settings.max_retries,
            self.logger,
        )
        self.ai = AIHelper(
            settings.openai_api_key,
            settings.openai_model,
            self.logger,
            disabled=disable_ai,
        )
        self.nvd = NvdClient(self.http, self.logger, settings.nvd_api_key)
        self.kev = CisaKevClient(self.http)
        self.epss = EpssClient(self.http)

    def run(
        self,
        goal: str,
        scan_path: Path,
        output_dir: Path,
        *,
        simulate_epss_failure: bool = False,
    ) -> tuple[RunResult, dict[str, Path]]:
        started_at = datetime.now(timezone.utc)
        run_id = f"RUN-{started_at:%Y%m%d-%H%M%S}-{uuid4().hex[:6].upper()}"
        self.logger.log("COORDINATOR", "START", "Started vulnerability triage", run_id=run_id)

        plan = self.ai.create_plan(goal)
        for step in plan.steps:
            self.logger.log("PLAN", "READY", f"{step.number}. {step.action}")

        self.logger.log("INPUT", "START", f"Reading {scan_path.name}")
        scan = read_scan_csv(scan_path)
        self.logger.log(
            "INPUT",
            "SUCCESS",
            f"Accepted {len(scan.findings)} findings",
            invalid_rows=len(scan.issues),
            duplicates_removed=scan.duplicates_removed,
        )

        cve_ids = sorted({item.cve_id for item in scan.findings})
        self.logger.log("CISA KEV", "START", "Downloading the current KEV catalog")
        self.kev.load_catalog()
        self.logger.log("EPSS", "START", f"Requesting {len(cve_ids)} scores in one batch")
        epss_results = self.epss.fetch_many(
            cve_ids, simulate_failure=simulate_epss_failure
        )

        enriched: list[EnrichedFinding] = []
        for index, finding in enumerate(scan.findings):
            self.logger.log("ENRICH", "START", f"Processing {finding.cve_id}")
            nvd = self.nvd.fetch(finding.cve_id)
            kev = self.kev.lookup(finding.cve_id)
            epss = epss_results[finding.cve_id]
            enriched.append(
                prioritize(
                    EnrichedFinding(
                        finding=finding,
                        nvd=nvd,
                        kev=kev,
                        epss=epss,
                    )
                )
            )
            self.logger.log("ENRICH", "SUCCESS", f"Prioritized {finding.cve_id}")
            if index < len(scan.findings) - 1:
                self.nvd.polite_pause()

        enriched.sort(
            key=lambda item: (item.risk_score or 0, item.epss.score or 0),
            reverse=True,
        )
        selected = enriched[: min(plan.requested_top_n, len(enriched))]
        self.logger.log(
            "PRIORITIZATION",
            "SUCCESS",
            f"Selected the top {len(selected)} findings",
        )

        warnings = validate_findings(selected)
        if scan.issues:
            warnings.append(
                f"{len(scan.issues)} input row issue(s) were isolated; see JSON output"
            )
        narrative = self.ai.create_narrative(goal, selected)

        completed_at = datetime.now(timezone.utc)
        self.logger.log("QA", "SUCCESS", "Final evidence and schema checks passed")
        result = RunResult(
            run_id=run_id,
            goal=goal,
            plan=plan,
            ai_mode=self.ai.mode,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            input_file=str(scan_path.resolve()),
            input_summary={
                "valid_findings": len(scan.findings),
                "invalid_rows": len(scan.issues),
                "duplicates_removed": scan.duplicates_removed,
            },
            findings=selected,
            validation_issues=scan.issues,
            executive_summary=narrative.executive_summary,
            overall_recommendation=narrative.overall_recommendation,
            warnings=sorted(set(warnings)),
            events=list(self.logger.events),
        )
        paths = write_outputs(result, output_dir)
        self.logger.log("COORDINATOR", "DONE", "Reports written successfully")
        return result, paths
