"""CrewAI department report generation for SentinelPrior."""

from __future__ import annotations

import json
import os
from pathlib import Path

from crewai import Agent, Crew, Process, Task

# Groq rejects CrewAI's prompt-cache marker on non-Anthropic providers.
# CrewAI currently adds this marker through its cache helper before sending
# the request through LiteLLM, so leave the message unchanged for Groq.
try:
    import crewai.llms.cache as _crewai_cache
    _crewai_cache.mark_cache_breakpoint = lambda message: message
except (ImportError, AttributeError):
    pass


def load_dotenv() -> None:
    path = Path(__file__).with_name(".env")
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def department_report(department: str, records: list[dict]) -> str:
    load_dotenv()
    if not records:
        return f"No CVEs are currently assigned to {department}."
    agent = Agent(
        role=f"{department} vulnerability analyst",
        goal=f"Analyze CVE records for {department} and prioritize review work.",
        backstory="You are a careful cybersecurity analyst. Use only supplied records and never invent evidence.",
        llm=os.getenv("CREWAI_LLM", "gemini/gemini-3.8-flash"),
        verbose=False,
        allow_delegation=False,
    )
    compact_records = [
        {
            "cveId": item.get("cve_id"),
            "description": (item.get("description") or "")[:600],
            "cvss": item.get("cvss_score"),
            "severity": item.get("severity"),
            "epss": item.get("epss_score"),
            "kev": item.get("cisaKevListed"),
            "published": item.get("published"),
        }
        for item in records[:20]
    ]
    task = Task(
        description=(
            f"Prepare a concise Markdown report for {department} from these records:\n"
            f"{json.dumps(compact_records, indent=2)}\n\n"
            "Include CVE ID, severity, CVSS, EPSS, KEV status, why it matters, and a recommended review action."
        ),
        expected_output="An evidence-grounded Markdown department report.",
        agent=agent,
    )
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)
    return str(crew.kickoff())
