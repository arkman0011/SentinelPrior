"""Generate eight department-specific CVE reports from SQLite records."""

from __future__ import annotations

from datetime import datetime, timezone

import query
from crew_agents import department_report


DEPARTMENT_TERMS = {
    "Security": ["security", "vulnerability", "exploit", "attack", "risk", "cve"],
    "Software Engineering": ["software", "code", "library", "framework", "api", "application"],
    "Cloud / DevOps": ["cloud", "docker", "kubernetes", "container", "server", "linux", "aws"],
    "IT / Network Operations": ["network", "vpn", "router", "firewall", "browser", "endpoint"],
    "Database / Data Engineering": ["database", "sql", "postgres", "mysql", "data", "storage"],
    "Finance / Payments": ["finance", "payment", "billing", "banking", "transaction"],
    "HR": ["hr", "human resource", "employee", "payroll", "personnel"],
    "Risk / Compliance / Management": ["compliance", "policy", "governance", "audit", "risk", "management"],
}


def records_for_department(department: str) -> list[dict]:
    terms = DEPARTMENT_TERMS[department]
    records = query.search("", limit=500)
    return [
        record for record in records
        if any(term in f"{record.get('cve_id', '')} {record.get('description', '')} {record.get('nvd', {})}".lower() for term in terms)
    ]


def generate_report(department: str) -> dict:
    records = records_for_department(department)
    if not records:
        return {
            "department": department,
            "recordCount": 0,
            "summary": "No matching CVE records are currently available.",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "records": [],
        }
    return {
        "department": department,
        "recordCount": len(records),
        "summary": department_report(department, records[:50]),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "records": records,
    }


def generate_all_reports() -> dict[str, dict]:
    return {department: generate_report(department) for department in DEPARTMENT_TERMS}
