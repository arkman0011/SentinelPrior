"""LLM planner for SentinelPrior's natural-language chat."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path


def _load_env() -> str | None:
    path = Path(__file__).with_name(".env")
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    return os.getenv("GEMINI_API_KEY")


def make_plan(question: str) -> dict:
    """Return a small JSON plan that the executor can safely validate."""
    key = _load_env()
    if not key:
        return {"action": "chat", "message": "GROQ_API_KEY is missing."}
    from gemini_client import generate

    instructions = """You are the SentinelPrior planner. Return JSON only.
Choose exactly one action:
- chat: greetings or general conversation; fields message
- top_cvss: highest CVSS CVEs; fields limit
- top_epss: highest EPSS CVEs; fields limit
- cvss_equals: CVEs with an exact CVSS score; fields value, limit
- critical: critical CVEs; fields limit
- kev: CISA KEV CVEs; fields limit
- vendor_top_cvss: vendors associated with the highest-CVSS records; fields limit
- vendor: CVEs for a vendor; fields value, limit
- product: CVEs for a product; fields value, limit
- published_after: CVEs after YYYY-MM-DD; fields value, limit
- search: search CVE records; fields value, limit
- explain: explain a database result; fields value, limit
Use limit 5 unless the user specifies another number, maximum 20.
Use explain for why, explain, summarize, compare, recommend, or prioritize questions.
Return an object with action, value, limit, and message. Do not write SQL.
"""
    try:
        content = generate(instructions + "\nQuestion: " + question).strip()
        if "```" in content:
            content = content.replace("```json", "").replace("```", "").strip()
        # Keep only the JSON object if the model adds a sentence around it.
        start, end = content.find("{"), content.rfind("}")
        if start >= 0 and end > start:
            content = content[start:end + 1]
        plan = json.loads(content)
    except Exception:
        return fallback_plan(question)
    allowed = {"chat", "top_cvss", "top_epss", "cvss_equals", "critical", "kev", "vendor", "product", "published_after", "vendor_top_cvss", "search", "explain"}
    plan["action"] = plan.get("action") if plan.get("action") in allowed else "search"
    plan["limit"] = max(1, min(int(plan.get("limit") or 5), 20))
    return plan


def fallback_plan(question: str) -> dict:
    """Safe local route used when the planner response is not valid JSON."""
    text = question.lower()
    ids = re.findall(r"cve-\d{4}-\d{4,}", text, re.IGNORECASE)
    limit_match = re.search(r"\b(?:top|first)\s+(\d+)\b", text)
    limit = max(1, min(int(limit_match.group(1)) if limit_match else 5, 20))
    cvss_match = re.search(r"(?:cvss|score)\s*(?:of|=|is)?\s*(\d+(?:\.\d+)?)", text)
    if cvss_match:
        return {"action": "cvss_equals", "value": cvss_match.group(1), "limit": limit}
    if ("vendor" in text or "company" in text) and ("highest" in text or "top" in text or "most" in text):
        return {"action": "vendor_top_cvss", "limit": limit}
    if any(word in text for word in ("hello", "hi", "hey", "good morning", "good evening")):
        return {"action": "chat", "message": "Hello. I can answer questions about the CVE database."}
    if ids or any(word in text for word in ("why", "reason", "dangerous", "explain", "impact")):
        return {"action": "explain", "value": ids[0] if ids else question, "limit": limit}
    if "epss" in text:
        return {"action": "top_epss", "limit": limit}
    if "kev" in text or "known exploited" in text:
        return {"action": "kev", "limit": limit}
    if "critical" in text:
        return {"action": "critical", "limit": limit}
    if "top" in text or "highest" in text or "most vulnerable" in text:
        return {"action": "top_cvss", "limit": limit}
    return {"action": "search", "value": question, "limit": limit, "explain": True}
