"""Plan, execute and answer one SentinelPrior chat message."""

from __future__ import annotations

import json

from executor import execute
from gemini_client import explain
from planner import make_plan


def respond(question: str) -> str:
    plan = make_plan(question)
    result = execute(plan)
    if plan.get("action") == "chat":
        return plan.get("message") or "I can help with greetings and CVE database questions."
    return explain(question, result["records"])
