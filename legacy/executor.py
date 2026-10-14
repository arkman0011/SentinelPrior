"""Safe execution of planner JSON against the CVE query layer."""

from __future__ import annotations

import query


def execute(plan: dict) -> dict:
    action = plan.get("action", "chat")
    limit = plan.get("limit", 5)
    value = str(plan.get("value") or "")
    if action == "top_cvss": records = query.top_by_cvss(limit)
    elif action == "top_epss": records = query.top_by_epss(limit)
    elif action == "cvss_equals": records = query.cves_by_cvss(float(value), limit)
    elif action == "critical": records = query.critical_cves()
    elif action == "kev": records = query.kev_cves(limit)
    elif action == "vendor": records = query.cves_by_vendor(value, limit)
    elif action == "product": records = query.cves_by_product(value, limit)
    elif action == "published_after": records = query.cves_published_after(value, limit)
    elif action == "vendor_top_cvss": records = query.vendors_by_highest_cvss(limit)
    elif action in {"search", "explain"}: records = query.search(value, limit)
    else: records = []
    return {"action": action, "value": value, "records": records, "message": plan.get("message", "")}
