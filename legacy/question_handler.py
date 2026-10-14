"""Turn common SentinelPrior questions into SQLite retrievals."""

from __future__ import annotations

import re
from datetime import date
import json
import os
from pathlib import Path


import query
import gemini_client


def answer_question(question: str) -> dict:
    text = question.strip().lower()
    if text in {"hi", "hello", "hey", "good morning", "good afternoon", "good evening"}:
        return {"query": "greeting", "records": []}
    number_match = re.search(r"\b(?:top|first)\s+(\d+)\b", text)
    limit = int(number_match.group(1)) if number_match else 5

    if "epss" in text and ("top" in text or "highest" in text or "most" in text):
        return {"query": "top_by_epss", "records": query.top_by_epss(limit)}
    if "kev" in text or "known exploited" in text:
        return {"query": "kev_cves", "records": query.kev_cves(limit)}
    if "critical" in text:
        return {"query": "critical_cves", "records": query.critical_cves()}
    if "vendor" in text:
        value = _value_after(text, "vendor")
        return {"query": "cves_by_vendor", "value": value, "records": query.cves_by_vendor(value, limit)}
    if "product" in text:
        value = _value_after(text, "product")
        return {"query": "cves_by_product", "value": value, "records": query.cves_by_product(value, limit)}
    date_match = re.search(r"(?:after|since)\s+(\d{4}-\d{2}-\d{2})", text)
    if date_match:
        return {
            "query": "cves_published_after",
            "value": date_match.group(1),
            "records": query.cves_published_after(date_match.group(1), limit),
        }
    if "top" in text or "highest" in text or "most vulnerable" in text:
        return {"query": "top_by_cvss", "records": query.top_by_cvss(limit)}
    return llm_route(question)


def llm_route(question: str) -> dict:
    """Convert natural language to a whitelisted SQLite operation."""
    from litellm import completion

    path = Path(__file__).with_name(".env")
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    key = os.getenv("GROQ_API_KEY")
    if not key:
        return {"query": "search", "value": question, "records": query.search(question), "needs_explanation": True}
    prompt = """Classify this CVE database question. Return JSON only with keys: intent, value, limit, explain.
Allowed intent values: top_cvss, top_epss, critical, kev, vendor, product, published_after, search.
Use value for vendor/product/date/search text. limit is an integer, default 5. explain is true only when the user asks why, explain, summarize, recommend, compare, or analyze.
Question: """ + question
    try:
        response = completion(
            model="groq/openai/gpt-oss-20b",
            api_key=key,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=120,
        )
        data = json.loads(response.choices[0].message.content)
    except Exception:
        data = {"intent": "search", "value": question, "limit": 5, "explain": True}
    intent = data.get("intent", "search")
    value = str(data.get("value") or question)
    limit = max(1, min(int(data.get("limit") or 5), 20))
    if intent == "top_cvss": records = query.top_by_cvss(limit)
    elif intent == "top_epss": records = query.top_by_epss(limit)
    elif intent == "critical": records = query.critical_cves()
    elif intent == "kev": records = query.kev_cves(limit)
    elif intent == "vendor": records = query.cves_by_vendor(value, limit)
    elif intent == "product": records = query.cves_by_product(value, limit)
    elif intent == "published_after": records = query.cves_published_after(value, limit)
    else: records = query.search(value, limit)
    return {"query": intent, "value": value, "records": records, "needs_explanation": bool(data.get("explain"))}


def ask(question: str) -> str:
    result = answer_question(question)
    return gemini_client.explain(question, result["records"])


def format_direct(result: dict) -> str:
    """Format factual query results without calling an LLM."""
    records = result["records"]
    if not records:
        if result["query"] == "kev_cves":
            return "No CISA KEV-listed CVEs are currently stored in the database."
        if result["query"] == "critical_cves":
            return "No critical CVEs are currently stored in the database."
        return "No matching CVEs were found in the database."
    lines = [f"Found {len(records)} CVE record(s):", ""]
    for item in records:
        lines.append(
            f"- {item.get('cve_id')}: CVSS {item.get('cvss_score') or 'N/A'} "
            f"({item.get('severity') or 'unknown'}), EPSS {item.get('epss_score') or 'N/A'}, "
            f"KEV {'Yes' if item.get('cisaKevListed') else 'No'}"
        )
    return "\n".join(lines)


def _value_after(text: str, label: str) -> str:
    value = text.split(label, 1)[1].strip(" :?\"")
    return value or label


if __name__ == "__main__":
    print(answer_question("What are the top 5 CVEs by EPSS?"))
