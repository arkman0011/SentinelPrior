"""Use Gemini to explain records already retrieved from SQLite."""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
import re
import time
from pathlib import Path



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


def generate(prompt: str, model: str = "gemini-3.8-flash") -> str:
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is missing from .env")
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read())
            return payload["candidates"][0]["content"]["parts"][0]["text"]
        except urllib.error.HTTPError as error:
            if error.code != 503 or attempt == 1:
                raise
            time.sleep(2)
    raise RuntimeError("Gemini did not return a response")


def explain(question: str, records: list[dict], model: str = "gemini-3.8-flash") -> str:

    compact_records = [
        {
            "cveId": item.get("cve_id"),
            "description": (item.get("description") or "")[:600],
            "cvss": item.get("cvss_score"),
            "severity": item.get("severity"),
            "epss": item.get("epss_score"),
            "kev": item.get("cisaKevListed"),
            "published": item.get("published"),
            "vendor": _vendor_product(item.get("nvd") or {})[0],
            "product": _vendor_product(item.get("nvd") or {})[1],
        }
        for item in records[:20]
    ]
    prompt = (
        "You are SentinelPrior, a vulnerability analyst. Answer only from the supplied records. "
        "If the records do not contain the answer, say that clearly. Do not invent exploitability.\n\n"
        f"Question: {question}\n\nRecords:\n{json.dumps(compact_records, indent=2)}"
    )
    return generate(prompt, model)


def _vendor_product(nvd: dict) -> tuple[str | None, str | None]:
    for group in nvd.get("affected") or []:
        for item in group.get("affectedData") or []:
            return item.get("vendor"), item.get("product")
    for config in nvd.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 4 and parts[0:3] == ["cpe", "2.3", "a"]:
                    return parts[3], parts[4]
    return None, None
