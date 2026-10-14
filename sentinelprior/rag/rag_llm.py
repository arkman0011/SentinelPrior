"""Grounded LLM answer generation with provider fallback for the RAG track."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sentinelprior.rag.rag_config import load_dotenv


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
DEFAULT_PROVIDER_ORDER = "groq,gemini,mistral"
PROVIDER_PRIORITY = ("groq", "gemini", "mistral")


@dataclass(frozen=True)
class Provider:
    name: str
    key_variable: str
    model_variable: str
    default_model: str
    base_url: str


PROVIDERS = {
    "groq": Provider(
        "Groq",
        "GROQ_API_KEY",
        "GROQ_RAG_MODEL",
        "openai/gpt-oss-20b",
        "https://api.groq.com/openai/v1",
    ),
    "gemini": Provider(
        "Gemini",
        "GEMINI_API_KEY",
        "GEMINI_RAG_MODEL",
        "gemini-3.8-flash",
        "https://generativelanguage.googleapis.com/v1beta/openai/",
    ),
    "mistral": Provider(
        "Mistral",
        "MISTRAL_API_KEY",
        "MISTRAL_RAG_MODEL",
        "mistral-small-latest",
        "https://api.mistral.ai/v1",
    ),
}


SYSTEM_PROMPT = """You are SentinelPrior, a grounded CVE intelligence assistant.
Answer the question only from the supplied retrieved evidence.
Do not add facts, affected products, exploitation claims, remediation, or numbers
that are absent from the evidence. Cite supporting CVEs using [CVE-YYYY-NNNN].
If the evidence is insufficient, clearly say that the answer was not found in
the available CVE documents. Keep the answer concise and security-focused."""

COMBINED_SYSTEM_PROMPT = """You are SentinelPrior, a grounded CVE intelligence assistant.
Answer only from the supplied descriptive RAG evidence and structured SQLite
results. Use SQLite values for scores, counts, dates, rankings, vendors and
products. Use RAG evidence for explanations, impact, remediation and vendor
solutions. Do not invent missing facts. Cite CVE-specific claims using
[CVE-YYYY-NNNN]. Keep the answer concise and security-focused."""

NO_EVIDENCE_SYSTEM_PROMPT = """You are SentinelPrior, a local CVE intelligence assistant.

Name:
- SentinelPrior.

Description:
- A local vulnerability-intelligence assistant that combines semantic CVE
  retrieval with structured database queries.

Role:
- Help users inspect and understand CVE records stored by SentinelPrior.

Goal:
- Give concise, accurate answers grounded in SentinelPrior's local evidence.

Backstory and available workflow:
- SentinelPrior collects mature CVEs from CVEProject.
- It cleans and enriches them with NVD, FIRST EPSS, and CISA KEV evidence.
- Qdrant supplies descriptive evidence such as vulnerability explanations,
  remediation, and vendor solutions.
- SQLite and TextSQL supply structured facts such as CVSS, EPSS, KEV status,
  vendors, products, dates, counts, filters, and rankings.

How to respond in this no-evidence mode:
- Answer greetings and ordinary conversation naturally.
- Explain who SentinelPrior is, its purpose, workflow, and capabilities when
  asked.
- You may explain general cybersecurity concepts, but clearly distinguish a
  general explanation from a result found in SentinelPrior's local data.
- If the question asks for a specific CVE, vendor, product, score, ranking,
  date, exploit, remediation, or other local-database fact that is not present
  in supplied evidence, reply exactly: "I don't know the answer from the
  available SentinelPrior data."
- If a follow-up question lacks the CVE or subject it refers to, ask the user
  to provide that missing context instead of guessing.

Restrictions:
- Do not invent or guess a CVE, score, affected product, vendor, exploit,
  remediation, or database result.
- Never claim that a general explanation came from SentinelPrior's database.
- Respond as concise natural-language text. Do not return JSON, an intent
  label, or a Markdown code block unless the user explicitly asks for one."""

SAFE_NO_EVIDENCE_RESPONSE = "I don't know the answer from the available SentinelPrior data."
TokenCallback = Callable[[str], None]

def completion_text(
    client: Any,
    model: str,
    messages: list[dict[str, str]],
    max_tokens: int,
    on_token: TokenCallback | None = None,
) -> str:
    """Return a completion, forwarding provider chunks when streaming is enabled."""
    if on_token is None:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
        )
        return str(response.choices[0].message.content or "").strip()

    stream = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=max_tokens,
        stream=True,
    )
    pieces: list[str] = []
    for chunk in stream:
        if not getattr(chunk, "choices", None):
            continue
        delta = getattr(chunk.choices[0], "delta", None)
        content = getattr(delta, "content", None) if delta is not None else None
        if not content:
            continue
        text = str(content)
        pieces.append(text)
        on_token(text)
    return "".join(pieces).strip()


def configured_providers() -> list[tuple[Provider, Any, str]]:
    load_dotenv()
    try:
        from openai import OpenAI
    except ImportError as error:
        raise RuntimeError("OpenAI-compatible client is missing. Run: python -m pip install openai") from error

    configured = [
        name.strip().casefold()
        for name in os.getenv("RAG_PROVIDER_ORDER", DEFAULT_PROVIDER_ORDER).split(",")
        if name.strip()
    ]
    unknown = [name for name in configured if name not in PROVIDERS]
    if unknown:
        raise RuntimeError(f"Unknown provider(s) in RAG_PROVIDER_ORDER: {', '.join(unknown)}")
    selected = set(configured)
    requested = [name for name in PROVIDER_PRIORITY if name in selected]

    result: list[tuple[Provider, Any, str]] = []
    for name in requested:
        provider = PROVIDERS[name]
        key = os.getenv(provider.key_variable)
        if not key:
            continue
        client = OpenAI(api_key=key, base_url=provider.base_url)
        model = os.getenv(provider.model_variable, provider.default_model)
        result.append((provider, client, model))
    if not result:
        raise RuntimeError("No RAG LLM provider key is configured in .env")
    return result


def context_text(evidence: list[dict[str, Any]]) -> str:
    """Give the LLM only compact descriptive and remediation evidence.

    Retrieval and reranking still use the complete indexed chunk. This
    function is the post-reranking boundary that removes search metadata and
    unrelated factual fields before generation.
    """
    blocks = []
    for index, item in enumerate(evidence, start=1):
        metadata = item.get("metadata") or {}
        cve_id = str(metadata.get("cveId") or "UNKNOWN")
        description = str(metadata.get("description") or "").strip()
        remediation = [
            str(value).strip()
            for value in metadata.get("remediation") or []
            if str(value).strip()
        ]
        vendor_solutions = [
            str(value).strip()
            for value in metadata.get("vendorSolutions") or []
            if str(value).strip()
        ]

        # Compatibility for an index created before description was copied to
        # metadata. Use only the Summary section, never the complete chunk.
        if not description:
            content = str(item.get("content") or "")
            summary_match = re.search(
                r"(?:^|\n)Summary:\s*\n(?P<summary>.*?)(?=\n\n[^\n]+:\s*\n|\Z)",
                content,
                flags=re.DOTALL,
            )
            if summary_match:
                description = summary_match.group("summary").strip()

        lines = [f"Evidence {index} — {cve_id}"]
        if description:
            lines.append(f"Description:\n{description}")
        if remediation:
            lines.append("Remediation:\n" + "\n".join(f"- {value}" for value in remediation))
        if vendor_solutions:
            lines.append(
                "Vendor solution:\n" + "\n".join(f"- {value}" for value in vendor_solutions)
            )
        blocks.append("\n\n".join(lines))
    return "\n\n---\n\n".join(blocks)


def verified(answer: str, allowed_cves: set[str]) -> tuple[bool, str]:
    cited = {match.upper() for match in CVE_PATTERN.findall(answer)}
    unsupported = cited - allowed_cves
    if unsupported:
        return False, "unsupported CVE citation(s): " + ", ".join(sorted(unsupported))
    insufficient = any(
        phrase in answer.casefold()
        for phrase in ("not found", "insufficient evidence", "do not contain", "does not contain")
    )
    if not cited and not insufficient:
        return False, "the answer did not cite a retrieved CVE"
    return True, ""


def verified_combined(answer: str, allowed_cves: set[str]) -> tuple[bool, str]:
    """Validate citations while allowing aggregate SQL answers without IDs."""
    cited = {match.upper() for match in CVE_PATTERN.findall(answer)}
    unsupported = cited - allowed_cves
    if unsupported:
        return False, "unsupported CVE citation(s): " + ", ".join(sorted(unsupported))
    insufficient = any(
        phrase in answer.casefold()
        for phrase in ("not found", "insufficient evidence", "do not contain", "does not contain")
    )
    if allowed_cves and not cited and not insufficient:
        return False, "the answer did not cite an available CVE"
    return True, ""


def compact_sql_rows(rows: Any) -> Any:
    """Remove large storage columns that the final answer does not need."""
    excluded = {"affected_json", "nvd_json", "enriched_text_card"}
    if not isinstance(rows, list):
        return rows
    return [
        {key: value for key, value in row.items() if key not in excluded}
        if isinstance(row, dict)
        else row
        for row in rows
    ]


class GroundedLLM:
    def __init__(self) -> None:
        self.providers = configured_providers()

    def answer(
        self,
        question: str,
        evidence: list[dict[str, Any]],
        on_token: TokenCallback | None = None,
    ) -> tuple[str, str]:
        allowed_cves = {
            str((item.get("metadata") or {}).get("cveId") or "").upper()
            for item in evidence
        }
        allowed_cves.discard("")
        prompt = f"Retrieved CVE evidence:\n\n{context_text(evidence)}\n\nQuestion:\n{question}"
        failures: list[str] = []
        for provider, client, model in list(self.providers):
            try:
                answer = completion_text(
                    client,
                    model,
                    [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    700,
                    on_token,
                )
                is_valid, reason = verified(answer, allowed_cves)
                if not is_valid:
                    raise RuntimeError(f"grounding verification failed: {reason}")
                return answer, provider.name
            except Exception as error:
                message = str(error).replace("\n", " ").strip()
                failures.append(f"{provider.name}: {message[:240]}")
        raise RuntimeError("All RAG LLM providers failed:\n- " + "\n- ".join(failures))

    def answer_combined(
        self,
        question: str,
        evidence: list[dict[str, Any]],
        generated_sql: str,
        sql_rows: Any,
        on_token: TokenCallback | None = None,
    ) -> tuple[str, str]:
        """Write one answer from post-reranking RAG context plus SQLite rows."""
        descriptive_context = context_text(evidence)
        compact_rows = compact_sql_rows(sql_rows)
        structured_context = json.dumps(compact_rows, indent=2, ensure_ascii=False, default=str)
        allowed_cves = {
            match.upper()
            for match in CVE_PATTERN.findall(descriptive_context + "\n" + structured_context)
        }
        prompt = (
            "Descriptive RAG evidence:\n\n"
            f"{descriptive_context}\n\n"
            "Structured SQLite evidence:\n\n"
            f"SQL: {generated_sql}\n"
            f"Rows: {structured_context}\n\n"
            f"Question:\n{question}"
        )
        failures: list[str] = []
        for provider, client, model in list(self.providers):
            try:
                answer = completion_text(
                    client,
                    model,
                    [
                        {"role": "system", "content": COMBINED_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    700,
                    on_token,
                )
                is_valid, reason = verified_combined(answer, allowed_cves)
                if not is_valid:
                    raise RuntimeError(f"grounding verification failed: {reason}")
                return answer, provider.name
            except Exception as error:
                message = str(error).replace("\n", " ").strip()
                failures.append(f"{provider.name}: {message[:240]}")
        raise RuntimeError("All final-answer providers failed:\n- " + "\n- ".join(failures))

    def answer_no_evidence(
        self,
        question: str,
        on_token: TokenCallback | None = None,
    ) -> tuple[str, str]:
        """Let the LLM handle conversation without predefined intent matching."""
        failures: list[str] = []
        for provider, client, model in list(self.providers):
            try:
                answer = completion_text(
                    client,
                    model,
                    [
                        {"role": "system", "content": NO_EVIDENCE_SYSTEM_PROMPT},
                        {"role": "user", "content": question},
                    ],
                    300,
                    on_token,
                )
                if not answer:
                    raise RuntimeError("provider returned an empty answer")
                # No local evidence was supplied, so a newly generated CVE ID
                # would be an unsupported project-specific claim. General
                # conversation and explanations remain fully LLM-controlled.
                if CVE_PATTERN.search(answer):
                    return SAFE_NO_EVIDENCE_RESPONSE, "Safety filter"
                return answer, provider.name
            except Exception as error:
                message = str(error).replace("\n", " ").strip()
                failures.append(f"{provider.name}: {message[:240]}")
        return SAFE_NO_EVIDENCE_RESPONSE, "Safety filter"
