"""Ask natural-language questions of the CVE database with provider fallback."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from sentinelprior.ingestion.enrichment import load_dotenv
from sentinelprior.paths import DATA_DIR
from sentinelprior.sql.textsql_database import (
    DEFAULT_DATABASE,
    configured_database_url,
    schema_metadata,
    using_supabase,
)


SCENARIOS = Path(__file__).with_name("scenarios.md")
TRACES_DIR = DATA_DIR
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
        name="Groq",
        key_variable="GROQ_API_KEY",
        model_variable="GROQ_TEXTSQL_MODEL",
        default_model="openai:openai/gpt-oss-20b",
        base_url="https://api.groq.com/openai/v1",
    ),
    "gemini": Provider(
        name="Gemini",
        key_variable="GEMINI_API_KEY",
        model_variable="GEMINI_TEXTSQL_MODEL",
        default_model="openai:gemini-3.8-flash",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    ),
    "mistral": Provider(
        name="Mistral",
        key_variable="MISTRAL_API_KEY",
        model_variable="MISTRAL_TEXTSQL_MODEL",
        default_model="openai:mistral-small-latest",
        base_url="https://api.mistral.ai/v1",
    ),
}


def requested_providers() -> list[Provider]:
    configured = os.getenv("TEXTSQL_PROVIDER_ORDER", DEFAULT_PROVIDER_ORDER)
    names = [name.strip().casefold() for name in configured.split(",") if name.strip()]
    unknown = [name for name in names if name not in PROVIDERS]
    if unknown:
        raise RuntimeError(f"Unknown provider(s) in TEXTSQL_PROVIDER_ORDER: {', '.join(unknown)}")
    selected = set(names)
    return [PROVIDERS[name] for name in PROVIDER_PRIORITY if name in selected]


@lru_cache(maxsize=1)
def cached_schema_metadata() -> str:
    """Reuse the stable CVE schema for SQLite and Supabase PostgreSQL."""
    return schema_metadata()


TEXTSQL_INSTRUCTIONS = """The complete schema for this single-table database is supplied in
Custom Metadata. Do not query system catalogs or run schema discovery. Use the
supplied cves columns, write the requested read-only SELECT
or WITH query, and execute it with execute_sql. Retry only if that query returns
an actual SQL execution error. Do not treat greetings or general conversation
as SQL. For remediation questions, use remediation and vendor_solutions;
cisa_required_action contains only CISA KEV instructions."""


def build_engines() -> list[tuple[Provider, Any]]:
    """Build one TextSQL engine per configured provider without making API calls."""
    load_dotenv()
    if not using_supabase() and not DEFAULT_DATABASE.exists():
        raise RuntimeError(
            f"SQLite database not found: {DEFAULT_DATABASE}. "
            "Run textsql_database.py or run_textsql_pipeline.py first."
        )
    try:
        from text2sql import TextSQL
    except ImportError as error:
        raise RuntimeError(
            'TextSQL is not installed. Run: python -m pip install "text2sql-framework[openai]"'
        ) from error

    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    metadata = cached_schema_metadata()
    connection_string = configured_database_url(DEFAULT_DATABASE)
    engines: list[tuple[Provider, Any]] = []
    missing: list[str] = []

    for provider in requested_providers():
        api_key = os.getenv(provider.key_variable)
        if not api_key:
            missing.append(provider.key_variable)
            continue

        # TextSQL constructs an OpenAI-compatible client when each engine is
        # created. The client retains this provider's key and endpoint even
        # after these process variables are changed for the next engine.
        os.environ["OPENAI_API_KEY"] = api_key
        os.environ["OPENAI_BASE_URL"] = provider.base_url
        model = os.getenv(provider.model_variable, provider.default_model)
        engine = TextSQL(
            connection_string,
            model=model,
            instructions=TEXTSQL_INSTRUCTIONS,
            examples=str(SCENARIOS),
            metadata_hint=metadata,
            trace_file=str(TRACES_DIR / f"textsql_traces_{provider.name.casefold()}.jsonl"),
        )
        engines.append((provider, engine))

    if not engines:
        required = ", ".join(missing) or "provider API keys"
        raise RuntimeError(f"No TextSQL provider is available. Missing: {required}")
    if missing:
        print(f"Skipping providers with missing keys: {', '.join(missing)}")
    print("Provider order: " + " -> ".join(provider.name for provider, _engine in engines))
    return engines


def short_error(error: Exception) -> str:
    status_code = getattr(error, "status_code", None)
    message = str(error).replace("\n", " ").strip()
    if len(message) > 240:
        message = message[:237] + "..."
    return f"HTTP {status_code}: {message}" if status_code else message


def failure_hint(provider: Provider, error: Exception) -> str:
    """Return a short corrective hint without exposing credentials."""
    status_code = getattr(error, "status_code", None)
    if status_code == 401:
        return f"Check or replace {provider.key_variable}; the provider rejected its credentials."
    if status_code == 404:
        return f"Check {provider.model_variable}; the configured model is unavailable for this account."
    if status_code == 429:
        return "This provider accepted the request but its current rate or usage quota was reached."
    return "The provider could not complete this TextSQL run."


def query_with_fallback(
    engines: list[tuple[Provider, Any]],
    question: str,
    max_rows: int = 50,
    announce: bool = True,
) -> tuple[str, Any]:
    """Return the first complete TextSQL result from the provider fallback."""
    failures: list[str] = []
    for provider, engine in list(engines):
        if announce:
            print(f"\nTrying {provider.name}...")
        try:
            # TextSQL may inspect the schema, execute SQL, and self-correct.
            # When any provider run fails, the next provider restarts the same
            # question so no incomplete agent state is reused.
            result = engine.ask(question, max_rows=max_rows)
        except Exception as error:
            reason = short_error(error)
            failures.append(f"{provider.name}: {reason}\n  Hint: {failure_hint(provider, error)}")
            if announce:
                print(f"{provider.name} failed; switching to the next provider.")
            continue

        return provider.name, result

    detail = "\n".join(f"- {failure}" for failure in failures)
    raise RuntimeError(f"All configured TextSQL providers failed:\n{detail}")


def ask_with_fallback(
    engines: list[tuple[Provider, Any]],
    question: str,
    max_rows: int = 50,
) -> None:
    """Run TextSQL and preserve the existing command-line presentation."""
    provider_name, result = query_with_fallback(engines, question, max_rows=max_rows)
    print(f"Answered by: {provider_name}")
    print("\nGenerated SQL")
    print("-------------")
    print(result.sql)
    print("\nDatabase rows")
    print("-------------")
    print(json.dumps(result.data, indent=2, ensure_ascii=False, default=str))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ask natural-language questions of the CVE SQLite table")
    parser.add_argument("question", nargs="*", help="optional one-time natural-language question")
    parser.add_argument("--max-rows", type=int, default=50, help="maximum rows returned by TextSQL")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        engines = build_engines()
        one_time_question = " ".join(args.question).strip()
        if one_time_question:
            ask_with_fallback(engines, one_time_question, args.max_rows)
            return

        print("SentinelPrior TextSQL")
        print("Ask a CVE database question, or type exit to stop.")
        while True:
            try:
                question = input("\nQuestion: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if question.casefold() in {"exit", "quit"}:
                break
            if question:
                try:
                    ask_with_fallback(engines, question, args.max_rows)
                except RuntimeError as error:
                    print(f"\n{error}")
                    if not engines:
                        print("Restart later after a provider quota or service becomes available.")
                        break
    except RuntimeError as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
