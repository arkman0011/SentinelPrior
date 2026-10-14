"""Run collector -> cleaner -> enrichment -> TextSQL SQLite loading."""

from __future__ import annotations

from pathlib import Path

from sentinelprior.ingestion.clean_cves import clean_file
from sentinelprior.ingestion.collector import collect
from sentinelprior.ingestion.enrichment import enrich
from sentinelprior.sql.textsql_database import load_enriched_cves, using_supabase


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
RAW_FILE = DATA_DIR / "raw_cves.json"
CLEAN_FILE = DATA_DIR / "clean_cves.json"
ENRICHED_FILE = DATA_DIR / "enriched_cves.json"
COMPARISON_DIR = DATA_DIR / "comparison"
DATABASE_FILE = DATA_DIR / "sentinelprior_textsql.db"


def main() -> None:
    print("1/4 Collecting mature CVEs using the existing collector configuration...")
    collected = collect(output_path=str(RAW_FILE))
    print(f"    Collected {collected['count']} CVEs")

    print("2/4 Cleaning and flattening the raw CVEs...")
    cleaned = clean_file(RAW_FILE, CLEAN_FILE, COMPARISON_DIR)
    print(f"    Cleaned {cleaned['cleanRecordCount']} CVEs")

    print("3/4 Enriching cleaned CVEs with NVD, FIRST EPSS, and CISA KEV...")
    enriched = enrich(input_path=str(CLEAN_FILE), output_path=str(ENRICHED_FILE))
    print(
        f"    Enriched {enriched['count']} CVEs; "
        f"{len(enriched.get('errors') or [])} warning(s)"
    )

    destination = "Supabase PostgreSQL" if using_supabase() else "SQLite"
    print(f"4/4 Loading current enriched CVEs into {destination}...")
    loaded = load_enriched_cves(ENRICHED_FILE, DATABASE_FILE)
    print(f"    Loaded {loaded} CVEs into {destination}")

    print("\nPipeline complete.")
    print('Next command: python -m sentinelprior.sql.textsql_chat')


if __name__ == "__main__":
    main()
