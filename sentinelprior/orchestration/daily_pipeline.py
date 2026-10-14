"""Run the complete daily SentinelPrior data-building workflow."""

from __future__ import annotations

from sentinelprior.ingestion.clean_cves import clean_file
from sentinelprior.ingestion.collector import collect
from sentinelprior.ingestion.enrichment import enrich
from sentinelprior.paths import DATA_DIR
from sentinelprior.rag.rag_cleaner import prepare_rag_documents
from sentinelprior.rag.rag_indexer import index_documents
from sentinelprior.sql.textsql_database import load_enriched_cves, using_supabase


RAW_FILE = DATA_DIR / "raw_cves.json"
CLEAN_FILE = DATA_DIR / "clean_cves.json"
ENRICHED_FILE = DATA_DIR / "enriched_cves.json"
COMPARISON_DIR = DATA_DIR / "comparison"
DATABASE_FILE = DATA_DIR / "sentinelprior_textsql.db"
RAG_DOCUMENTS_FILE = DATA_DIR / "rag_cve_documents.json"


def main() -> None:
    print("1/6 Collecting CVEs with the existing 30-day selection policy...")
    collected = collect(output_path=str(RAW_FILE))
    print(f"    Collected {collected['count']} CVE(s)")

    print("2/6 Cleaning and flattening the raw CVEs...")
    cleaned = clean_file(RAW_FILE, CLEAN_FILE, COMPARISON_DIR)
    print(f"    Cleaned {cleaned['cleanRecordCount']} CVE(s)")

    print("3/6 Enriching with NVD, FIRST EPSS, and CISA KEV...")
    enriched = enrich(input_path=str(CLEAN_FILE), output_path=str(ENRICHED_FILE))
    print(
        f"    Enriched {enriched['count']} CVE(s); "
        f"{len(enriched.get('errors') or [])} warning(s)"
    )

    destination = "Supabase PostgreSQL" if using_supabase() else "SQLite"
    print(f"4/6 Loading the current enriched records into {destination}...")
    loaded = load_enriched_cves(ENRICHED_FILE, DATABASE_FILE)
    print(f"    Loaded {loaded} CVE(s) into {destination}")

    print("5/6 Preparing the reduced descriptive RAG JSON...")
    prepared = prepare_rag_documents(ENRICHED_FILE, RAG_DOCUMENTS_FILE)
    print(
        f"    Prepared {prepared['count']} RAG document(s); "
        f"skipped {len(prepared['skipped'])}"
    )

    print("6/6 Chunking, embedding, and rebuilding the Qdrant index...")
    indexed = index_documents(documents_path=RAG_DOCUMENTS_FILE)
    print(f"    Stored {indexed['chunksStored']} chunk(s) in {indexed['collection']}")

    print("\nDaily pipeline complete.")
    print("Next command: python chat.py")


if __name__ == "__main__":
    main()
