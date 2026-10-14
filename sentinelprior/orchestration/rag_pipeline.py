"""Build only the independent SentinelPrior RAG documents and Qdrant index."""

from __future__ import annotations

from sentinelprior.rag.rag_cleaner import DEFAULT_INPUT, DEFAULT_OUTPUT, prepare_rag_documents
from sentinelprior.rag.rag_indexer import index_documents


def main() -> None:
    print("1/2 Preparing compact RAG documents from enriched CVEs...")
    payload = prepare_rag_documents(DEFAULT_INPUT, DEFAULT_OUTPUT)
    print(f"    Prepared {payload['count']} document(s); skipped {len(payload['skipped'])}")

    print("2/2 Tokenizing, chunking, embedding, and indexing in local Qdrant...")
    result = index_documents()
    print(f"    Stored {result['chunksStored']} chunk(s)")
    print(f"    Collection: {result['collection']}")
    print(f"    Qdrant path: {result['qdrantPath']}")
    print("\nRAG index complete.")
    print("Next command: python -m sentinelprior.rag.rag_chat")


if __name__ == "__main__":
    main()
