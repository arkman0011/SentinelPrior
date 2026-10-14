"""Configuration shared only by the independent SentinelPrior RAG track."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sentinelprior.paths import DATA_DIR, ENV_FILE
RAG_DOCUMENTS_FILE = DATA_DIR / "rag_cve_documents.json"
RAG_CHUNKS_FILE = DATA_DIR / "rag_chunks.json"
QDRANT_PATH = DATA_DIR / "qdrant"
QDRANT_COLLECTION = "sentinelprior_cve_rag"

EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
RERANKER_MODEL = "Xenova/ms-marco-MiniLM-L-6-v2"
EMBEDDING_DIMENSION = 384

CHUNK_SIZE_TOKENS = 384
CHUNK_OVERLAP_TOKENS = 48
RETRIEVAL_LIMIT = 10
RERANK_LIMIT = 1


def load_dotenv() -> None:
    """Load simple KEY=VALUE entries without adding another dependency."""
    env_path = ENV_FILE
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def qdrant_connection(
    local_path: Path = QDRANT_PATH,
) -> tuple[dict[str, Any], str]:
    """Return Qdrant Cloud settings, falling back to the established local index."""
    load_dotenv()
    url = os.getenv("QDRANT_URL", "").strip().rstrip("/")
    api_key = os.getenv("QDRANT_API_KEY", "").strip()
    if url:
        if not api_key:
            raise RuntimeError("QDRANT_API_KEY is required when QDRANT_URL is configured.")
        return {"url": url, "api_key": api_key, "timeout": 60}, url

    local_path.mkdir(parents=True, exist_ok=True)
    return {"path": str(local_path)}, str(local_path.resolve())


def qdrant_collection_name(default: str = QDRANT_COLLECTION) -> str:
    """Allow deployments to select a collection without changing source code."""
    load_dotenv()
    return os.getenv("QDRANT_COLLECTION", default).strip() or default
