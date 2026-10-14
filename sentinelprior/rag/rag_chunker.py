"""Token-aware document chunking for compact SentinelPrior CVE documents."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Callable

from sentinelprior.rag.rag_config import (
    CHUNK_OVERLAP_TOKENS,
    CHUNK_SIZE_TOKENS,
    EMBEDDING_MODEL,
    RAG_CHUNKS_FILE,
    RAG_DOCUMENTS_FILE,
)


class DocumentChunker:
    """Use Semchunk with FastEmbed's BGE token counter when available."""

    def __init__(
        self,
        token_counter: Callable[[str], int] | None = None,
        chunk_size: int = CHUNK_SIZE_TOKENS,
        overlap: int = CHUNK_OVERLAP_TOKENS,
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if overlap < 0 or overlap >= chunk_size:
            raise ValueError("overlap must be at least zero and smaller than chunk_size")
        try:
            import semchunk
            from fastembed import TextEmbedding
        except ImportError as error:
            raise RuntimeError(
                "Lightweight RAG packages are not installed. Run: "
                "python -m pip install fastembed semchunk"
            ) from error
        # When used by rag_indexer, the already-loaded FastEmbed model supplies
        # its exact BGE token counter. The fallback creates the same ONNX model.
        self._embedding_model = None
        if token_counter is None:
            self._embedding_model = TextEmbedding(model_name=EMBEDDING_MODEL)
            token_counter = self._embedding_model.token_count
        self._chunker = semchunk.chunkerify(token_counter, chunk_size)
        self.chunk_size = chunk_size
        self.overlap = overlap

    def split_text(self, text: str) -> list[str]:
        if not text.strip():
            return []
        return [chunk.strip() for chunk in self._chunker(text, overlap=self.overlap) if chunk.strip()]

    def chunk_document(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        document_id = str(document.get("documentId") or "").strip()
        content = str(document.get("content") or "").strip()
        if not document_id or not content:
            return []
        pieces = self.split_text(content)
        chunks: list[dict[str, Any]] = []
        for index, text in enumerate(pieces):
            point_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinelprior:{document_id}:{index}"))
            metadata = dict(document.get("metadata") or {})
            metadata.update(
                {
                    "documentId": document_id,
                    "chunkIndex": index,
                    "totalChunks": len(pieces),
                }
            )
            chunks.append({"chunkId": point_id, "content": text, "metadata": metadata})
        return chunks


def load_documents(path: Path = RAG_DOCUMENTS_FILE) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    documents = payload.get("documents") if isinstance(payload, dict) else None
    if not isinstance(documents, list):
        raise ValueError(f"Expected a top-level documents list in {path}")
    return [document for document in documents if isinstance(document, dict)]


def create_chunks(
    input_path: Path = RAG_DOCUMENTS_FILE,
    output_path: Path = RAG_CHUNKS_FILE,
    token_counter: Callable[[str], int] | None = None,
) -> list[dict[str, Any]]:
    chunker = DocumentChunker(token_counter=token_counter)
    chunks = [chunk for document in load_documents(input_path) for chunk in chunker.chunk_document(document)]
    payload = {
        "stage": "rag-chunked",
        "embeddingModel": EMBEDDING_MODEL,
        "chunkSizeTokens": chunker.chunk_size,
        "chunkOverlapTokens": chunker.overlap,
        "count": len(chunks),
        "chunks": chunks,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return chunks
