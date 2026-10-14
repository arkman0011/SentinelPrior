"""Retrieve CVE chunks from Qdrant and rerank them with a cross-encoder."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sentinelprior.rag.rag_config import (
    EMBEDDING_MODEL,
    QDRANT_COLLECTION,
    QDRANT_PATH,
    RERANKER_MODEL,
    RERANK_LIMIT,
    RETRIEVAL_LIMIT,
    qdrant_collection_name,
    qdrant_connection,
)


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class RAGRetriever:
    def __init__(
        self,
        qdrant_path: Path = QDRANT_PATH,
        collection_name: str = QDRANT_COLLECTION,
    ) -> None:
        try:
            from fastembed import TextEmbedding
            from fastembed.rerank.cross_encoder import TextCrossEncoder
            from qdrant_client import QdrantClient
            from qdrant_client.models import FieldCondition, Filter, MatchValue
        except ImportError as error:
            raise RuntimeError(
                "RAG packages are not installed. Run: "
                "python -m pip install fastembed qdrant-client semchunk"
            ) from error

        self.collection_name = qdrant_collection_name(collection_name)
        self._FieldCondition = FieldCondition
        self._Filter = Filter
        self._MatchValue = MatchValue
        connection, storage_location = qdrant_connection(qdrant_path)
        self.client = QdrantClient(**connection)
        if not self.client.collection_exists(self.collection_name):
            self.client.close()
            raise RuntimeError(
                f"Qdrant collection '{self.collection_name}' does not exist at "
                f"{storage_location}. Run the RAG pipeline first."
            )
        self.embedder = TextEmbedding(model_name=EMBEDDING_MODEL)
        self.reranker = TextCrossEncoder(model_name=RERANKER_MODEL)

    def close(self) -> None:
        self.client.close()

    def warm_up(self) -> None:
        """Load local ONNX inference sessions before the first user question."""
        warmup_question = "Describe a software vulnerability"
        next(self.embedder.query_embed(warmup_question)).tolist()
        list(
            self.reranker.rerank(
                warmup_question,
                ["A software vulnerability affects an application."],
                batch_size=1,
            )
        )

    def retrieve(
        self,
        question: str,
        retrieval_limit: int = RETRIEVAL_LIMIT,
        rerank_limit: int = RERANK_LIMIT,
    ) -> list[dict[str, Any]]:
        question = question.strip()
        if not question:
            return []
        query_vector = next(self.embedder.query_embed(question)).tolist()
        exact_id = CVE_PATTERN.search(question)
        query_filter = None
        if exact_id:
            # CVE identifiers are exact keys, not semantic concepts. Restrict
            # Qdrant to that CVE while retaining vector ranking between its
            # individual chunks and the normal cross-encoder reranking stage.
            query_filter = self._Filter(
                must=[
                    self._FieldCondition(
                        key="metadata.cveId",
                        match=self._MatchValue(value=exact_id.group(0).upper()),
                    )
                ]
            )
        response = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vector,
            query_filter=query_filter,
            limit=retrieval_limit,
            with_payload=True,
            with_vectors=False,
        )
        candidates: list[dict[str, Any]] = []
        for point in response.points:
            payload = point.payload or {}
            content = str(payload.get("content") or "").strip()
            if not content:
                continue
            candidates.append(
                {
                    "pointId": str(point.id),
                    "content": content,
                    "metadata": dict(payload.get("metadata") or {}),
                    "vectorScore": float(point.score),
                }
            )
        if not candidates:
            return []

        scores = list(
            self.reranker.rerank(
                question,
                [candidate["content"] for candidate in candidates],
                batch_size=16,
            )
        )
        for candidate, score in zip(candidates, scores, strict=True):
            candidate["rerankScore"] = float(score)
        candidates.sort(key=lambda item: item["rerankScore"], reverse=True)
        return candidates[:rerank_limit]
