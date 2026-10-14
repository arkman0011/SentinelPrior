"""Embed RAG chunks with BGE and store them in Qdrant Cloud or locally."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from sentinelprior.rag.rag_chunker import create_chunks
from sentinelprior.rag.rag_config import (
    EMBEDDING_DIMENSION,
    EMBEDDING_MODEL,
    QDRANT_COLLECTION,
    QDRANT_PATH,
    RAG_CHUNKS_FILE,
    RAG_DOCUMENTS_FILE,
    qdrant_collection_name,
    qdrant_connection,
)


def required_packages() -> tuple[Any, Any, Any, Any, Any]:
    try:
        from fastembed import TextEmbedding
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, PointStruct, VectorParams
    except ImportError as error:
        raise RuntimeError(
            "RAG packages are not installed. Run: "
            "python -m pip install fastembed qdrant-client semchunk"
        ) from error
    return QdrantClient, Distance, PointStruct, VectorParams, TextEmbedding


def index_documents(
    documents_path: Path = RAG_DOCUMENTS_FILE,
    chunks_path: Path = RAG_CHUNKS_FILE,
    qdrant_path: Path = QDRANT_PATH,
    collection_name: str = QDRANT_COLLECTION,
) -> dict[str, Any]:
    QdrantClient, Distance, PointStruct, VectorParams, TextEmbedding = required_packages()
    model = TextEmbedding(model_name=EMBEDDING_MODEL)
    chunks = create_chunks(documents_path, chunks_path, token_counter=model.token_count)
    if not chunks:
        raise RuntimeError(f"No chunks were created from {documents_path}")

    vectors = list(model.passage_embed([chunk["content"] for chunk in chunks], batch_size=32))
    dimension = len(vectors[0])
    if dimension != EMBEDDING_DIMENSION:
        raise RuntimeError(
            f"Unexpected embedding dimension {dimension}; expected {EMBEDDING_DIMENSION}"
        )

    collection_name = qdrant_collection_name(collection_name)
    connection, storage_location = qdrant_connection(qdrant_path)
    client = QdrantClient(**connection)
    try:
        if client.collection_exists(collection_name):
            client.delete_collection(collection_name)
        client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=dimension, distance=Distance.COSINE),
        )
        points = [
            PointStruct(
                id=chunk["chunkId"],
                vector=vector.tolist(),
                payload={"content": chunk["content"], "metadata": chunk["metadata"]},
            )
            for chunk, vector in zip(chunks, vectors, strict=True)
        ]
        client.upsert(collection_name=collection_name, points=points, wait=True)
        stored = int(client.count(collection_name=collection_name, exact=True).count)
    finally:
        client.close()

    return {
        "documentsFile": str(documents_path.resolve()),
        "chunksFile": str(chunks_path.resolve()),
        "qdrantPath": storage_location,
        "collection": collection_name,
        "embeddingModel": EMBEDDING_MODEL,
        "chunksStored": stored,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the independent SentinelPrior Qdrant RAG index")
    parser.add_argument("--documents", type=Path, default=RAG_DOCUMENTS_FILE)
    parser.add_argument("--chunks", type=Path, default=RAG_CHUNKS_FILE)
    parser.add_argument("--qdrant-path", type=Path, default=QDRANT_PATH)
    parser.add_argument("--collection", default=QDRANT_COLLECTION)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = index_documents(args.documents, args.chunks, args.qdrant_path, args.collection)
    print(f"Stored {result['chunksStored']} chunk(s) in Qdrant.")
    print(f"Collection: {result['collection']}")
    print(f"Qdrant path: {result['qdrantPath']}")


if __name__ == "__main__":
    main()
