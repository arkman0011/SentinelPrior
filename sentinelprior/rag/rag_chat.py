"""Interactive grounded RAG chat over the independent CVE Qdrant index."""

from __future__ import annotations

import argparse

from sentinelprior.rag.rag_llm import GroundedLLM
from sentinelprior.rag.rag_retriever import RAGRetriever


def answer_question(retriever: RAGRetriever, llm: GroundedLLM, question: str) -> None:
    evidence = retriever.retrieve(question)
    if not evidence:
        print("No relevant CVE evidence was retrieved.")
        return
    answer, provider = llm.answer(question, evidence)
    print(f"\nAnswer ({provider})")
    print("----------------")
    print(answer)
    print("\nRetrieved evidence")
    print("------------------")
    for item in evidence:
        metadata = item.get("metadata") or {}
        print(
            f"- {metadata.get('cveId', 'UNKNOWN')} "
            f"| vector={item['vectorScore']:.4f} "
            f"| reranker={item['rerankScore']:.4f} "
            f"| chunk={metadata.get('chunkIndex', 0) + 1}/{metadata.get('totalChunks', 1)}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ask grounded questions of the SentinelPrior CVE RAG index")
    parser.add_argument("question", nargs="*", help="optional one-time natural-language question")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    retriever = RAGRetriever()
    try:
        llm = GroundedLLM()
        one_time_question = " ".join(args.question).strip()
        if one_time_question:
            answer_question(retriever, llm, one_time_question)
            return

        print("SentinelPrior grounded RAG chat")
        print("Ask an explanatory CVE question, or type exit to stop.")
        while True:
            try:
                question = input("\nQuestion: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if question.casefold() in {"exit", "quit"}:
                break
            if not question:
                continue
            try:
                answer_question(retriever, llm, question)
            except RuntimeError as error:
                print(f"\n{error}")
                if not llm.providers:
                    break
    finally:
        retriever.close()


if __name__ == "__main__":
    main()
