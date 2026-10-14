"""RAG-first, SQLite-second, grounded SentinelPrior question workflow."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from time import perf_counter

from sentinelprior.rag.rag_llm import GroundedLLM
from sentinelprior.rag.rag_retriever import RAGRetriever
from sentinelprior.sql.textsql_chat import build_engines, query_with_fallback


MIN_RERANK_SCORE_FOR_ANSWER = 0.0


class AnswerStream:
    """Print final-answer chunks as the provider produces them."""

    def __init__(self) -> None:
        self.started = False

    def write(self, token: str) -> None:
        if not self.started:
            print("\nAnswer (streaming)")
            print("------------------")
            self.started = True
        print(token, end="", flush=True)

    def finish(self, answer: str, provider: str) -> None:
        if self.started:
            print(f"\n\nAnswered by: {provider}")
            return
        print(f"\nAnswer ({provider})")
        print("----------------")
        print(answer)


def print_timings(timings: dict[str, float], total_started: float) -> None:
    """Temporary opt-in diagnostic output for locating latency."""
    print("\nLatency diagnostics")
    print("-------------------")
    for key, label in (
        ("rag", "RAG retrieval + reranking"),
        ("sql", "TextSQL + SQLite"),
        ("llm", "Final LLM"),
    ):
        if key in timings:
            print(f"{label}: {timings[key]:.3f}s")
    print(f"Total: {perf_counter() - total_started:.3f}s")


def sql_has_rows(rows: object) -> bool:
    if rows is None:
        return False
    if isinstance(rows, (list, tuple, dict, set, str, bytes)):
        return len(rows) > 0
    return True


def answer_question(
    question: str,
    retriever: RAGRetriever,
    sql_engines: list,
    llm: GroundedLLM,
    max_rows: int = 20,
    show_timing: bool = False,
) -> None:
    total_started = perf_counter()
    timings: dict[str, float] = {}
    timings_lock = Lock()

    # The unchanged original question goes to both evidence pipelines at the
    # same time. The final LLM waits until both have completed.
    rag_error = ""
    retrieved = []
    sql_provider = "bypassed"
    sql_result = None
    sql_error = ""

    def retrieve_rag() -> list:
        started = perf_counter()
        try:
            return retriever.retrieve(question)
        finally:
            with timings_lock:
                timings["rag"] = perf_counter() - started

    def retrieve_sql() -> tuple[str, object]:
        started = perf_counter()
        try:
            return query_with_fallback(
                sql_engines,
                question,
                max_rows=max_rows,
                announce=False,
            )
        finally:
            with timings_lock:
                timings["sql"] = perf_counter() - started

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="sentinelprior") as executor:
        rag_future = executor.submit(retrieve_rag)
        sql_future = executor.submit(retrieve_sql)
        try:
            retrieved = rag_future.result()
        except Exception as error:
            rag_error = str(error).replace("\n", " ").strip()
        try:
            sql_provider, sql_result = sql_future.result()
        except Exception as error:
            sql_error = str(error).replace("\n", " ").strip()

    # A returned point is useful answer evidence only when the reranker's
    # relevance score is non-negative. Retrieval top-10 and reranking top-1
    # remain unchanged.
    rag_evidence = [
        item
        for item in retrieved
        if float(item.get("rerankScore", float("-inf"))) >= MIN_RERANK_SCORE_FOR_ANSWER
    ]

    sql_rows = sql_result.data if sql_result is not None else []
    has_rag_answer = bool(rag_evidence)
    has_sql_answer = sql_has_rows(sql_rows)

    # The final response is selected only after both retrieval attempts finish.
    stream = AnswerStream()
    llm_started = perf_counter()
    if has_rag_answer or has_sql_answer:
        answer, answer_provider = llm.answer_combined(
            question,
            rag_evidence,
            str(sql_result.sql) if sql_result is not None else "No SQL result",
            sql_rows,
            on_token=stream.write,
        )
        answer_mode = "local evidence"
    else:
        answer, answer_provider = llm.answer_no_evidence(question, on_token=stream.write)
        answer_mode = (
            "safe refusal; no local evidence found"
            if answer_provider == "Safety filter"
            else "LLM conversation; no local evidence required"
        )
    timings["llm"] = perf_counter() - llm_started
    stream.finish(answer, answer_provider)
    print(f"\nAnswer mode: {answer_mode}")
    print("\nEvidence path")
    print("-------------")
    if rag_evidence:
        metadata = rag_evidence[0].get("metadata") or {}
        print(
            f"RAG: {metadata.get('cveId', 'UNKNOWN')} "
            f"(top 1 after reranking)"
        )
    else:
        detail = f" ({rag_error[:160]})" if rag_error else ""
        print(f"RAG: no sufficiently relevant descriptive evidence{detail}")
    if sql_result is not None:
        print(f"SQLite/TextSQL: {sql_provider}")
        print(f"Generated SQL: {sql_result.sql}")
    else:
        detail = f" ({sql_error[:160]})" if sql_error else ""
        print(f"SQLite/TextSQL: no result{detail}")
    if show_timing:
        print_timings(timings, total_started)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ask SentinelPrior using parallel RAG and SQLite, then one grounded answer"
    )
    parser.add_argument("question", nargs="*", help="optional one-time natural-language question")
    parser.add_argument("--max-rows", type=int, default=20)
    parser.add_argument(
        "--timing",
        action="store_true",
        help="temporarily show RAG, TextSQL, final-LLM, and total latency",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    retriever = RAGRetriever()
    try:
        retriever.warm_up()
        sql_engines = build_engines()
        llm = GroundedLLM()
        one_time_question = " ".join(args.question).strip()
        if one_time_question:
            answer_question(
                one_time_question,
                retriever,
                sql_engines,
                llm,
                args.max_rows,
                show_timing=args.timing,
            )
            return

        print("SentinelPrior unified CVE assistant")
        print("Question flow: RAG + SQLite/TextSQL in parallel -> grounded LLM answer")
        print("Type exit to stop.")
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
                answer_question(
                    question,
                    retriever,
                    sql_engines,
                    llm,
                    args.max_rows,
                    show_timing=args.timing,
                )
            except RuntimeError as error:
                print(f"\n{error}")
                if not sql_engines or not llm.providers:
                    break
    finally:
        retriever.close()


if __name__ == "__main__":
    main()
