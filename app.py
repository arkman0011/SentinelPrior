"""Streamlit interface for the existing SentinelPrior unified backend."""

from __future__ import annotations

from queue import Queue
from threading import Lock, Thread
from time import perf_counter

import streamlit as st
from sqlalchemy import create_engine, text

from sentinelprior.orchestration.unified_chat import answer_question
from sentinelprior.rag.rag_llm import GroundedLLM
from sentinelprior.rag.rag_retriever import RAGRetriever
from sentinelprior.sql.textsql_chat import build_engines
from sentinelprior.sql.textsql_database import configured_database_url


st.set_page_config(page_title="SentinelPrior", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
    .stApp {background: linear-gradient(145deg, #07111f 0%, #0c1829 55%, #111827 100%);}
    .hero {padding: 1.6rem 1.8rem; border: 1px solid #26374f; border-radius: 18px;
           background: linear-gradient(120deg, rgba(17,34,57,.95), rgba(12,25,43,.9));
           box-shadow: 0 12px 36px rgba(0,0,0,.25); margin-bottom: 1.2rem;}
    .hero h1 {margin: 0; color: #f8fafc; font-size: 2.4rem;}
    .hero p {color: #9fb3c8; margin: .45rem 0 0;}
    .status {display:inline-block; padding:.22rem .65rem; border-radius:999px;
             color:#86efac; background:#123322; border:1px solid #23633d; font-size:.82rem;}
    [data-testid="stChatMessage"] {border:1px solid #26374f; border-radius:15px; padding:.35rem .75rem;}
    </style>
    <div class="hero">
      <span class="status">● Cloud intelligence ready</span>
      <h1>🛡️ SentinelPrior</h1>
      <p>Ask questions across structured CVE facts and grounded vulnerability descriptions.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource(show_spinner="Warming up SentinelPrior…")
def backend_resources():
    retriever = RAGRetriever()
    retriever.warm_up()
    return retriever, build_engines(), GroundedLLM(), Lock()


@st.cache_data(ttl=60, show_spinner=False)
def database_metrics() -> dict[str, int]:
    engine = create_engine(configured_database_url(), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT COUNT(*) AS total, "
                    "COALESCE(SUM(CASE WHEN cvss_severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical, "
                    "COALESCE(SUM(CASE WHEN cisa_kev_listed = 1 THEN 1 ELSE 0 END), 0) AS kev "
                    "FROM cves"
                )
            ).mappings().one()
            return {key: int(row[key] or 0) for key in ("total", "critical", "kev")}
    finally:
        engine.dispose()


def stream_answer(question: str) -> dict:
    request_started = perf_counter()
    retriever, engines, llm, backend_lock = backend_resources()
    setup_seconds = perf_counter() - request_started
    tokens: Queue[str | None] = Queue()
    state: dict = {}

    def run() -> None:
        try:
            with backend_lock:
                state["result"] = answer_question(
                    question, retriever, engines, llm, on_token=tokens.put
                )
        except Exception as error:
            state["error"] = str(error)
        finally:
            tokens.put(None)

    worker = Thread(target=run, daemon=True)
    worker.start()
    placeholder = st.empty()
    chunks: list[str] = []
    first_token_seconds: float | None = None
    while True:
        token = tokens.get()
        if token is None:
            break
        if first_token_seconds is None:
            first_token_seconds = perf_counter() - request_started
        chunks.append(token)
        placeholder.markdown("".join(chunks) + "▌")
    worker.join()
    if "error" in state:
        raise RuntimeError(state["error"])
    result = state["result"]
    result["setupSeconds"] = setup_seconds
    result["firstTokenSeconds"] = first_token_seconds
    result["streamlitTotalSeconds"] = perf_counter() - request_started
    placeholder.markdown(result["answer"])
    return result


def show_latency_diagnostics(result: dict) -> None:
    """Display temporary per-stage timings without changing the answer workflow."""
    timings = result.get("timings") or {}
    measurements = (
        ("Setup / warm-up", result.get("setupSeconds")),
        ("RAG + reranking", timings.get("rag")),
        ("TextSQL + Supabase", timings.get("sql")),
        ("First token", result.get("firstTokenSeconds")),
        ("Final LLM", timings.get("llm")),
        ("End-to-end", result.get("streamlitTotalSeconds")),
    )
    available = [(label, value) for label, value in measurements if value is not None]
    if not available:
        return
    with st.expander("Latency diagnostics (testing)"):
        columns = st.columns(3)
        for index, (label, value) in enumerate(available):
            columns[index % 3].metric(label, f"{float(value):.2f} s")
        st.caption(
            "RAG and TextSQL run in parallel; the final LLM starts after both finish."
        )


with st.sidebar:
    st.header("Current intelligence")
    try:
        metrics = database_metrics()
        st.metric("Current CVEs", metrics["total"])
        left, right = st.columns(2)
        left.metric("Critical", metrics["critical"])
        right.metric("CISA KEV", metrics["kev"])
    except Exception:
        st.info("Waiting for the first scheduled Supabase load.")
    st.caption("RAG: Qdrant Cloud · Facts: Supabase PostgreSQL")
    if st.button("Clear conversation", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

if "messages" not in st.session_state:
    st.session_state.messages = []

st.subheader("Ask the CVE intelligence assistant")
suggestions = st.columns(3)
examples = (
    "Which CVE has the highest EPSS score?",
    "Which vulnerability could terminate the JVM?",
    "Show the most severe vulnerabilities and their remedies.",
)
selected = ""
for column, example in zip(suggestions, examples, strict=True):
    if column.button(example, use_container_width=True):
        selected = example

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if message.get("evidence"):
            with st.expander("Evidence path"):
                st.caption(message["evidence"])
                if message.get("sql"):
                    st.code(message["sql"], language="sql")
        if message.get("latency"):
            show_latency_diagnostics(message["latency"])

question = selected or st.chat_input("Ask about CVEs, CVSS, EPSS, KEV, impact or remediation…")
if question:
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)
    with st.chat_message("assistant"):
        try:
            result = stream_answer(question)
            evidence = " · ".join(
                value for value in (
                    f"RAG: {result['ragSource']}" if result["ragSource"] else "",
                    f"TextSQL: {result['sqlProvider']}" if result["sqlProvider"] else "",
                    f"LLM: {result['provider']}",
                ) if value
            )
            with st.expander("Evidence path"):
                st.caption(evidence)
                if result["sql"]:
                    st.code(result["sql"], language="sql")
            show_latency_diagnostics(result)
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": result["answer"],
                    "evidence": evidence,
                    "sql": result["sql"],
                    "latency": result,
                }
            )
        except Exception as error:
            message = f"SentinelPrior is temporarily unavailable: {error}"
            st.error(message)
            st.session_state.messages.append({"role": "assistant", "content": message})
