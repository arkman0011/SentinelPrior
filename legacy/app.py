"""Complete local SentinelPrior Streamlit dashboard."""

from __future__ import annotations

import streamlit as st

import query
from chatbot import respond
from gemini_client import explain
from department_reports import generate_report, records_for_department


DEPARTMENTS = {
    "Security": "security, vulnerability, exploit, attack, risk, cve",
    "Software Engineering": "software, code, library, framework, api, application",
    "Cloud / DevOps": "cloud, docker, kubernetes, container, server, linux, aws",
    "IT / Network Operations": "network, vpn, router, firewall, browser, endpoint",
    "Database / Data Engineering": "database, sql, postgres, mysql, data, storage",
    "Finance / Payments": "finance, payment, billing, banking, transaction",
    "HR": "hr, human resource, employee, payroll, personnel",
    "Risk / Compliance / Management": "compliance, policy, governance, audit, risk, management",
}


def records_for_department(terms_text: str) -> list[dict]:
    terms = [term.strip() for term in terms_text.split(",")]
    records = query.search("", limit=500)
    return [
        record for record in records
        if any(term in f"{record.get('cve_id', '')} {record.get('description', '')} {record.get('nvd', {})}".lower() for term in terms)
    ]


def show_department(department: str, terms_text: str) -> None:
    records = records_for_department(terms_text)
    st.subheader(f"{department} report")
    if not records:
        st.info("No matching CVEs are currently stored for this department.")
        return
    if st.button(f"Generate {department} summary", key=f"summary-{department}"):
        with st.spinner("Generating summary..."):
            try:
                report = generate_report(department)
                st.write(report["summary"])
            except Exception as error:
                st.error("Gemini is temporarily unavailable. Please try this department again in a moment.")
                with st.expander("Technical details"):
                    st.code(str(error))
    st.caption(f"{len(records)} matching CVE record(s)")
    st.dataframe([
        {"CVE ID": item.get("cve_id"), "CVSS": item.get("cvss_score"),
         "Severity": item.get("severity"), "EPSS": item.get("epss_score"),
         "KEV": item.get("cisaKevListed")}
        for item in records
    ], use_container_width=True)


st.set_page_config(page_title="SentinelPrior", page_icon="🛡️", layout="wide")
st.title("🛡️ SentinelPrior")
st.caption("CVE intelligence dashboard powered by SQLite and Gemini")

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

st.header("Ask SentinelPrior")
for message in st.session_state.chat_history:
    with st.chat_message(message["role"]):
        st.write(message["content"])

question = st.chat_input("Ask about CVSS, EPSS, KEV, vendors or products...")
if question:
    st.session_state.chat_history.append({"role": "user", "content": question})
    try:
        answer = respond(question)
    except Exception as error:
        answer = f"Unable to generate the AI answer: {error}"
    st.session_state.chat_history.append({"role": "assistant", "content": answer})
    st.rerun()

st.divider()
st.header("Department reports")
tabs = st.tabs(list(DEPARTMENTS))
for tab, (department, terms) in zip(tabs, DEPARTMENTS.items()):
    with tab:
        show_department(department, terms)

with st.sidebar:
    st.header("Database overview")
    try:
        all_records = query.search("", limit=500)
        st.metric("Stored CVEs", len(all_records))
        st.metric("Critical CVEs", len(query.critical_cves()))
        st.metric("KEV CVEs", len(query.kev_cves(500)))
    except Exception as error:
        st.error(f"Database unavailable: {error}")
    if st.button("Clear temporary chat"):
        st.session_state.chat_history = []
        st.rerun()
