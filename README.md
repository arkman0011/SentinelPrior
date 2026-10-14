# SentinelPrior CVE Intelligence

SentinelPrior builds two complementary evidence stores from the same daily CVE
collection. SQLite keeps complete structured enriched records. Qdrant keeps a
reduced descriptive representation for semantic retrieval.

## Project structure

```text
New SentinelPrior project/
├── run_pipeline.py                 # complete daily data workflow
├── chat.py                         # unified RAG -> SQLite -> LLM chat
├── sentinelprior/
│   ├── ingestion/                  # collect, clean, enrich
│   ├── rag/                        # RAG preparation, indexing and retrieval
│   ├── sql/                        # SQLite loading and TextSQL
│   └── orchestration/              # combined workflows
├── data/                            # generated JSON, SQLite and Qdrant data
├── legacy/                          # preserved earlier UI/CrewAI prototype
├── .env.example                    # safe environment-variable template
├── .env                            # local credentials; never committed
└── requirements.txt
```

## Daily data workflow

```text
CVEProject deltaLog
        ↓
Collector: exact publication date 30 days before the run
        ↓
data/raw_cves.json
        ↓
Cleaner / flattener
        ↓
data/clean_cves.json
        ↓
NVD + FIRST EPSS + CISA KEV enrichment
        ↓
data/enriched_cves.json
        ├── complete structured records → SQLite
        └── reduced descriptive RAG JSON
                 ↓
            chunk + embed
                 ↓
            local Qdrant
```

Run the complete workflow from the project root:

```powershell
& ".\.venv\Scripts\python.exe" run_pipeline.py
```

The collector's existing selection policy is unchanged: it looks only at the
exact UTC date 30 days before the run and requires the NVD record, English
description, CVSS, affected-product information and FIRST EPSS evidence.

## Unified question workflow

```text
Original user question
     ├──→ Qdrant vector retrieval: top 10
     │          ↓
     │    MiniLM reranker: top 1
     │
     ├──→ SQLite/TextSQL search
     │
     └──→ Final LLM waits for both retrieval attempts
                         ↓
                    Final answer
```

If either RAG or SQLite returns useful local evidence, the final answer is
restricted to that evidence. When both systems return no usable evidence,
SentinelPrior may answer greetings and explain its own role, purpose, workflow,
and capabilities. The LLM classifies this conversational intent from its
system prompt; Python does not maintain a list of predefined questions. Every
other unsupported question receives the fixed response
`I don't know the answer from the available SentinelPrior data.` General
cybersecurity knowledge is never used as a substitute for missing local data.

The final LLM receives only these fields from the selected RAG result:

- CVE ID, for grounded citations
- description
- remediation
- official vendor solution

Vector scores, reranking scores, CVSS, EPSS and other structured metadata are
not included in the RAG portion of the final prompt. Structured facts come from
SQLite.

Start the unified interactive assistant:

```powershell
& ".\.venv\Scripts\python.exe" chat.py
```

Start the Streamlit interface:

```powershell
& ".\.venv\Scripts\python.exe" -m streamlit run app.py
```

Ask one question directly:

```powershell
& ".\.venv\Scripts\python.exe" chat.py "Which vulnerability can terminate the JVM and how should it be fixed?"
```

## Individual pipelines

The two established pipelines remain independently available:

```powershell
& ".\.venv\Scripts\python.exe" -m sentinelprior.orchestration.rag_pipeline
& ".\.venv\Scripts\python.exe" -m sentinelprior.rag.rag_chat

& ".\.venv\Scripts\python.exe" -m sentinelprior.orchestration.textsql_pipeline
& ".\.venv\Scripts\python.exe" -m sentinelprior.sql.textsql_chat
```

The RAG configuration remains:

- embedding: `BAAI/bge-small-en-v1.5`
- retrieval: top 10
- reranker: `Xenova/ms-marco-MiniLM-L-6-v2`
- reranking output: top 1
- Qdrant path: `data/qdrant/`

The provider fallback order remains Groq, Gemini and Mistral. API keys stay in
`.env`; never commit that file.

## Supabase PostgreSQL

Set `SUPABASE_DB_URL` to the Supabase session-pooler connection string. The
daily pipeline then replaces the `cves` table in one transaction with the
current batch. If that transaction fails, the preceding batch remains intact.
When the variable is absent, the established local SQLite database is used.

Generated JSON files are temporary pipeline files and are not uploaded to
Supabase Storage. Qdrant is rebuilt from the current RAG documents during the
same daily run, so PostgreSQL and Qdrant both expose only the newest batch.

## Qdrant Cloud

Add the cluster endpoint and API key to the local `.env` file:

```dotenv
QDRANT_URL=https://your-cluster-endpoint
QDRANT_API_KEY=your_qdrant_api_key
QDRANT_COLLECTION=sentinelprior_cve_rag
```

Then run the normal RAG pipeline. It creates the collection and uploads the
current chunks to Qdrant Cloud. If `QDRANT_URL` is absent, SentinelPrior keeps
using the established local `data/qdrant/` index.
