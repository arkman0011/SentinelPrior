# Architecture Notes

SentinelPrior uses one coordinator with small specialized components. This keeps the system agentic without hiding control flow inside a large framework.

## Components

1. **Coordinator Agent** - owns the run state and controls the workflow.
2. **Planner** - converts the goal into a visible list of operational steps. It uses OpenAI Structured Outputs when configured and a documented deterministic plan otherwise.
3. **Input Validator** - parses CSV, validates CVE format and values, and removes duplicates.
4. **Enrichment Tools** - query NVD, CISA KEV, and FIRST EPSS.
5. **Risk Engine** - applies deterministic rules and produces a priority, score, confidence, reasons, and defensive actions.
6. **Quality Checks** - reject incomplete internal results and surface unavailable sources.
7. **Report Writer** - produces Markdown, JSON, logs, and a transcript.

## Responsibility boundary

```text
AI: goal interpretation, plan wording, executive narrative
Code: validation, retries, API parsing, scores, priorities, QA
Human: verify applicability, approve remediation, change systems
```

The application deliberately avoids exposing private chain-of-thought. The visible planning trace contains actions, purposes, tool status, errors, and final evidence.
