# Assessment Requirement Mapping

| Requirement | Implementation |
|---|---|
| Natural-language goal | `--goal` input processed by the Planner |
| Visible planning trace | Printed plan plus `run_transcript.md` |
| At least two tools | CSV reader, NVD, CISA KEV, EPSS, report writer |
| Step-by-step execution | `CoordinatorAgent.run()` and execution events |
| Deliberately induced failure | `--simulate-epss-failure` |
| Graceful recovery | Three attempts, explicit null value, reduced confidence, continued report |
| Structured result | Markdown and JSON reports |
| No provided dataset | Synthetic inputs plus live public APIs |
| Document assumptions | README disclosure and report limitations |
| Source code and README | Repository root |
| Architecture diagram | `docs/architecture.png` (editable SVG included) |
| 2-3 sample runs | `docs/sample_runs/` |
| One-page write-up | `docs/DESIGN_WRITEUP.md` |
| Tests | `tests/` |
