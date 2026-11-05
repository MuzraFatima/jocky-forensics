# JOCKY Gap Analysis and Roadmap

This compares the repository against the *JOCKY SIH26148 Master Research Blueprint* and lays out
the remaining work as five phases (0–4). Each phase lands as one pull request into `main`.

## Where the project stands

| Blueprint area | Status in repo | Notes |
|---|---|---|
| DSL lexer / parser / AST | Done | `backend/app/language/` — flat keyword grammar (`CASE`, `TARGET`, `COLLECT`, `ANALYZE`, `VERIFY`, `REPORT`) with `WHERE` filters |
| Semantic validation | Partial | Structural rules only; no type system, no error codes, no suggested corrections |
| Typed, versioned IR | Partial | IR v1.0 has no source mapping, no declared capabilities, no output schema |
| Platform backend (IR → OS capability) | Missing | Unsupported operations are not reported explicitly at compile time |
| Restricted runtime | Done | IR executor dispatches only to a fixed collector catalog; no shell execution |
| Windows / Ubuntu adapters | Partial | System, process, network, files, users, registry. **Missing:** services, startup entries, drivers / kernel modules, DNS cache, listening-port view |
| Normalized process schema (§5.3) | Partial | No `collection_status`, no `source_platform` on every record |
| Function contract (§6.2) | Partial | Results lack a uniform envelope (collector version, endpoint, status) |
| Detection: rules, behaviour, correlation | Partial | Analyzers and a correlator exist; no declarative (Sigma-style) rule files, no baselines, no confidence / benign-explanation fields |
| Detection evaluation (E4) | Missing | No labeled fixtures, no precision / recall / F1 harness |
| Evidence hashing + custody | Done | SHA-256 vault with custody log |
| Tamper-evident audit trail | Missing | Audit log is a plain list; entries are not hash-chained |
| Encryption at rest (AES-256-GCM) | Missing | Evidence is stored as plaintext JSON |
| Orchestration (pairing, heartbeat, jobs) | Done | `backend/app/agents/`, `agent/` |
| Signed jobs, expiry, replay protection | Missing | Jobs are not signed; the agent cannot verify them |
| Auth on forensic API | Missing | `/api/jocky/*` and `/api/forensics/*` (including `simulate-tampering`) accept unauthenticated calls |
| RBAC | Missing | One investigator role; no approve / view separation |
| Multi-endpoint case | Partial | Jobs target one device at a time |
| Experiments E1–E6 | Missing | No documented methodology or results |
| CI / lint | Missing → Phase 0 | No workflow; tests rewrote tracked `data/*.json` |
| Docs accuracy | Drifted | `FINAL_PROTOTYPE_STATUS.md` cited files that do not exist |

## Progress

| Phase | State |
|---|---|
| 0 — Foundation and CI | Merged (#1) |
| 1 — Language and compiler | Merged (#2) |
| 2 — Cross-platform forensic library | Merged (#3) |
| 3 — Detection and evidence integrity | In review |
| 4 — Secure orchestration and hardening | Planned |

## Phase 0 — Foundation and CI
- ruff config and a clean lint pass over the Python code
- ESLint for the frontend; fix the undefined `handleVerifyVault` crash
- GitHub Actions: ruff, pytest on Ubuntu and Windows, frontend lint and build
- Tests isolated from tracked `data/` files
- This gap analysis; correct the stale file paths in the status document

## Phase 1 — Language and compiler
- Block syntax `investigation "name" { ... }` alongside the existing flat syntax
- Diagnostics with stable error codes and "did you mean" suggestions
- IR v2: source-line mapping, required capability per operation, output schema
- Platform backend that lowers IR for `windows` / `linux` and marks unsupported operations explicitly
- `jocky compile --emit ir|ast --platform <os>` CLI and a written grammar (EBNF) / language spec

## Phase 2 — Cross-platform forensic library
- Services and startup-entry collectors (Windows services / Run keys, systemd units / cron / autostart)
- Driver and kernel-module inventory (Windows driver services, `/proc/modules`)
- Listening ports and DNS resolver configuration
- Uniform result envelope (§6.2) and normalized process schema (§5.3) with `collection_status`
- New DSL targets wired through lexer, validator, IR and executor

## Phase 3 — Detection and evidence integrity
- Declarative detection rules with severity, confidence, ATT&CK mapping and benign explanations; at least five rules
- Labeled benign / suspicious fixtures and a precision / recall / F1 harness (E4)
- Hash-chained, tamper-evident audit log with a verification endpoint
- AES-256-GCM encryption of evidence at rest with verified retrieval
- Tamper-detection experiment (E5)

## Phase 4 — Secure orchestration and hardening
- Authentication required on forensic and DSL endpoints; RBAC (viewer / investigator / admin)
- HMAC-signed jobs with expiry and nonce replay protection, verified by the agent
- One case dispatched across several endpoints with aggregated status
- Experiments write-up (E1–E6) and updated README / architecture docs
