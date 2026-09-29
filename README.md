# JOCKY — Domain-Specific Forensic Analysis Framework

A domain-specific programming language and execution framework for authorized computer and network forensic analysis without triggering endpoint security solutions.

[![Tests](https://img.shields.io/badge/Tests-359%20Passing-success?style=flat-square&logo=pytest)](tests/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?style=flat-square&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=flat-square)](backend/app/collectors/)

---

## Problem Statement

> **Smart India Hackathon (SIH) — SIH26148**  
> *"Creation of scripts/functions with new programming language to commence Computer & Network forensic analysis without triggering security solutions."*

---

## What It Does

JOCKY is a domain-specific forensic programming language and execution framework designed for security teams, incident responders, and forensic examiners:

- **Domain-Specific Language**: Investigators define structured, reproducible forensic triage routines using intuitive, declarative JOCKY commands.
- **Safe Telemetry Acquisition**: Collects system metadata, process hierarchies, and network socket telemetry using standard read-only OS instrumentation.
- **Cryptographic Evidence Vault**: Acquired telemetry is immediately sealed with SHA-256 digests and registered into an auditable chain of custody.
- **Advanced Technique Analysis**: Transparently evaluates evidence through a structured analytical pipeline: `Evidence → Observable Indicator → Technique → Forensic Finding`.
- **Correlation, Timeline & MITRE ATT&CK**: Correlates network connections to process trees, reconstructs a chronological event timeline, and maps findings to MITRE ATT&CK tactics and techniques.
- **Local & Endpoint Workflows**: Supports standalone local triage as well as remote multi-workstation investigations via a lightweight, authenticated Endpoint Agent.

---

## Why JOCKY?

Standard administrative scripts (such as aggressive PowerShell loops or unconstrained shell pipelines) frequently trigger false-positive alerts on Antivirus (AV) and Endpoint Detection & Response (EDR) agents. This alert fatigue hinders legitimate incident response.

JOCKY addresses this problem through structural design:

- **Structured Forensic Investigations**: Replaces fragile, ad-hoc shell commands with declarative, validated forensic directives.
- **Repeatable Investigation Workflows**: Standardized Intermediate Representation (IR) guarantees consistent, deterministic execution across investigations.
- **Evidence Integrity & Traceability**: Immutable custody logging and millisecond SHA-256 sealing ensure verifiable chain of custody for legal and operational review.
- **Cross-Platform Collection**: Unified data schemas normalize telemetry across Windows, Linux, and macOS without relying on platform-specific quirks.
- **Advanced Technique Analysis**: Detects persistence, unusual process lineage, and suspicious network indicators through deterministic heuristic rules without running offensive code.
- **Centralized Evidence & Reporting**: Packages findings into tamper-evident bundles and exports executive dossiers in JSON, HTML, and Markdown.

---

## Key Features

| Component | Description |
|---|---|
| **JOCKY DSL** | High-level declarative syntax for incident triage (`CASE`, `TARGET`, `COLLECT`, `ANALYZE`, `VERIFY INTEGRITY`, `REPORT`) |
| **Parser / AST / IR** | Lexer, recursive-descent parser, semantic policy validator, and portable Intermediate Representation (IR v1.0) |
| **Forensic Collectors** | Safe, read-only collectors for system hardware/OS, running processes, sockets, user accounts, and filesystem metadata |
| **Endpoint Agent** | Autonomous daemon featuring single-use pairing codes, secure authentication, heartbeat streaming, and job polling |
| **Evidence Vault** | File-backed JSON repository storing collected telemetry artifacts isolated by case identifier |
| **SHA-256 Integrity Verification** | Cryptographic hashing at acquisition with mathematical tamper detection and full-vault audit routines |
| **Advanced Technique Analysis** | Structured inference pipeline converting raw telemetry into explainable forensic findings |
| **Correlation Graph** | Correlates network socket listeners and outbound connections with process trees and binaries |
| **Forensic Timeline** | Unified chronological timeline consolidating process launches, network activity, and file events |
| **MITRE ATT&CK Mapping** | Direct mapping of forensic findings to ATT&CK tactics and techniques with verifiable evidence lineage |
| **Forensic Reports** | Multi-format reporting engine outputting machine-readable JSON, print-ready HTML dossiers, and Markdown |
| **React Dashboard** | Full-stack Dark Cyber forensic console built with React 18 and Vite for real-time investigation management |

---

## Architecture

```text
JOCKY Script / Dashboard
        │
        ▼
Parser → AST → IR
        │
        ▼
   IR Executor
        │
        ▼
Collectors / Endpoint Agent
        │
        ▼
  Evidence Vault
        │
        ▼
SHA-256 Verification
        │
        ▼
Advanced Technique Analysis
        │
        ▼
Correlation → Timeline → MITRE ATT&CK
        │
        ▼
  Report Engine
        │
        ▼
React Dashboard / Reports
```

---

## JOCKY DSL

JOCKY uses a declarative domain-specific language designed specifically for forensic inquiry. Scripts define investigation scope, target hosts, telemetry collection scopes, analysis passes, integrity checks, and output formats.

### Supported Commands

- `CASE "<case-id>"` — Declares the unique case docket identifier (required).
- `TARGET "<target-host>"` — Designates the local or remote target endpoint (required).
- `COLLECT SYSTEM` — Acquires hardware, OS version, kernel, and system specifications.
- `COLLECT PROCESSES` — Acquires process trees, PID/PPID relationships, command lines, and memory metrics.
- `COLLECT NETWORK` — Acquires active network interfaces, listening sockets, and established connections.
- `ANALYZE` — Executes anomaly detection, suspicious path heuristics, and cross-source correlation.
- `VERIFY INTEGRITY` — Audits stored evidence artifacts by recomputing SHA-256 digests against custody records.
- `REPORT` — Synthesizes forensic findings into structured dossiers (supports format parameters).

### Example Script

```jocky
# JOCKY Forensic Investigation Script
CASE "INCIDENT-2026-001"
TARGET "WORKSTATION-01"

COLLECT SYSTEM
COLLECT PROCESSES
COLLECT NETWORK

ANALYZE
VERIFY INTEGRITY
REPORT
```

---

## Core Components

### 1. JOCKY Language Engine
Located in `backend/app/language/`:
- **Lexer (`lexer.py`)**: Tokenizes source text into strongly typed tokens while capturing line numbers, column offsets, and character spans.
- **Parser (`parser.py`)**: Recursive-descent parser enforcing language grammar and building an Abstract Syntax Tree (AST) composed of typed nodes (`CaseNode`, `TargetNode`, `CollectNode`, `AnalyzeNode`, `VerifyNode`, `ReportNode`).
- **Semantic Validator (`validator.py`)**: Enforces structural invariants (mandatory case and target declarations, valid collection targets, and path sanitization).
- **IR Generator (`ir.py`, `compiler.py`)**: Compiles validated AST into a standardized JOCKY Intermediate Representation (IR v1.0) JSON structure.

### 2. Execution Engine
Located in `backend/app/engine/`:
- **IR Executor (`ir_executor.py`)**: Traverses the Intermediate Representation sequentially, executing operations with error boundaries and producing an execution receipt.
- **Policy Enforcement (`ir_policy.py`, `policy.py`)**: Strictly limits operations to read-only actions, disallowing file modification, arbitrary code execution, and directory traversal.
- **Hardening & Isolation (`hardening.py`)**: Enforces rate limiting, bounded memory inspection, execution timeouts, and path sandboxing to minimize host impact.

### 3. Forensic Collectors
Located in `backend/app/collectors/`:
- **Dispatcher (`dispatcher.py`)**: Auto-detects the operating platform (`Windows`, `Linux`, or `Darwin`) and routes collection tasks to platform-specific modules.
- **System Collector (`system.py`)**: Extracts hardware model, architecture, CPU count, boot time, memory limits, and OS build metadata.
- **Process Collector (`processes.py`)**: Enumerates running tasks, process identifiers (PID), parent process identifiers (PPID), usernames, memory RSS/VMS, and launch arguments via `psutil`.
- **Network Collector (`network.py`)**: Inspects open listening sockets, established connections, bound interfaces, and IP/port-to-PID relationships without injecting network packets.
- **Auxiliary Collectors**: Includes read-only file metadata collector (`files.py`), user account inspector (`users.py`), and platform persistence metadata collectors (`linux_collectors.py`, `macos_collectors.py`, `windows_metadata.py`).

### 4. Endpoint Agent
Located in `agent/` and `jocky-agent.py`:
- **Pairing**: Connects endpoints to the central server using an 8-character single-use pairing code generated from the dashboard.
- **Device Authentication**: Authenticates communication sessions using token credentials stored locally in `.jocky-agent.json`.
- **Heartbeat Loop**: Periodically streams heartbeat telemetry to report connectivity, load, and host status.
- **Job Polling**: Polls the server queue for pending forensic collection jobs scoped to the endpoint.
- **Evidence Submission**: Bundles acquired telemetry with SHA-256 hashes and posts the results back to the central server.
- **Device Revocation**: Supports administrative revocation from the dashboard to reject requests from compromised endpoints.
- **Server-Side Verification**: Verifies incoming hashes, matches device credentials, and normalizes device records.

### 5. Evidence Vault
Located in `backend/app/evidence/`:
- **Evidence Artifacts**: Stores acquired forensic telemetry as structured JSON files under `evidence/vault/cases/<CASE_ID>/`.
- **SHA-256 Hashes**: Computes cryptographic hashes over raw artifact bytes at the exact moment of collection.
- **Integrity Verification**: Audits stored artifacts by recalculating file hashes and comparing them against recorded digests.
- **Chain of Custody (`custody.py`)**: Logs chronological custody events (`ACQUIRED`, `VERIFIED`, `ACCESSED`, `EXPORTED`, `TAMPER_DETECTED`) with timestamps and operator identity.
- **Endpoint Provenance**: Records originating device IDs and hostnames in artifact metadata to preserve collection origin.
- **Tamper Detection**: Identifies any post-collection modification or unauthorized disk mutation, flagging tampered artifacts during audit.

### 6. Advanced Technique Analysis
Located in `backend/app/analysis/`:
- **Inference Pipeline**:
  ```text
  Evidence
     │
     ▼
  Observable Indicator
     │
     ▼
  Technique
     │
     ▼
  Forensic Finding
  ```
- **Indicator Extraction**: Identifies suspicious process paths (e.g., binaries executing from temporary folders), anomalous parent-child execution lineages, unmapped network binaries, and persistence hooks.
- **Defensive Scope**: **The implementation strictly focuses on forensic detection and analysis.** It does not execute offensive evasion techniques, exploit vulnerabilities, or inject code.

### 7. Correlation and Timeline
Located in `backend/app/analysis/`:
- **Entity Correlation (`correlator.py`)**: Correlates socket listeners and active connections with process entities, linking network behavior directly to executable binaries.
- **Timeline Synthesis (`timeline.py`)**: Aggregates timestamps from process creation, file access, and network connections into a normalized chronological sequence for root-cause analysis.

### 8. MITRE ATT&CK Mapping
Located in `backend/app/analysis/mapping.py` and `mitre.py`:
- Maps detected forensic findings to MITRE ATT&CK techniques (e.g., T1059 Command and Scripting Interpreter, T1057 Process Discovery, T1049 System Network Connections Discovery, T1071 Application Layer Protocol).
- Maintains strict traceability from each mapped technique back to the exact evidence artifact and raw indicator that triggered it.

### 9. Reporting
Located in `backend/app/reporting/report_engine.py`:
- **JSON**: Machine-readable, structured export designed for SIEM ingestion and programmatic pipelines.
- **HTML**: Self-contained, printable forensic dossier including executive summaries, integrity audit results, and MITRE ATT&CK tables.
- **Markdown**: Clean, structured text summary suitable for incident tracking systems and documentation repositories.

### 10. Dashboard
Located in `frontend/`:
- **Investigation Workspace**: Full-featured React 18 + Vite interface with a Dark Cyber forensic color scheme.
- **Script Studio**: Interactive JOCKY DSL editor with validation feedback, compilation inspections, and execution triggers.
- **Device Management**: Unified target device selector with live agent status, pairing code generation, and revocation controls.
- **Evidence & Analytics**: Interactive Evidence Vault viewer, correlation graphs, chronological event timeline, and multi-format report exporter.

---

## Repository Structure

```text
jocky-forensics/
├── agent/                        # Endpoint agent implementation
│   ├── adapter.py                # Telemetry adaptation & serialization
│   ├── client.py                 # HTTP client (pairing, heartbeat, jobs)
│   ├── config.py                 # Agent configuration & credential storage
│   └── runner.py                 # Background polling & heartbeat loop
├── backend/
│   ├── app/
│   │   ├── agents/               # Endpoint agent management & routes
│   │   ├── analysis/             # Correlation, timeline & MITRE analyzers
│   │   ├── collectors/           # Cross-platform read-only collectors
│   │   ├── engine/               # IR executor, policy & hardening
│   │   ├── evidence/             # Evidence vault, custody ledger & hashing
│   │   ├── language/             # JOCKY DSL lexer, parser, AST & compiler
│   │   ├── reporting/            # HTML, JSON & Markdown report generation
│   │   ├── security/             # Authentication, RBAC, audit & AI support
│   │   ├── cli.py                # CLI command implementations
│   │   └── main.py               # FastAPI application entrypoint
│   ├── test_e2e_full_workflow.py # End-to-end integration test
│   └── requirements.txt          # Python dependencies
├── frontend/                     # React 18 + Vite investigative dashboard
│   ├── src/                      # UI components, views, styles & API client
│   ├── package.json              # Frontend npm dependencies
│   ├── vite.config.js            # Vite configuration & API proxy
│   └── index.html                # Application entry HTML
├── examples/                     # Sample JOCKY forensic scripts
│   ├── sample.jocky              # Canonical triage script
│   └── invalid.jocky             # Malformed script for error testing
├── tests/                        # Automated test suite (359 tests)
├── architecture.md               # Technical specification & architecture notes
├── Dockerfile                    # Container build configuration
├── jocky-agent.py                # Standalone endpoint agent CLI runner
└── jocky.py                      # Master CLI runner
```

---

## Quickstart

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Node.js 18+ and npm
- Git

### 1. Clone Repository & Enter Directory
```bash
git clone https://github.com/MuzraFatima/jocky-forensics.git
cd jocky-forensics
```

### 2. Install Python Dependencies
```bash
pip install -r backend/requirements.txt
```

### 3. Start the Backend Server
```bash
python jocky.py serve --port 8000
```
- API Root: `http://127.0.0.1:8000/api`
- Interactive API Documentation: `http://127.0.0.1:8000/docs`

### 4. Start the Frontend Dashboard
In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```

### 5. Open the Dashboard
Navigate to `http://localhost:5173` in your browser.  
Default test analyst credentials: `analyst` / `analyst123`

---

## Endpoint Agent

The standalone agent (`jocky-agent.py`) runs on remote workstations to facilitate authorized remote telemetry collection:

```bash
# 1. Pair device with the central JOCKY server using an 8-character pairing code
python jocky-agent.py pair --server http://127.0.0.1:8000 --code ABC12345 [--name "WORKSTATION-01"]

# 2. Start the agent daemon (heartbeat and job polling loop)
python jocky-agent.py start [--interval 2.0] [--heartbeat 15.0]

# 3. Check enrollment status and test connection to the central server
python jocky-agent.py status

# 4. Unpair the device and remove local credentials
python jocky-agent.py unpair
```

---

## CLI

JOCKY provides a command-line interface via `jocky.py` for headless operations, scripted triage, and server hosting:

```bash
# Compile and validate a JOCKY DSL script
python jocky.py compile examples/sample.jocky

# Execute a script through the IR pipeline and output a report
python jocky.py execute examples/sample.jocky --format HTML --output reports/triage.html

# Audit the cryptographic integrity of the Evidence Vault
python jocky.py audit [--case <case_id>]

# Export a signed evidence bundle with manifest
python jocky.py export <case_id> [--output <path>]

# Start the FastAPI backend server
python jocky.py serve [--port 8000]

# Invoke endpoint agent commands via master executable
python jocky.py agent [pair|start|status|unpair]
```

---

## Investigation Workflow

```text
JOCKY Script
    │
    ▼
Select Target / Endpoint
    │
    ▼
Execute Investigation
    │
    ▼
Collect Evidence
    │
    ▼
Evidence Vault
    │
    ▼
Advanced Technique Analysis
    │
    ▼
Correlation
    │
    ▼
Timeline
    │
    ▼
MITRE ATT&CK
    │
    ▼
Forensic Report
```

---

## Testing

The project includes an automated test suite verifying compiler mechanics, telemetry collectors, evidence integrity, agent workflows, and report generation:

```bash
# Run the complete test suite
python -m pytest -v
```

**Verified Test Result**:
```text
359 passed, 1 warning in 193.13s
```

### Frontend Build
To validate production compilation of the React dashboard:

```bash
cd frontend
npm run build
```

**Verified Build Result**:
```text
✓ 44 modules transformed.
dist/index.html                   0.72 kB │ gzip:  0.42 kB
dist/assets/index-C6jg-Z6o.css    4.48 kB │ gzip:  1.67 kB
dist/assets/index-Q_uOOU1T.js   390.23 kB │ gzip: 92.20 kB
✓ built in ~5s
```

---

## Security & Scope

JOCKY is designed exclusively for authorized forensic investigation, security auditing, and controlled incident response research.

The advanced analysis components focus solely on identifying, extracting, and correlating forensic indicators from collected telemetry. **JOCKY does not provide operational mechanisms or instructions for offensive techniques**, including:

- Process injection or process hollowing
- Reflective DLL injection
- API unhooking
- Direct syscall evasion
- Kernel exploitation
- Vulnerable-driver exploitation (BYOVD)
- EDR/AV security bypass
- Covert command-and-control (C2) channels
- Arbitrary remote shell execution
- Exploit payload or shellcode generation

All collection routines operate in strict read-only mode using standard operating system APIs and require explicit operator initiation.

---

## Technology Stack

- **Language**: Python 3.10+
- **Backend API**: FastAPI, Pydantic, Uvicorn, HTTPX
- **Telemetry Instrumentation**: psutil, native platform interfaces
- **Evidence Storage**: File-backed Tamper-Evident JSON Store & Manifest Bundles
- **Cryptography**: SHA-256 (`hashlib`), PBKDF2 (`hashlib`)
- **Threat Taxonomy**: MITRE ATT&CK Framework
- **Frontend Dashboard**: React 18, Vite
- **Testing**: pytest

---

## Project Status

- **DSL Engine**: Lexer, AST parser, semantic validator, and IR v1.0 compiler fully operational.
- **Execution & Policy**: Read-only IR execution engine with resource limits and path sandboxing active.
- **Telemetry Collectors**: Standardized cross-platform telemetry collectors implemented for Windows, Linux, and macOS.
- **Endpoint Agent**: Cryptographic pairing, heartbeat streaming, job polling, and server-side verification operational.
- **Evidence Vault**: Cryptographic SHA-256 sealing, chain-of-custody logging, and tamper detection validated.
- **Analytics & Mapping**: Entity correlation, chronological event timeline, and MITRE ATT&CK technique mapping functioning.
- **Reporting & Dashboard**: Multi-format report builder (JSON/HTML/MD) and React 18 investigative dashboard active.
- **Verification**: 359/359 automated tests passing; production frontend build verified.

---

## License

This project is developed for educational and authorized forensic research purposes in connection with the Smart India Hackathon (SIH) 2026. No formal open-source license is currently specified.
