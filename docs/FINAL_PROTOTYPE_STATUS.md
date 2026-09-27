# JOCKY Final Prototype Status

**Project**: SIH 2026 — Problem Statement SIH26148  
**Prototype Version**: 1.0 (Frozen)  
**Freeze Date**: 2026-09-27  
**Status**: ? COMPLETE — FROZEN  

---

## Architecture Overview

```
Frontend (React/Vite)
    ?  REST API
Backend (FastAPI + Python)
    +-- JOCKY DSL Engine  (parser / IR executor)
    +-- Collectors         (system, process, network, file, user, persistence)
    +-- Evidence Vault     (SHA-256 tamper detection, chain of custody)
    +-- Analysis Engine    (correlation, timeline, MITRE, advanced techniques)
    +-- Reporting Engine   (Markdown + HTML forensic reports)
    +-- Endpoint Agent     (standalone binary, device pairing, heartbeat, jobs)
```

---

## Implementation Phases — All Complete

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | JOCKY DSL + IR Executor | ? Complete |
| 2 | Collectors (system, process, network, file, user, persistence) | ? Complete |
| 3 | Evidence Vault + SHA-256 Integrity | ? Complete |
| 4 | Correlation Engine + Timeline + MITRE Mapping | ? Complete |
| 5 | Forensic Reporting (Markdown + HTML) | ? Complete |
| 6 | Endpoint Device Management (pairing, heartbeat, jobs, revocation) | ? Complete |
| 7 | Frontend Endpoint Device Management UI | ? Complete |
| 8 | Final Validation & Regression Testing | ? Complete |
| AT-1 | Advanced Technique Requirements Analysis | ? Complete |
| AT-2 | Advanced Technique Registry (40 techniques) | ? Complete |
| AT-3 | Evidence/Indicator Mapping | ? Complete |
| AT-4 | Safe Advanced Technique Analysis Modules | ? Complete |
| AT-5 | Correlation + Timeline + MITRE Integration | ? Complete |
| AT-6 | Frontend + Forensic Report Integration | ? Complete |
| AT-7 | Final Validation & Freeze | ? Complete |

---

## Security Invariants (Preserved Throughout)

The following capabilities are NOT implemented and must never be added:
- Process injection
- Reflective DLL injection
- Process hollowing (execution mechanism)
- API unhooking / direct syscalls
- Kernel exploitation / vulnerable-driver exploitation
- EDR/AV bypass
- Covert C2 channels
- Arbitrary shell execution
- Payload generation

JOCKY is a forensic analysis system only — it detects and analyzes observable indicators.

---

## Full Data Flow (Evidence Traceability)

```
JOCKY Script / API Trigger
    ? IR Executor
    ? Collectors (system/process/network/file/user/persistence)
    ? Evidence Vault  [SHA-256 hash, timestamp, device_id, case_id]
    ? Advanced Technique Analyzer  [Evidence ? Indicator ? Technique ? Finding]
    ? Correlation Engine
    ? Timeline Engine
    ? MITRE Engine  [ATT&CK tactic/technique mapping]
    ? Report Engine  [Markdown + HTML forensic report]
    ? Frontend  [Dashboard / Advanced Techniques tab / Report viewer]
```

Every finding is traceable back to its source evidence artifact in the Evidence Vault.

---

## Key Backend Files

- backend/app/main.py — FastAPI entry point
- backend/app/engine/jocky_parser.py — JOCKY DSL parser
- backend/app/engine/ir_executor.py — IR execution + API endpoints
- backend/app/collectors/ — System/process/network/file/user/persistence
- backend/app/vault/evidence_vault.py — SHA-256 evidence storage + audit
- backend/app/analysis/correlation_engine.py — Event correlation
- backend/app/analysis/timeline_engine.py — Forensic timeline
- backend/app/analysis/mitre_engine.py — MITRE ATT&CK mapping
- backend/app/analysis/technique_analyzer.py — Indicator detection
- backend/app/analysis/evidence_indicator_mapper.py — Evidence ? Indicator ? Technique
- backend/app/agents/ — Endpoint Device Management (models, manager, routes)
- backend/app/reporting/report_engine.py — Markdown + HTML forensic reports
- backend/app/registry/technique_registry.py — 40-technique registry
- backend/endpoint_agent/agent.py — Standalone endpoint agent

## Key Frontend Files

- frontend/src/App.jsx — Main application, state, tab routing
- frontend/src/Sidebar.jsx — Navigation sidebar with counts/badges
- frontend/src/InvestigatorDashboard.jsx — Overview & analysis dashboard
- frontend/src/EndpointDevices.jsx — Endpoint Device Management UI
- frontend/src/AdvancedTechniques.jsx — Advanced Technique Analysis UI
- frontend/src/ReportSection.jsx — Forensic report display
- frontend/src/api.js — Typed API client

---

## Advanced Technique Registry Summary

40 techniques across 8 categories:
- Process Manipulation (5)
- Network Evasion (5)
- Defense Evasion (5)
- Persistence (5)
- Privilege Escalation (5)
- Credential Access (5)
- Lateral Movement (5)
- Memory Forensics (5)

---

## Endpoint Agent Capabilities

- Device Pairing: time-limited (10 min), single-use codes
- Heartbeat: 30-second keep-alive, online/offline tracking
- Job Dispatch: remote forensic collection jobs
- Result Ingestion: endpoint evidence into local Evidence Vault
- Device Revocation: immediate with rejection of further requests
- Multi-device Isolation: per-device evidence namespace

---

## JOCKY IS NOW FROZEN AS THE FINAL PROTOTYPE.
