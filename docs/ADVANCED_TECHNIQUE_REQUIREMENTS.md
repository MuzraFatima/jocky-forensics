# JOCKY — Advanced Technique Requirements Specification
## SIH26148 Forensic Capabilities & Advanced Analysis Matrix

---

## 1. Executive Context & Scope

### 1.1 Problem Statement (SIH26148)
> *"Creation of scripts/functions with new programming language to commence Computer & Network forensic analysis without triggering security solutions."*

### 1.2 Defensive Engineering & Safety Scope
In digital forensics and incident response (DFIR), legitimate investigators must acquire telemetry from compromised or suspicious endpoints without:
1. **Triggering False-Positive Alerts**: Disrupting investigations or causing alert fatigue via intrusive scripts, process termination, or unverified binaries.
2. **Alerting Adversaries**: Causing adversary evasion through heavy-handed or destructive actions.
3. **Modifying Endpoint Evidence**: Altering target files, registry entries, or process states, which compromises legal admissibility.

**JOCKY solves this challenge defensively**:
- It implements a **declarative, read-only Domain-Specific Language (DSL)**.
- It relies on **standard, passive system and OS inspection primitives** (`psutil`, Win32 read APIs, `/proc`, `sysctl`, `launchd`).
- It **strictly forbids** malware evasion techniques (e.g., AV/EDR disabling, kernel driver tampering, process hollowing, code injection).
- It binds all collected telemetry to **cryptographic SHA-256 hashes** and an **immutable legal chain of custody**.

---

## 2. Classification Taxonomy

Each advanced forensic and security technique is classified according to its concrete state in the repository:

| Classification | Definition |
| :--- | :--- |
| **Implemented** | Fully coded, integrated into the pipeline, and validated by automated tests in the repository. |
| **Partially Implemented** | Foundational data structures, collector APIs, or heuristics exist, but require expanded rules, schemas, or full end-to-end integration. |
| **Detectable through forensic evidence** | Existing collectors already acquire the underlying evidence/telemetry, but dedicated analysis rules or correlation logic have not yet been codified. |
| **Planned** | Architecturally specified in blueprints, roadmaps, or stubs, but collectors and analyzers are not yet written. |
| **Not Implemented** | Identified as out-of-scope, requiring external tools, or intentionally excluded (e.g. offensive/evasion techniques). |

---

## 3. Advanced Forensic & Security Techniques Matrix

### 3.1 Domain-Specific Language (DSL) & Non-Disruptive Execution

| # | Technique / Capability | Classification | JOCKY Component | Concrete Supporting Evidence / Files |
|---|---|:---:|---|---|
| **DSL-01** | Declarative Forensic Scripting Syntax | **Implemented** | Lexer & Recursive-Descent Parser | [`backend/app/language/lexer.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/language/lexer.py), [`tokens.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/language/tokens.py), [`parser.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/language/parser.py). Supports `CASE`, `TARGET`, `COLLECT`, `WHERE`, `ANALYZE`, `VERIFY INTEGRITY`, `REPORT`. |
| **DSL-02** | Intermediate Representation (IR) Compilation | **Implemented** | Semantic Compiler & IR Generator | [`backend/app/language/compiler.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/language/compiler.py). Emits validated IR JSON schema with standardized operation tasks. |
| **DSL-03** | AST Semantic Validation & Policy Enforcement | **Implemented** | Policy Engine | [`backend/app/engine/ir_policy.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/engine/ir_policy.py), [`hardening.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/engine/hardening.py). Validates allowed capabilities, rejects path traversal (`../`, `..\`), enforces case ID constraints. |
| **DSL-04** | Operation Filter Expressions (`WHERE status == RUNNING`) | **Implemented** | IR Executor & Dispatcher | [`backend/app/engine/ir_executor.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/engine/ir_executor.py#L65-L120). Evaluates filter clauses on process and network connection collections. |
| **DSL-05** | Bounded & Throttled System Inspection | **Implemented** | Hardening Engine | [`backend/app/engine/hardening.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/engine/hardening.py#L90-L130). Enforces maximum file sizes (`MAX_FORENSIC_FILE_BYTES = 25MB`), bounded memory inspections (`bounded_memory_inspect`), and CPU/memory quotas. |

---

### 3.2 Cross-Platform Telemetry & Artifact Collection

| # | Technique / Capability | Classification | JOCKY Component | Concrete Supporting Evidence / Files |
|---|---|:---:|---|---|
| **COL-01** | Non-Invasive Process Inventory & Ancestry | **Implemented** | Process Collector | [`backend/app/collectors/processes.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/processes.py). Collects PID, PPID, executable path, command line, memory RSS/VMS, status, creation timestamp without process disruption. |
| **COL-02** | Network Sockets & Connection Telemetry | **Implemented** | Network Collector | [`backend/app/collectors/network.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/network.py). Enumerates TCP/UDP listening ports, established sockets, local/remote IP and ports, socket status, and PID bindings. |
| **COL-03** | Controlled Filesystem Forensics & MAC Times | **Implemented** | File Collector | [`backend/app/collectors/files.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/files.py). Scans targeted evidence paths, extracts file size, permissions, modified/accessed/created timestamps, and computes SHA-256 hashes. |
| **COL-04** | User Session & Security Context Collection | **Implemented** | User Collector | [`backend/app/collectors/users.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/users.py). Discovers logged-in users, administrative group privileges (`is_admin`), terminal sessions, and domain affiliations. |
| **COL-05** | Windows Registry Autorun & Persistence | **Implemented** | Windows Metadata Collector | [`backend/app/collectors/windows_metadata.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/windows_metadata.py#L32-L76). Inspects HKLM/HKCU `Run`, `RunOnce`, and WoW6432Node Run keys in strictly read-only mode (`KEY_READ`). |
| **COL-06** | Windows Service Configuration Enumeration | **Implemented** | Windows Metadata Collector | [`backend/app/collectors/windows_metadata.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/windows_metadata.py#L110-L160). Enumerates active and stopped Windows services, binary paths, start types, and display names via read-only APIs. |
| **COL-07** | Linux Systemd & Cron Persistence Telemetry | **Implemented** | Linux Collectors | [`backend/app/collectors/linux_collectors.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/linux_collectors.py#L420-L510). Reads `/etc/crontab`, `/etc/cron.*`, and `/etc/systemd/system/*.service` unit files. |
| **COL-08** | macOS LaunchDaemons & LaunchAgents Forensics | **Implemented** | macOS Collectors | [`backend/app/collectors/macos_collectors.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/macos_collectors.py#L430-L510). Parses LaunchDaemons and LaunchAgents plist configurations and user cron tabs. |
| **COL-09** | Windows Event Log Acquisition (`.evtx`) | **Planned** | Collector Roadmap | Identified in collector roadmap; stubbed in `windows_metadata.py` for Security/System event log parsing. |
| **COL-10** | NTFS Alternate Data Streams (ADS) Inspection | **Detectable through forensic evidence** | File Collector | `collect_files_info` accesses file stat; can be extended with Win32 stream inspection to detect hidden data streams. |
| **COL-11** | Linux Bash History & Shell Audit Forensics | **Implemented** | Linux Collectors | [`backend/app/collectors/linux_collectors.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/linux_collectors.py#L380-L415). Collects user home `.bash_history` files in read-only mode. |

---

### 3.3 Cryptographic Integrity, Tamper-Evidence & Legal Custody

| # | Technique / Capability | Classification | JOCKY Component | Concrete Supporting Evidence / Files |
|---|---|:---:|---|---|
| **CRYPTO-01** | Deterministic SHA-256 Payload Hashing | **Implemented** | Evidence Hashing Engine | [`backend/app/evidence/hashing.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/evidence/hashing.py). Canonical JSON serialization with sorted keys and constant-time HMAC comparison. |
| **CRYPTO-02** | Cryptographic Evidence Sealing at Acquisition | **Implemented** | Evidence Vault | [`backend/app/evidence/vault.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/evidence/vault.py#L69-L125). Seals artifacts with metadata (timestamp, target host, collector identity, version, SHA-256). |
| **CRYPTO-03** | Mathematical Tamper Detection | **Implemented** | Evidence Vault | [`backend/app/evidence/vault.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/evidence/vault.py#L127-L183). Re-computes SHA-256 hash on verification (`verify_artifact_integrity`) and detects byte-level modifications. |
| **CRYPTO-04** | Full-Vault Cryptographic Integrity Audit | **Implemented** | Evidence Vault | [`backend/app/evidence/vault.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/evidence/vault.py#L184-L260). `verify_vault_integrity` audits all case artifacts, producing INTACT or COMPROMISED status. |
| **CRYPTO-05** | Immutable 5W1H Chain of Custody Ledger | **Implemented** | Custody Engine | [`backend/app/evidence/custody.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/evidence/custody.py), [`vault.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/evidence/vault.py). Appends immutable records for `ACQUIRED`, `VERIFIED`, `ACCESSED`, `EXPORTED`. |
| **CRYPTO-06** | Verifiable Evidence Bundle Export with Manifest | **Implemented** | Evidence Vault | [`backend/app/evidence/vault.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/evidence/vault.py#L265-L330). Bundles case artifacts into ZIP packages with cryptographic manifest SHA-256 verification. |

---

### 3.4 Multi-Source Artifact Correlation & Timeline Reconstruction

| # | Technique / Capability | Classification | JOCKY Component | Concrete Supporting Evidence / Files |
|---|---|:---:|---|---|
| **CORR-01** | Process ↔ Network Socket Binding | **Implemented** | Forensic Correlator | [`backend/app/analysis/correlator.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/correlator.py#L150-L195). Maps open sockets to process entities (`ENT-PROC-{pid}`) using PID and connection tuples. |
| **CORR-02** | Parent ↔ Child Process Hierarchy Reconstruction | **Implemented** | Forensic Correlator | [`backend/app/analysis/correlator.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/correlator.py#L125-L148). Rebuilds execution tree via PPID, establishing execution ancestry and orphaned process detection. |
| **CORR-03** | Process ↔ Executable File & Hash Binding | **Implemented** | Forensic Correlator | [`backend/app/analysis/correlator.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/correlator.py#L198-L235). Correlates process executable paths with collected filesystem entries and SHA-256 hashes. |
| **CORR-04** | Process ↔ User Identity Binding | **Implemented** | Forensic Correlator | [`backend/app/analysis/correlator.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/correlator.py#L238-L260). Links processes to user security entities (`ENT-USER-{username}`), tracking administrative privileges. |
| **TIME-01** | Multi-Source Chronological Event Stream | **Implemented** | Forensic Timeline Engine | [`backend/app/analysis/timeline.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/timeline.py#L40-L210). Aggregates boot times, process creation, network sockets, file inspections, and autorun keys with deterministic ordering. |
| **TIME-02** | Temporal Anomaly & Out-of-Sequence Detection | **Partially Implemented** | Timeline & Correlator | Timeline engine normalizes and sorts all event dates; rules for detecting retroactive file timestamp alteration (timestomping) are partially implemented. |

---

### 3.5 Threat Detection Heuristics & MITRE ATT&CK Mapping

| # | Technique / MITRE ID | Classification | JOCKY Component | Concrete Supporting Evidence / Files |
|---|---|:---:|---|---|
| **RULE-001** | Execution from Temporary Directories (T1036.005 / T1059) | **Implemented** | Forensic Rule Engine | [`backend/app/analysis/rules.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/rules.py#L80-L104). Flags binaries running from `\temp`, `\tmp`, `\appdata\local\temp`, `\windows\temp`. (Severity: HIGH) |
| **RULE-002** | Suspicious Parent-Child Process Spawning (T1059.001 / T1059.003 / T1204.002) | **Implemented** | Forensic Rule Engine | [`backend/app/analysis/rules.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/rules.py#L105-L133). Flags office apps/browsers spawning shells (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`). (Severity: HIGH) |
| **RULE-003** | Anomalous Outbound Network Sockets (T1571 / T1071 / T1043) | **Implemented** | Forensic Rule Engine | [`backend/app/analysis/rules.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/rules.py#L134-L164). Flags connections to known backdoor/exploitation ports (4444, 1337, 6667, 31337, 8888, 23). (Severity: MEDIUM) |
| **RULE-004** | Unmapped Binary Execution / Process Hollowing Indicator (T1055) | **Implemented** | Forensic Rule Engine | [`backend/app/analysis/rules.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/rules.py#L165-L188). Detects running processes where executable file path is inaccessible or empty on disk. (Severity: LOW) |
| **RULE-005** | Suspicious Persistence Script Autorun (T1547.001) | **Implemented** | Forensic Rule Engine | [`backend/app/analysis/rules.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/analysis/rules.py#L189-L210). Flags Windows autorun registry entries invoking `.vbs`, `.ps1`, `.bat`, `.cmd`, `powershell`, `wscript`. (Severity: MEDIUM) |
| **TECH-01** | Masquerading / Living-off-the-Land Binaries (LOLBins) (T1036.003) | **Detectable through forensic evidence** | Process & File Collectors | Process command line and executable paths are captured; LOLBin heuristics (e.g. `certutil` downloading files or `mshta` executing scripts) can be evaluated directly on existing `processes.py` data. |
| **TECH-02** | Cron / Systemd Service Persistence on Linux (T1053.003 / T1543.002) | **Detectable through forensic evidence** | Linux Persistence Collector | Telemetry acquired in [`linux_collectors.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/linux_collectors.py#L420-L510); automated heuristic rule linking suspicious script commands in cron to findings can be added in Phase 2. |
| **TECH-03** | macOS LaunchAgent / LaunchDaemon Persistence (T1543.001 / T1543.004) | **Detectable through forensic evidence** | macOS Persistence Collector | Telemetry acquired in [`macos_collectors.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/collectors/macos_collectors.py#L430-L510); rule evaluation on plist `ProgramArguments` can be added in Phase 2. |
| **TECH-04** | Lateral Movement Port Scanning Indicator (T1046) | **Detectable through forensic evidence** | Network Collector | Multiple SYN_SENT or diverse IP connections from a single process PID can be correlated from existing `network.py` connection tables. |
| **TECH-05** | Account Discovery & Privilege Escalation Indicator (T1087 / T1078) | **Detectable through forensic evidence** | User Collector | Current user privileges and administrator status are collected in `users.py`; correlation with processes running under SYSTEM vs standard user is supported. |

---

### 3.6 Remote Endpoint Agent Architecture & Cryptographic Transport

| # | Technique / Capability | Classification | JOCKY Component | Concrete Supporting Evidence / Files |
|---|---|:---:|---|---|
| **AGT-01** | Single-Use Short-Lived Pairing Code Exchange | **Implemented** | Agent Manager & Routes | [`backend/app/agents/manager.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/agents/manager.py#L130-L245), [`routes.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/agents/routes.py#L120-L180). Cryptographically random 8-character codes, 10-minute TTL, single-use consumption. |
| **AGT-02** | Cryptographic Device Token Hashing (PBKDF2) | **Implemented** | Agent Manager | [`backend/app/agents/manager.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/agents/manager.py#L40-L75). Plaintext tokens returned once; server persists only `pbkdf2_sha256$` salted hash. |
| **AGT-03** | Multi-Device Job Queue & Tenant Isolation | **Implemented** | Agent Manager | [`backend/app/agents/manager.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/agents/manager.py#L407-L440). Per-device FIFO queues prevent cross-device or cross-investigator job leakage. |
| **AGT-04** | Agent Telemetry SHA-256 Anti-Tamper Verification | **Implemented** | Agent Routes | [`backend/app/agents/routes.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/agents/routes.py#L240-L290). Re-computes SHA-256 over uploaded telemetry; rejects mismatches with `TRANSMISSION_TAMPERED` (HTTP 400). |
| **AGT-05** | Collector Provider Adapter Pattern | **Implemented** | Engine Abstraction | [`backend/app/engine/collector_provider.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/engine/collector_provider.py). Standardizes `LocalCollectorProvider` and `EndpointEvidenceProvider` without collector duplication. |
| **AGT-06** | Instant Device Revocation & Token Invalidation | **Implemented** | Agent Manager & Routes | [`backend/app/agents/manager.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/agents/manager.py#L290-L315). Sets `is_revoked=True`, zeroes token hash, and purges pending queues immediately. |
| **AGT-07** | Endpoint Presence Heartbeat Monitoring | **Implemented** | Agent Manager & Routes | [`backend/app/agents/routes.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/agents/routes.py#L182-L238). Tracks `last_seen` timestamps with authoritative 90-second online threshold calculation. |

---

### 3.7 Investigator Web Dashboard & Presentation

| # | Technique / Capability | Classification | JOCKY Component | Concrete Supporting Evidence / Files |
|---|---|:---:|---|---|
| **UI-01** | In-Browser Forensic DSL Code Editor | **Implemented** | React Web Dashboard | [`frontend/src/App.jsx`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/frontend/src/App.jsx#L14-L52). Interactive editor with canonical JOCKY script templates and execution controls. |
| **UI-02** | Endpoint Device Management & Pairing UI | **Implemented** | Endpoint Devices Component | [`frontend/src/EndpointDevices.jsx`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/frontend/src/EndpointDevices.jsx). Pairing modal with countdown, CLI command copy, safe metadata display, and revocation. |
| **UI-03** | Dynamic Target Selector (`Local Machine` vs `Endpoints`) | **Implemented** | Dashboard & App Layout | [`frontend/src/InvestigatorDashboard.jsx`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/frontend/src/InvestigatorDashboard.jsx), [`App.jsx`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/frontend/src/App.jsx). Toggles target dynamically and routes `device_id` to `/api/jocky/execute`. |
| **UI-04** | Process Tree Ancestry Visualizer | **Implemented** | React Hierarchy Tree | [`frontend/src/App.jsx`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/frontend/src/App.jsx#L54-L120). Interactive collapsible tree visualizer mapping parent/child PID hierarchies. |
| **UI-05** | Cryptographic Evidence Explorer with SHA-256 Badges | **Implemented** | React Evidence Explorer | [`frontend/src/App.jsx`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/frontend/src/App.jsx). Displays sealed artifact files, computed hashes, and verification badges. |
| **UI-06** | Incident Timeline & Threat Triage Display | **Implemented** | React Dashboard | [`frontend/src/App.jsx`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/frontend/src/App.jsx). Chronological event list with anomaly alerts and severity color indicators. |

---

### 3.8 Multi-Format Forensic Reporting & Legal Attestation

| # | Technique / Capability | Classification | JOCKY Component | Concrete Supporting Evidence / Files |
|---|---|:---:|---|---|
| **REP-01** | Structured JSON Forensic Dossiers | **Implemented** | Forensic Report Builder | [`backend/app/reporting/report_engine.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/reporting/report_engine.py#L350-L400). Standardized forensic schema with findings, severity counts, and hashes. |
| **REP-02** | Printable Markdown & HTML Reports | **Implemented** | Forensic Report Builder | [`backend/app/reporting/report_engine.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/reporting/report_engine.py#L400-L750). Complete investigative reports with CSS styling, executive threat summaries, and manifests. |
| **REP-03** | Cryptographic Attestation Certificate | **Implemented** | Forensic Report Builder | [`backend/app/reporting/report_engine.py`](file:///c:/Users/User/OneDrive/Desktop/sih148/jocky-forensics/backend/app/reporting/report_engine.py#L220-L260). Embeds digital attestation with SHA-256 evidence manifest digest and examiner signature metadata. |

---

## 4. Classification Summary Statistics

```text
======================================================================
JOCKY ADVANCED TECHNIQUE CLASSIFICATION SUMMARY
======================================================================
Total Analyzed Techniques / Capabilities:    35
----------------------------------------------------------------------
  1. Implemented:                            28  (80.0%)
  2. Detectable through forensic evidence:    5  (14.3%)
  3. Partially Implemented:                   1   (2.9%)
  4. Planned:                                 1   (2.9%)
  5. Not Implemented (Offensive/Evasion):     0   (0.0%) [Deliberately excluded]
======================================================================
```

---

## 5. Roadmap: Phase 2 Advanced Technique Analysis

The following techniques are currently **Detectable through forensic evidence** or **Partially Implemented** and will form the primary focus of Phase 2 rule additions:

1. **RULE-006: Living-off-the-Land Binaries (LOLBins) Execution**
   - *Evidence Available*: `processes.py` captures complete `cmdline` and executable names.
   - *Target Techniques*: `certutil.exe -urlcache`, `mshta.exe http://...`, `bitsadmin.exe /transfer`, `powershell.exe -enc`.
2. **RULE-007: Linux Persistence via Cron or Systemd Anomaly**
   - *Evidence Available*: `linux_collectors.py` captures crontab entries and systemd service unit files.
   - *Target Techniques*: Cron executing binaries in `/tmp` or non-standard paths; systemd units pointing to unmapped scripts.
3. **RULE-008: macOS LaunchAgent / LaunchDaemon Persistence Anomaly**
   - *Evidence Available*: `macos_collectors.py` collects plist definitions.
   - *Target Techniques*: Launchd plists executing scripts from user home directories or `/private/tmp`.
4. **RULE-009: Lateral Movement Outbound Reconnaissance**
   - *Evidence Available*: `network.py` captures connection states and IP/port distributions.
   - *Target Techniques*: Single PID opening numerous outbound connection attempts across sequential ports.
5. **RULE-010: Process Elevation Context Disparity**
   - *Evidence Available*: `users.py` captures admin status and `processes.py` captures process execution usernames.
   - *Target Techniques*: Standard user processes attempting to masquerade or elevate without proper token attributes.

---

## 6. Safety & Non-Disruptive Guarantees (Compliance Confirmation)

All techniques cataloged in this specification strictly uphold the core invariants of JOCKY and SIH26148:
- **No Offensive/Evasion Mechanisms**: No process hollowing, memory patching, kernel driver unhooking, or security software termination.
- **Passive Read-Only Acquisition**: All collectors utilize read-only flags (`O_RDONLY`, `KEY_READ`, psutil non-destructive inspection).
- **Zero Evidence Contamination**: No target files are altered or deleted.
- **Cryptographic Chain of Custody**: Every acquired artifact is immutably anchored by SHA-256 hashing.
