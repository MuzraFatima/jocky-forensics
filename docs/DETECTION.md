# Detection, Evidence Integrity and Audit

## Detection rules

Rules are JSON files in `backend/app/detection/rules/`. The engine is deterministic and read-only. It
evaluates evidence that was already collected and never touches the host.

| Rule | Source | Looks for | ATT&CK | Severity / confidence |
|---|---|---|---|---|
| JKY-DET-001 | services | Service executable in a temp or user-writable folder | T1543, T1543.002, T1543.003 | high / medium |
| JKY-DET-002 | startup | Startup entry that downloads, decodes or runs from temp | T1547.001, T1053.003, T1105 | high / medium |
| JKY-DET-003 | drivers | Unsigned or out-of-tree Linux kernel module | T1547.006, T1014 | high / medium |
| JKY-DET-004 | drivers | Windows driver registered outside System32\drivers / DriverStore | T1543.003, T1068 | medium / low |
| JKY-DET-005 | listening_ports | Listener on a backdoor or C2 default port | T1571, T1219 | high / medium |
| JKY-DET-006 | dns | Hosts file sends a vendor, update or security domain to a routable IP | T1565.001, T1562 | high / high |
| JKY-DET-007 | processes | Process executing from a temp or public folder | T1204.002, T1036 | medium / medium |
| JKY-DET-008 | processes | Office document, PDF reader or mail client started a shell | T1059, T1566.001 | high / high |

Run them from a script:

```jocky
investigation "Persistence_Sweep" {
    target "lab-ubuntu"
    collect services
    collect startup
    collect drivers
    collect listening_ports
    collect dns
    analyze detections
    verify integrity
    report format html
}
```

Or from the API:

```bash
curl http://localhost:8000/api/forensics/detections/rules
curl -X POST http://localhost:8000/api/forensics/detect -H "Content-Type: application/json" \
     -d '{"sources": ["services", "startup", "dns"]}'
```

### What a finding contains

- `rule_id`, `title`, `severity`, `confidence` and `attack` (technique ids and names)
- `matched_because`: which field satisfied which condition, for example
  `executable='/dev/shm/upd' contains '/dev/shm/'`
- `record`: the collected record that matched, and `evidence_id`, the sealed artifact it came from
- `benign_explanations`: what an analyst should rule out before acting

### Correlation (blueprint §7.4)

Findings from different sources on the same endpoint are combined. A single source keeps its rule
severity. Two independent sources raise the priority one step, and three or more raise it two. The
summary explains why the combination matters and lists every technique and benign explanation
involved. The verdict is always `analyst review recommended`. JOCKY never declares a host compromised.

### Writing a rule

```json
{
  "id": "JKY-DET-009",
  "title": "Short statement of what was seen",
  "description": "Why this matters to an investigator",
  "source": "services",
  "condition": {"all": [
    {"field": "executable", "op": "contains_any", "values": ["/tmp/"]},
    {"not": {"field": "name", "op": "equals", "value": "known-good.service"}}
  ]},
  "severity": "high",
  "confidence": "medium",
  "attack": [{"id": "T1543.002", "name": "Systemd Service"}],
  "benign_explanations": ["At least one legitimate reason this can happen"]
}
```

Operators: `equals`, `in`, `contains_any`, `not_contains_any`, `startswith_any`, `regex`, `is_true`,
`present`, `gte`, combined with `all`, `any` and `not`. String matching is case-insensitive and treats `\`
and `/` the same, so one rule covers Windows and Linux paths. Rules are validated when loaded. An unknown
source, operator, severity, missing ATT&CK id or missing benign explanation is rejected.

### Measured quality

`docs/EVALUATION.md` (experiment E4) reports precision, recall, F1 and false-positive rate on 59
hand-labelled records, and lists every false positive and false negative. A test keeps those numbers from
regressing.

## Evidence encryption at rest

Set one of these before starting the backend:

| Variable | Effect |
|---|---|
| `JOCKY_EVIDENCE_KEY` | Base64 of 32 random bytes. Generate one with `python -c "import base64,secrets;print(base64.b64encode(secrets.token_bytes(32)).decode())"` |
| `JOCKY_ENCRYPT_EVIDENCE=1` | Generate a key once in `data/evidence.key` (git-ignored) |

Records are then stored as AES-256-GCM envelopes with the evidence ID as associated data. Editing the
ciphertext, copying it onto another ID or using the wrong key is reported as tampering. Records written
before encryption was enabled remain readable. Back up the key: without it the evidence cannot be read.

Without a key, each record still carries a SHA-256 of its payload. Experiment E5 shows what that does and
does not catch.

## Tamper-evident audit log

Every audit entry has a sequence number, the previous entry's hash and its own SHA-256. Entries are
appended to `data/audit-log.jsonl` (git-ignored; override with `JOCKY_AUDIT_LOG=<path>` or disable with
`JOCKY_AUDIT_LOG=off`). After a restart the chain continues from the last entry in that file.

```bash
curl http://localhost:8000/api/security/audit/verify
# {"success": true, "valid": true, "checked": 42, "first_bad_seq": null, "reason": "chain intact", ...}
```

An edited, deleted or reordered entry makes `valid` false and names the first sequence number that no
longer matches.
