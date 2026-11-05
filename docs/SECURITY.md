# Access Control, Signed Jobs and Multi-Endpoint Cases

## Sign-in and roles

Everything under `/api/jocky/` and `/api/forensics/` needs a session token from `POST /api/auth/login`,
sent as `Authorization: Bearer <token>`. `/api/health`, `/api/status`, `/api/auth/*` and the docs stay open.

| Level | Job titles | Can |
|---|---|---|
| viewer | Digital Evidence Auditor | Read results, compile and validate scripts, list and verify evidence, download reports |
| investigator | Lead Forensic Examiner, Incident Responder | Everything above, plus collect, execute scripts, run detections, seal evidence, live correlation, report generation, dispatch endpoint jobs |
| admin | SOC Incident Commander | Everything, including the tamper-simulation demo and creating admin accounts |

- A missing or invalid token gets `401 AuthenticationRequired`. A role that is too low gets
  `403 InsufficientRole` with the level it needed, and the denial is written to the audit chain.
- Self-registration can create viewer or investigator accounts. An admin account can only be created by
  someone already signed in as admin.
- The frontend sends the token with every request and download, and returns to the sign-in screen when the
  server answers 401 (for example after a backend restart, since sessions live in memory).
- `JOCKY_AUTH_DISABLED=1` turns enforcement off. Only the older API tests use it. Never set it on a real
  deployment.

Demo accounts (change them with the `JOCKY_DEMO_*` / `JOCKY_ADMIN_*` environment variables):

| Account | Password | Level |
|---|---|---|
| `investigator@jocky.local` | `jocky-forensics-2026` | investigator |
| `admin@jocky.local` | `admin-forensics-2026` | admin |

## Signed endpoint jobs

The server signs every job it queues with an Ed25519 key. It also adds an `expires_at` (job timeout plus
five minutes) and a random single-use `nonce`. Agents receive the server's public key when they pair.

Before running anything, the agent checks that:

1. the signature matches every other field of the job,
2. the job is addressed to this device,
3. it has not expired, and
4. its nonce has not been used before.

A job that fails any check is logged and skipped. The key is asymmetric, so even a stolen device token
cannot forge jobs, and an intercepted job cannot be replayed.

| Variable | Effect |
|---|---|
| `JOCKY_JOB_SIGNING_KEY` | Base64 of a 32-byte Ed25519 seed |
| *(unset)* | A key is generated once in `data/job-signing.key` (git-ignored) |

Agents paired before signing existed have no public key. They keep working with a warning until they are
re-paired.

## One case across many endpoints

```bash
# queue signed jobs on several paired devices at once
curl -X POST http://localhost:8000/api/agents/cases/CASE-2026-07/dispatch \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"device_ids": ["DEV-1A2B3C4D5E6F", "DEV-0F9E8D7C6B5A"], "collectors": ["system", "services", "dns"]}'

# per-endpoint progress
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/agents/cases/CASE-2026-07
```

Each endpoint is reported as `queued`, `running` (job picked up), `receiving`, `completed`, `partial` or
`expired`, with the collectors received and still missing. Devices that are unknown, revoked or belong to
another investigator are listed under `rejected`, and the rest of the case still goes out. Timings are in
`docs/EVALUATION.md` (E6).

## Related controls

- Evidence encryption at rest and the hash-chained audit log: `docs/DETECTION.md`
- Every collector is read-only. The language has no way to express shell commands, and the runtime policy
  re-checks each operation's capability before running it: `docs/LANGUAGE.md`
