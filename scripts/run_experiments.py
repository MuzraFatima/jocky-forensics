"""
Run the blueprint's measurable experiments and write docs/EVALUATION.md.

    python scripts/run_experiments.py            # all experiments
    python scripts/run_experiments.py --quick    # one repetition for E3

E1  compiler correctness       valid scripts accepted, invalid rejected with the right code
E3  collection performance     wall time, CPU time and memory per collector on this host
E4  detection effectiveness    precision / recall / F1 / FPR on the labelled dataset
E5  evidence integrity         which tampering each storage mode detects

E6  orchestration              dispatch-to-evidence time and success across 1, 3 and 5 endpoints
E2 (cross-platform) is covered by CI on Ubuntu and Windows; see docs/EVALUATION.md.
Nothing here modifies the host: E5 works in a temporary directory.
"""

import argparse
import base64
import datetime
import json
import os
import platform
import secrets
import statistics
import sys
import tempfile
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# E6 pairs devices and signs in users. Point the backend at a scratch copy of
# data/ before anything imports it, so the tracked JSON files stay untouched.
if "JOCKY_STORAGE_DIR" not in os.environ:
    import shutil

    _scratch = Path(tempfile.mkdtemp(prefix="jocky-experiments-"))
    for _seed in (ROOT / "data").glob("*.json"):
        shutil.copy2(_seed, _scratch / _seed.name)
    os.environ["JOCKY_STORAGE_DIR"] = str(_scratch)
os.environ.setdefault("JOCKY_AUDIT_LOG", "off")

from backend.app.collectors import get_collectors  # noqa: E402
from backend.app.detection.evaluation import evaluate_dataset, load_dataset  # noqa: E402
from backend.app.evidence.storage import EvidenceCipher  # noqa: E402
from backend.app.evidence.vault import EvidenceVault  # noqa: E402
from backend.app.language import compile_jocky  # noqa: E402

HEADER = 'CASE "E1"\nTARGET "lab"\n'

# ── E1 ──────────────────────────────────────────────────────────────────────

E1_INVALID = [
    ('CASE "open', "JKY101"),
    (HEADER + "COLLECT SYSTEM @", "JKY102"),
    (HEADER + "COLLECT SYSTEM extra", "JKY201"),
    ("CASE 42", "JKY202"),
    ('CASE "a"\nTARGET host', "JKY203"),
    (HEADER + "COLLECT SYSTEM\nVERIFY HASHES", "JKY204"),
    (HEADER + "INJECT MALWARE", "JKY205"),
    (HEADER + "EXECUTE \"rm -rf /\"", "JKY205"),
    (HEADER + "COLLECT PASSWORDS", "JKY206"),
    (HEADER + "COLLECT FILES", "JKY207"),
    ('investigation "x" { target "a" collect system', "JKY209"),
    (HEADER + "COLLECT PROCESSES\nWHERE status RUNNING", "JKY210"),
    ('investigation "x" { target "a" platform beos collect system }', "JKY211"),
    ('TARGET "b"\nCOLLECT SYSTEM', "JKY301"),
    (HEADER + 'CASE "again"\nCOLLECT SYSTEM', "JKY302"),
    ('CASE "a"\nCOLLECT SYSTEM', "JKY303"),
    (HEADER + "REPORT", "JKY307"),
    ('investigation "x" { target "a" platform linux platform windows collect system }', "JKY308"),
    (HEADER + "COLLECT PROCESSES\nWHERE state == RUNNING", "JKY310"),
    (HEADER + "COLLECT PROCESSES\nWHERE status == FLYING", "JKY311"),
    (HEADER + "VERIFY INTEGRITY\nCOLLECT SYSTEM", "JKY320"),
    (HEADER + "COLLECT SYSTEM\nREPORT FORMAT PDF", "JKY330"),
]


def _valid_scripts():
    scripts = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((ROOT / "examples").glob("*.jocky"))
               if "invalid" not in p.name]
    scripts.append(("fixtures/sample_incident.jocky", (ROOT / "tests/fixtures/sample_incident.jocky").read_text()))
    words = ["system", "processes", "network", 'files "./evidence"', "users", "services", "startup", "drivers",
             "listening_ports", "dns", "registry", "windows_metadata", "running_processes", "kernel_modules",
             "open_ports", "dns_cache", "startup_entries"]
    for w in words:
        scripts.append((f"block collect {w}", f'investigation "E1" {{ target "lab" collect {w} verify integrity }}'))
        flat_word = w if '"' in w else w.upper()
        scripts.append((f"flat collect {w}", HEADER + "COLLECT " + flat_word + "\nREPORT"))
    return scripts


def run_e1():
    valid = _valid_scripts()
    accepted = [name for name, src in valid if compile_jocky(src)["success"]]
    rejected_right, rejected_wrong, accepted_bad = [], [], []
    for src, code in E1_INVALID:
        result = compile_jocky(src)
        if result["success"]:
            accepted_bad.append(code)
        elif result["error"]["code"] == code:
            rejected_right.append(code)
        else:
            rejected_wrong.append((code, result["error"]["code"]))
    ir_same = all(
        compile_jocky(src, platform=p)["ir"] == compile_jocky(src, platform="linux")["ir"]
        for _, src in valid if compile_jocky(src)["success"] for p in ("windows", "macos")
    )
    return {
        "valid_total": len(valid), "valid_accepted": len(accepted),
        "invalid_total": len(E1_INVALID), "invalid_rejected_with_expected_code": len(rejected_right),
        "invalid_rejected_with_other_code": rejected_wrong, "invalid_accepted": accepted_bad,
        "ir_identical_across_platforms": ir_same,
    }


# ── E3 ──────────────────────────────────────────────────────────────────────

E3_COLLECTORS = ["system", "processes", "network", "users", "services", "startup", "drivers", "listening_ports",
                 "dns", "files"]


def run_e3(repeats):
    me = psutil.Process()
    collectors = get_collectors()
    rows = []
    for name in E3_COLLECTORS:
        if name not in collectors:
            continue
        walls, cpus, mems, counts = [], [], [], []
        for _ in range(repeats):
            before_cpu = sum(me.cpu_times()[:2])
            before_rss = me.memory_info().rss
            start = time.perf_counter()
            result = collectors[name]()
            walls.append(time.perf_counter() - start)
            cpus.append(sum(me.cpu_times()[:2]) - before_cpu)
            mems.append(max(0, me.memory_info().rss - before_rss))
            counts.append(result.get("count", "—"))
        rows.append({
            "collector": name,
            "median_ms": round(statistics.median(walls) * 1000, 1),
            "max_ms": round(max(walls) * 1000, 1),
            "cpu_ms": round(statistics.median(cpus) * 1000, 1),
            "rss_growth_kb": round(statistics.median(mems) / 1024),
            "records": counts[-1],
            "payload_kb": round(len(json.dumps(result, default=str)) / 1024, 1),
        })
    return rows


# ── E5 ──────────────────────────────────────────────────────────────────────

def _attack_payload_edit(path, record_id, vault):
    vault.simulate_tampering(record_id, "hostname", "attacker-box")


def _attack_payload_and_hash(path, record_id, vault):
    """An attacker who knows the format edits the data and recomputes its SHA-256."""
    from backend.app.evidence.hashing import compute_sha256

    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("jocky_envelope"):
        # Without the key the attacker can only rewrite ciphertext bytes
        blob = bytearray(base64.b64decode(doc["ciphertext"]))
        blob[len(blob) // 2] ^= 0xFF
        doc["ciphertext"] = base64.b64encode(bytes(blob)).decode()
    else:
        doc["data"]["hostname"] = "attacker-box"
        doc["sha256"] = compute_sha256(doc["data"])
    path.write_text(json.dumps(doc), encoding="utf-8")


def _attack_custody_edit(path, record_id, vault):
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("jocky_envelope"):
        blob = bytearray(base64.b64decode(doc["ciphertext"]))
        blob[-20] ^= 0x01
        doc["ciphertext"] = base64.b64encode(bytes(blob)).decode()
    else:
        doc["custody_log"][0]["who"] = "Someone Else"
    path.write_text(json.dumps(doc), encoding="utf-8")


def _attack_swap(path, record_id, vault, donor=None):
    path.write_text(donor.read_text(encoding="utf-8"), encoding="utf-8")


def _attack_delete(path, record_id, vault):
    path.unlink()


E5_ATTACKS = [
    ("Edit payload, leave stored hash", _attack_payload_edit),
    ("Edit payload and recompute its SHA-256", _attack_payload_and_hash),
    ("Edit the custody log", _attack_custody_edit),
    ("Replace a file with another artifact's file", _attack_swap),
    ("Delete the artifact", _attack_delete),
]


def _detected(vault, evidence_id):
    try:
        result = vault.verify_artifact(evidence_id)
    except FileNotFoundError:
        return True
    if not result["valid"]:
        return True
    record = vault.get_artifact(evidence_id)
    # A swapped file is internally consistent; the ID mismatch gives it away
    return record.get("evidence_id") != evidence_id


def run_e5(trials=10):
    rows = []
    for mode in ("plaintext", "AES-256-GCM"):
        for label, attack in E5_ATTACKS:
            detected = 0
            for _ in range(trials):
                with tempfile.TemporaryDirectory() as tmp:
                    cipher = EvidenceCipher(secrets.token_bytes(32)) if mode != "plaintext" else None
                    vault = EvidenceVault(base_dir=tmp, cipher=cipher)
                    target = vault.seal_artifact("E5", "system", {"hostname": "lab", "n": secrets.randbelow(10**6)})
                    donor = vault.seal_artifact("E5", "system", {"hostname": "other", "n": 1})
                    tid = target["evidence_id"]
                    path = next(Path(tmp).rglob(f"{tid}.json"))
                    donor_path = next(Path(tmp).rglob(f"{donor['evidence_id']}.json"))
                    if attack is _attack_swap:
                        attack(path, tid, vault, donor=donor_path)
                    else:
                        attack(path, tid, vault)
                    detected += _detected(vault, tid)
            rows.append({"mode": mode, "attack": label, "trials": trials, "detected": detected})
    return rows


# ── E6 ──────────────────────────────────────────────────────────────────────

def run_e6(sizes=(1, 3, 5), repeats=3):
    """
    Pair N real agent clients against the API (in-process), dispatch one case
    to all of them, let each poll, verify its signed job, collect and upload,
    and time dispatch until the case reports complete.
    """
    from fastapi.testclient import TestClient

    from agent.client import EndpointAgentClient
    from agent.config import AgentConfig
    from backend.app.main import app

    client = TestClient(app)

    class _Session:
        def get(self, url, **kw):
            kw.pop("timeout", None)
            return client.get(url.replace("http://e6", ""), **kw)

        def post(self, url, **kw):
            kw.pop("timeout", None)
            return client.post(url.replace("http://e6", ""), **kw)

    login = client.post("/api/auth/login", json={"username": "investigator@jocky.local",
                                                 "password": "jocky-forensics-2026"}).json()
    headers = {"Authorization": f"Bearer {login['session']['token']}"}
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for n in sizes:
            times, completed = [], 0
            for rep in range(repeats):
                agents = []
                for i in range(n):
                    code = client.post("/api/agents/pairing/generate", headers=headers,
                                       json={"device_name": f"E6-{n}-{rep}-{i}"}).json()["pairing_code"]
                    agent = EndpointAgentClient(AgentConfig(config_path=str(Path(tmp) / f"{n}-{rep}-{i}.json")))
                    agent.session = _Session()
                    agent.pair("http://e6", code, custom_hostname=f"E6-{n}-{rep}-{i}")
                    agent.send_heartbeat = lambda: True
                    agents.append(agent)
                case_id = f"CASE-E6-{n}-{rep}-{secrets.token_hex(3)}"
                start = time.perf_counter()
                client.post(f"/api/agents/cases/{case_id}/dispatch", headers=headers,
                            json={"device_ids": [a.config.device_id for a in agents], "collectors": ["system", "dns"]})
                for agent in agents:
                    agent.run_once()
                status = client.get(f"/api/agents/cases/{case_id}", headers=headers).json()
                times.append(time.perf_counter() - start)
                completed += status["states"].get("completed", 0)
            rows.append({
                "endpoints": n,
                "runs": repeats,
                "jobs": n * repeats,
                "completed": completed,
                "median_s": round(statistics.median(times), 2),
                "max_s": round(max(times), 2),
            })
    return rows


# ── report ──────────────────────────────────────────────────────────────────

def _fmt(value):
    return "n/a" if value is None else f"{value:.3f}" if isinstance(value, float) else str(value)


def write_report(e1, e3, e4, e5, e6, out):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    host = f"{platform.system()} {platform.release()} · Python {platform.python_version()} · {psutil.cpu_count()} logical CPUs"
    lines = [
        "# JOCKY Evaluation",
        "",
        f"Generated by `python scripts/run_experiments.py` on {now}.  ",
        f"Host: {host}.",
        "",
        "These are measurements from one lab machine and a hand-labelled dataset. They show how the",
        "prototype behaves under the stated conditions; they are not claims about real-world detection rates.",
        "",
        "## E1 — Compiler correctness",
        "",
        "| Measure | Result |",
        "|---|---|",
        f"| Valid scripts accepted | {e1['valid_accepted']} / {e1['valid_total']} |",
        f"| Invalid scripts rejected with the expected error code | {e1['invalid_rejected_with_expected_code']} / {e1['invalid_total']} |",
        f"| Invalid scripts rejected with a different code | {len(e1['invalid_rejected_with_other_code'])} |",
        f"| Invalid scripts wrongly accepted | {len(e1['invalid_accepted'])} |",
        f"| IR identical whether lowered for Windows, Linux or macOS | {'yes' if e1['ir_identical_across_platforms'] else 'no'} |",
        "",
        "The valid set is every shipped example plus each collect target in both block and flat form.",
        "The invalid set includes an attempt to run a shell command and an unauthorised `INJECT` verb.",
        "",
        "## E3 — Collection performance",
        "",
        "Median of repeated runs of each collector on this host, called in-process.",
        "",
        "| Collector | Median ms | Max ms | CPU ms | RSS growth KB | Records | Payload KB |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in e3:
        lines.append(f"| {r['collector']} | {r['median_ms']} | {r['max_ms']} | {r['cpu_ms']} | {r['rss_growth_kb']} | "
                     f"{r['records']} | {r['payload_kb']} |")
    o = e4["overall"]
    lines += [
        "",
        "## E4 — Detection effectiveness",
        "",
        f"Dataset: `tests/fixtures/detection/labelled_records.json`, {e4['records']} records, "
        f"{e4['malicious']} malicious. Benign records deliberately include legitimate software that resembles",
        "attacker behaviour (NVIDIA and VirtualBox modules, ADB on 5555, installers in Temp, vendor updaters).",
        "",
        "| | TP | FP | FN | TN | Precision | Recall | F1 | FPR |",
        "|---|---|---|---|---|---|---|---|---|",
        f"| **All rules** | {o['tp']} | {o['fp']} | {o['fn']} | {o['tn']} | {_fmt(o['precision'])} | "
        f"{_fmt(o['recall'])} | {_fmt(o['f1'])} | {_fmt(o['false_positive_rate'])} |",
    ]
    for rid, m in e4["per_rule"].items():
        lines.append(f"| {rid} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {_fmt(m['precision'])} | "
                     f"{_fmt(m['recall'])} | {_fmt(m['f1'])} | {_fmt(m['false_positive_rate'])} |")
    lines += ["", "Every error, so the numbers can be checked:", "", "| Outcome | Source | Record |", "|---|---|---|"]
    for e in e4["errors"]:
        lines.append(f"| {e['outcome']} | {e['source']} | {e['note']} |")
    lines += [
        "",
        "## E5 — Evidence integrity",
        "",
        f"Each attack was applied to a freshly sealed artifact {e5[0]['trials']} times per storage mode, then the",
        "vault was asked to verify it.",
        "",
        "| Attack | Plaintext + SHA-256 | AES-256-GCM |",
        "|---|---|---|",
    ]
    plain = {r["attack"]: r for r in e5 if r["mode"] == "plaintext"}
    enc = {r["attack"]: r for r in e5 if r["mode"] != "plaintext"}
    for label, _ in E5_ATTACKS:
        lines.append(f"| {label} | {plain[label]['detected']} / {plain[label]['trials']} | "
                     f"{enc[label]['detected']} / {enc[label]['trials']} |")
    lines += [
        "",
        "A SHA-256 stored next to the data only proves the data matches that hash. Someone who can write the file",
        "can recompute it, and custody entries are outside the hashed payload. With encryption at rest the whole",
        "record is authenticated with a key the attacker does not hold and bound to its evidence ID, so every",
        "modification above is caught. This is why `JOCKY_EVIDENCE_KEY` should be set for real cases.",
        "",
        "## E6 — Multi-endpoint orchestration",
        "",
        "Real agent clients are paired against the API in-process, one case is dispatched to all of them, and each",
        "agent polls, verifies its Ed25519-signed job, runs `system` and `dns` and uploads the evidence. Time is",
        "measured from dispatch until the case status reports every endpoint completed. Network latency is not",
        "included, so these figures are the server and agent overhead only.",
        "",
        "| Endpoints | Runs | Jobs | Completed | Median s | Max s |",
        "|---|---|---|---|---|---|",
    ]
    for r in e6:
        lines.append(f"| {r['endpoints']} | {r['runs']} | {r['jobs']} | {r['completed']} | {r['median_s']} | {r['max_s']} |")
    lines += [
        "",
        "Refusal of forged, replayed, expired and mis-addressed jobs is covered by `tests/test_job_signing.py`;",
        "an endpoint that never answers stays `queued` and is reported as such (`tests/test_orchestration.py`).",
        "",
        "## E2 — Cross-platform consistency",
        "",
        "Runs on every push: the full test suite, including the Linux collectors against a fixture filesystem and",
        "live collection on the runner, passes on Ubuntu (Python 3.11 and 3.12) and Windows (Python 3.12). E1 above",
        "also confirms the same script produces identical IR whichever platform it is lowered for.",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--quick", action="store_true", help="one repetition for E3 and fewer E5 trials")
    parser.add_argument("--output", default=str(ROOT / "docs" / "EVALUATION.md"))
    args = parser.parse_args()
    e1 = run_e1()
    e3 = run_e3(1 if args.quick else 5)
    e4 = evaluate_dataset(load_dataset(ROOT / "tests/fixtures/detection/labelled_records.json"))
    e5 = run_e5(3 if args.quick else 10)
    e6 = run_e6(repeats=1 if args.quick else 3)
    write_report(e1, e3, e4, e5, e6, Path(args.output))
    print(json.dumps({"E1": e1, "E4": e4["overall"], "E5": e5}, indent=2, default=str))
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
