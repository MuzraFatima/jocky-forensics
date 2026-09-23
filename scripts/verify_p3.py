import sys
from pathlib import Path

# Ensure project root is in sys.path when running from scratch artifact directory
WORKSPACE_ROOT = Path(r"c:\Users\User\OneDrive\Desktop\sih148\jocky-forensics")
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from backend.app.collectors import (  # type: ignore
    get_collectors,
    collect_files_info,
    collect_users_info,
    collect_windows_metadata,
    collect_registry_info,
)
from backend.app.engine import execute_jocky_ir  # type: ignore
from backend.app.language import compile_jocky  # type: ignore
from fastapi.testclient import TestClient  # type: ignore
from backend.app.main import app  # type: ignore

print("=== 1. COLLECTORS REGISTRY ===")
cols = get_collectors()
for name, fn in cols.items():
    print(f"Collector: {name:18} -> callable={callable(fn)}")

print("\n=== 2. DIRECT RUN OF PHASE 3 COLLECTORS ===")
files = collect_files_info()
print(f"Files collected: {files['count']} files, {files['process_binaries_count']} proc binaries.")
print(f"Evidence ID: {files['evidence_id']}")
print(f"Provenance: method={files['provenance']['method']} | host={files['provenance']['host']}")

users = collect_users_info()
print(f"Users collected: {users['count']} items, current user={users['current_user']['username']} (admin={users['current_user']['is_admin']})")
print(f"Active sessions: {len(users['active_sessions'])}, profiles: {len(users['user_profiles'])}")

win = collect_windows_metadata()
print(f"Windows metadata: {len(win['autoruns'])} autoruns, {len(win['services'])} services.")
print(f"OS product: {win['os_metadata'].get('product_name')}")

print("\n=== 3. FASTAPI TESTCLIENT VERIFICATION ===")
client = TestClient(app)
r_list = client.get("/api/forensics/collectors")
print(f"GET /api/forensics/collectors: {r_list.status_code}, count={len(r_list.json()['collectors'])}")

r_files = client.get("/api/forensics/collect/files")
print(f"GET /api/forensics/collect/files: {r_files.status_code}, count={r_files.json()['artifact']['count']}")

r_users = client.get("/api/forensics/collect/users")
print(f"GET /api/forensics/collect/users: {r_users.status_code}, user={r_users.json()['artifact']['current_user']['username']}")

r_win = client.get("/api/forensics/collect/windows_metadata")
print(f"GET /api/forensics/collect/windows_metadata: {r_win.status_code}, autoruns={len(r_win.json()['artifact']['autoruns'])}")

print("\n=== 4. COMPILING AND EXECUTING FULL PHASE 3 JOCKY SCRIPT ===")
script = """CASE "SIH-P3-VERIFY"
TARGET "LOCAL-HOST"

COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
COLLECT NETWORK
    WHERE state == ESTABLISHED
COLLECT FILES "evidence"
COLLECT USERS
COLLECT REGISTRY

ANALYZE PROCESS_NETWORK
VERIFY INTEGRITY
REPORT FORMAT JSON
"""

c_res = compile_jocky(script)
print(f"Compiler success: {c_res['success']}, tokens={c_res.get('tokens_count')}, ops={len(c_res['ir']['operations'])}")

receipt = execute_jocky_ir(c_res["ir"])
print(f"IRExecutor success: {receipt['success']}")
print(f"Evidence IDs generated: {list(receipt['evidence_ids'].keys())}")
print(f"Integrity verified: {receipt['integrity_status']['verified']} ({receipt['integrity_status']['total_verified']} artifacts)")
print("Analysis findings:")
for f in receipt['analysis']['findings']:
    print("  *", f)
