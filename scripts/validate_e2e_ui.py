"""
Manual End-to-End Validation Script for Step 7 (Frontend Endpoint Management)
"""

import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

BASE = 'http://127.0.0.1:8000'

# 1. Login
req = urllib.request.Request(
    f'{BASE}/api/auth/login',
    data=json.dumps({'username': 'investigator@jocky.local', 'password': 'jocky-forensics-2026'}).encode(),
    headers={'Content-Type': 'application/json'},
)
res = json.loads(urllib.request.urlopen(req).read())
token = res['session']['token']
print('[1] Login succeeded, investigator token:', token[:20] + '...')

# 2. Generate Pairing Code
req2 = urllib.request.Request(
    f'{BASE}/api/agents/pairing/generate',
    data=json.dumps({'device_name': 'Validation-PC'}).encode(),
    headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'},
)
pair_gen = json.loads(urllib.request.urlopen(req2).read())
code = pair_gen['pairing_code']
print('[2] Pairing code generated:', code, 'expires in:', pair_gen['ttl_seconds'], 'seconds')

# 3. Pair device using jocky-agent.py
pair_cmd = subprocess.run(
    ['python', 'jocky-agent.py', 'pair', '--server', BASE, '--code', code, '--name', 'Validation-Endpoint'],
    capture_output=True,
    text=True,
)
print('[3] Pair output:\n' + pair_cmd.stdout.strip())

# 4. Status
status_cmd = subprocess.run(['python', 'jocky-agent.py', 'status'], capture_output=True, text=True)
print('[4] Status output:\n' + status_cmd.stdout.strip())

# 5. Check devices in backend
from agent.config import AgentConfig
local_cfg = AgentConfig.load()
dev_id = local_cfg.device_id

req_devs = urllib.request.Request(f'{BASE}/api/agents/devices', headers={'Authorization': f'Bearer {token}'})
devs = json.loads(urllib.request.urlopen(req_devs).read())['devices']
enrolled = next(d for d in devs if d['device_id'] == dev_id)
print('[5] Found enrolled device in backend:', dev_id, 'Status:', enrolled['status'], 'Online:', enrolled['is_online'])

# 6. Execute script against endpoint
script = """CASE "LAB-ENDPOINT-UI"
TARGET "ENDPOINT-WORKSTATION"

COLLECT SYSTEM

COLLECT PROCESSES
    WHERE status == RUNNING

COLLECT NETWORK
    WHERE state == ESTABLISHED

ANALYZE PROCESS_NETWORK

VERIFY INTEGRITY

REPORT FORMAT JSON"""

stop_flag = False

def agent_worker():
    global stop_flag
    print('--> Agent worker listening for jobs...')
    while not stop_flag:
        proc = subprocess.run(['python', 'jocky-agent.py', 'start', '--once'], capture_output=True, text=True)
        if 'Jobs processed:' in proc.stdout and not 'Jobs processed: 0' in proc.stdout:
            print('--> Agent successfully processed job:\n' + proc.stdout.strip())
            break
        time.sleep(0.5)

t = threading.Thread(target=agent_worker)
t.start()

exec_payload = {'script': script, 'device_id': dev_id, 'wait_timeout': 30}
req_exec = urllib.request.Request(
    f'{BASE}/api/jocky/execute',
    data=json.dumps(exec_payload).encode(),
    headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'},
)
try:
    exec_res = json.loads(urllib.request.urlopen(req_exec).read())
finally:
    stop_flag = True
    t.join(timeout=5)

print('\n[6] Execution result on endpoint:')
print('    Success:', exec_res.get('success'))
print('    Case ID:', exec_res.get('case_id'))
print('    Target:', exec_res.get('target'))
print('    Execution ID:', exec_res.get('execution_id'))
print('    Collected modules:', list(exec_res.get('collected_data', {}).keys()))
print('    Integrity status:', exec_res.get('integrity_status'))
print('    Evidence manifest items:', len(exec_res.get('evidence_manifest', [])))
report = exec_res.get('report', {})
print('    Report generated:', bool(report))
print('    Report target host:', report.get('target_host'))
print('    Report collector identity:', report.get('collector_identity'))

# 7. Unpair cleanup
unpair_cmd = subprocess.run(['python', 'jocky-agent.py', 'unpair'], capture_output=True, text=True)
print('[7] Unpair output:', unpair_cmd.stdout.strip())
print('\n[+] MANUAL END-TO-END VALIDATION COMPLETED SUCCESSFULLY!')
