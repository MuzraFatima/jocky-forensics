"""
Shared pytest setup.

The auth and agent managers persist users and devices as JSON under
JOCKY_STORAGE_DIR (default: <repo>/data). Those files are tracked in git, so
the suite points the managers at a throwaway copy before any backend module
is imported. Running the tests therefore never rewrites the repository.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

if "JOCKY_STORAGE_DIR" not in os.environ:
    _tmp_storage = Path(tempfile.mkdtemp(prefix="jocky-test-data-"))
    _seed_dir = _REPO_ROOT / "data"
    if _seed_dir.is_dir():
        for seed_file in _seed_dir.glob("*.json"):
            shutil.copy2(seed_file, _tmp_storage / seed_file.name)
    os.environ["JOCKY_STORAGE_DIR"] = str(_tmp_storage)

# The API test modules predate sign-in enforcement and call endpoints without a
# token. They run with enforcement off; tests/test_rbac.py switches it back on.
os.environ.setdefault("JOCKY_AUTH_DISABLED", "1")
