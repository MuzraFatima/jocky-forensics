"""
JOCKY Forensic Framework — Master Executable & CLI Runner

Usage:
    python jocky.py compile <script_file>
    python jocky.py execute <script_file> [--format HTML|MD|JSON] [--output <path>]
    python jocky.py audit [--case <case_id>]
    python jocky.py export <case_id> [--output <path>]
    python jocky.py serve [--port 8000]
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.app.cli import main, build_parser


if __name__ == "__main__":
    # Check if user invoked 'serve'
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        import uvicorn
        port = 8000
        if "--port" in sys.argv:
            idx = sys.argv.index("--port")
            if idx + 1 < len(sys.argv):
                port = int(sys.argv[idx + 1])
        print(f"[*] Starting JOCKY Forensics FastAPI Server on http://127.0.0.1:{port}...")
        uvicorn.run("backend.app.main:app", host="127.0.0.1", port=port, reload=False)
    else:
        sys.exit(main())
