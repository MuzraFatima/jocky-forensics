# JOCKY — Domain-Specific Forensic Analysis Framework

> **SIH 2026 Problem Statement SIH26148**: "Creation of scripts/functions with new programming language to commence Computer & Network forensic analysis without triggering security solutions."

[![Live Demo](https://img.shields.io/badge/Demo-Live%20Application-brightgreen?style=for-the-badge&logo=render)](https://YOUR-APP-NAME.onrender.com)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB?style=for-the-badge&logo=react)](https://react.dev)

---

## 🌐 Live Demo Link

> **Live Application URL**: `https://YOUR-APP-NAME.onrender.com`  
> *(Replace `YOUR-APP-NAME` with your free Render app name once deployed)*

---

## ⚠️ Important Scope & Compliance Statement

**JOCKY is an authorized digital-forensics research prototype.**
This framework strictly adheres to ethical, lawful, and defensive incident response standards:
- **NO Evasion or Bypass**: The framework deliberately avoids antivirus/EDR bypass, memory injection, process hollow/hollowing, kernel exploitation (BYOVD), rootkits, covert C2, or disabling system security telemetry.
- **Transparent, Authorized Architecture**: Rather than evading defenses through offensive stealth, JOCKY minimizes false-positive security alerts by employing an **authorized execution model**: signed scripts, declarative read-only operations, policy enforcement, rate-limited resource utilization, and transparent standard OS APIs (`psutil`, socket inspection).
- **Evidentiary Rigor**: Every artifact acquired is hashed with SHA-256 and registered into an immutable chain of custody for legal and auditing compliance.

---

## Current Status: Project Skeleton (Phase 1)

This repository currently hosts the **Phase 1 clean architectural skeleton**.

| Component | Status | Description |
|---|---|---|
| **Backend Core** | `Skeleton` | FastAPI application serving `/` metadata and `/api/health` verification endpoint. |
| **Language Module** | `Placeholder` | Design specifications for JOCKY Lexer, AST, and Execution Planner (`backend/app/language/`). |
| **Execution Engine** | `Placeholder` | Policy enforcement and task orchestration layer (`backend/app/engine/`). |
| **Safe Collectors** | `Placeholder` | Read-only collectors for System, Processes, Network, and Files (`backend/app/collectors/`). |
| **Evidence Store** | `Placeholder` | Evidence vault with SHA-256 hashing and Chain-of-Custody records (`backend/app/evidence/`). |
| **Analysis Engine** | `Placeholder` | Heuristic correlation and anomaly detection (`backend/app/analysis/`). |
| **Reporting Subsystem** | `Placeholder` | Structured JSON and human-readable forensic report generator (`backend/app/reports/`). |
| **Frontend Dashboard** | `Skeleton` | Vite + React web interface showing "JOCKY Forensic Analysis Framework" (`frontend/`). |
| **Examples & Tests** | `Ready` | Sample JOCKY DSL script (`examples/sample.jocky`) and backend health tests (`tests/test_backend.py`). |

---

## Project Structure

```
jocky-forensics/
├── backend/
│   ├── app/
│   │   ├── analysis/       # Heuristic anomaly detection (Placeholder)
│   │   ├── collectors/     # Safe read-only collectors (Placeholder)
│   │   ├── engine/         # Execution engine & policy validator (Placeholder)
│   │   ├── evidence/       # Evidence store & SHA-256 custody (Placeholder)
│   │   ├── language/       # DSL Lexer, Parser & AST (Placeholder)
│   │   ├── reports/        # Forensic report generator (Placeholder)
│   │   ├── __init__.py
│   │   └── main.py         # FastAPI entrypoint
│   └── requirements.txt    # Python dependencies (FastAPI, psutil, pydantic, etc.)
├── frontend/               # React + Vite investigative dashboard
├── examples/               # Example forensic scripts (.jocky)
│   └── sample.jocky
├── evidence/               # Target evidence vault directory (.gitkeep)
├── reports/                # Output directory for generated forensic reports (.gitkeep)
├── tests/                  # Backend and integration tests
│   └── test_backend.py
├── architecture.md         # Detailed architectural blueprint & data-flow pipeline
└── README.md               # Project documentation & scope guidelines
```

---

## Example JOCKY Forensic Script

```
CASE "LAB-2026-001"

TARGET "LAB-PC"

COLLECT SYSTEM
COLLECT PROCESSES
COLLECT NETWORK
COLLECT FILES "./evidence"

ANALYZE
VERIFY INTEGRITY
REPORT
```

---

## Getting Started

### 1. Backend Setup & Run

Requirements: Python 3.10+

```powershell
# Navigate to backend
cd jocky-forensics/backend

# Install dependencies
pip install -r requirements.txt

# Run development server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- API Root: `http://127.0.0.1:8000/`
- Health Endpoint: `http://127.0.0.1:8000/api/health`
- Interactive Swagger Docs: `http://127.0.0.1:8000/docs`

### 2. Frontend Setup & Run

Requirements: Node.js 18+

```powershell
# Navigate to frontend
cd jocky-forensics/frontend

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```

- Web Dashboard: `http://localhost:5173/`

### 3. Running Backend Tests

```powershell
# From jocky-forensics root
python -m pytest tests/
```

---

## 🚀 How to Deploy & Get a Live URL (Free)

This project contains a multi-stage Dockerfile and unified server setup so you can deploy both the React UI and FastAPI backend to a single free live link with zero CORS issues.

### Option 1: 1-Click Deploy on Render (Recommended — Free)

1. Push this repository to your GitHub account (`git push origin main`).
2. Go to **[Render.com](https://render.com/)** and log in with your GitHub account.
3. Click **New +** > **Web Service**.
4. Select your **`jocky-forensics`** repository.
5. In the configuration settings:
   - **Name**: `jocky-forensics` (or your preferred name)
   - **Language / Runtime**: **Docker** (it will automatically detect the root `Dockerfile`)
   - **Region**: Any close to you (e.g., Oregon or Frankfurt)
   - **Instance Type**: **Free**
6. Click **Create Web Service**.
7. Render will build the React frontend and launch the FastAPI server. Once finished, you will receive a public HTTPS URL:
   `https://<your-service-name>.onrender.com`
8. Paste that link into your GitHub repository's **About / Website** section and update the `[Live Demo]` badge at the top of this `README.md`!

---

### Option 2: Run with Docker Locally

```bash
# Build the unified image
docker build -t jocky-forensics .

# Run the container
docker run -p 8000:8000 jocky-forensics
```
Visit `http://localhost:8000` to interact with the full application.

