# Multi-stage Dockerfile for JOCKY Forensics (Frontend + Backend in One)

# --- Stage 1: Build React Frontend ---
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Python Backend & Unified Server ---
FROM python:3.11-slim
WORKDIR /app

# Install essential dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend application code & framework files
COPY backend/ ./backend/
COPY jocky.py ./

# Copy built frontend distribution from builder stage
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Configure port (Render and Railway inject $PORT dynamically)
ENV PORT=8000
EXPOSE 8000

# Start FastAPI application
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
