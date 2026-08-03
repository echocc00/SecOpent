# SecOpent application image (Linux)
# Multi-stage: build the React frontend, then run the FastAPI app.
#
# The app runs adapter containers via the host Docker daemon, so at runtime
# mount the host docker socket:  -v /var/run/docker.sock:/var/run/docker.sock
# and install the docker CLI inside the image (done below).

# ---------- Stage 1: build the frontend ----------
FROM node:20-slim AS web-builder
WORKDIR /web
COPY src/secopent/interfaces/web/package*.json ./
RUN npm ci --legacy-peer-deps
COPY src/secopent/interfaces/web/ ./
RUN npm run build

# ---------- Stage 2: Python app ----------
FROM python:3.12-slim

# docker CLI (client only) so the app can run adapter containers on the host daemon.
# curl is used by the built-in health checks; ca-certificates for OSV/registry TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (better layer caching)
COPY pyproject.toml ./
COPY src/secopent/__version__.py ./src/secopent/__version__.py
RUN pip install --no-cache-dir -e ".[dev]"

# Copy the source + the built frontend
COPY src/ ./src/
COPY alembic.ini alembic/ ./
COPY --from=web-builder /web/dist ./src/secopent/interfaces/web/dist

# Serve the SPA + API from one port
ENV SECOPTENT_WEB_DIST=/app/src/secopent/interfaces/web/dist
ENV PYTHONUNBUFFERED=1
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

# Run DB migrations on every start, then serve. The alembic.ini + alembic/
# dir are copied with src/; SECOPTENT_DB_URL (set at runtime) selects the DB.
# Migrations are idempotent (alembic stamps the current revision), so re-running
# on an up-to-date DB is a no-op. A 60s timeout prevents infinite hang when the
# DB is locked by a stale process (avoids restart loops).
CMD ["sh", "-c", "timeout 60 alembic upgrade head && exec python3 -m uvicorn secopent.interfaces.api.main:create_app --factory --host 0.0.0.0 --port 8000"]
