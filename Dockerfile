# ── Stage 1: dependency installer ────────────────────────────────────────────
FROM python:3.12-slim AS deps

WORKDIR /app

# Install build tools needed for some native wheels (httptools, uvloop)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Install into a separate prefix so Stage 2 can copy only the packages
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from the build stage
COPY --from=deps /install /usr/local

# Copy application source
COPY main.py .
COPY templates/ templates/

# Non-root user for least-privilege execution
RUN useradd -m appuser
USER appuser

# Expose the FastAPI port
EXPOSE 8000

# Uvicorn: bind to all interfaces, single worker is fine for a dev/test tool.
# For production add --workers N or use gunicorn + uvicorn workers.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
