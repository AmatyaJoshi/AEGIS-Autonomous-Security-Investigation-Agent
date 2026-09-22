# AEGIS API image (recommend-only SOC investigation agent). Runs the FastAPI review backend over the
# offline DuckDB snapshot mounted at /app/data. No GPU, no API keys required.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_SYSTEM_PYTHON=1 \
    AEGIS_DATA_ROOT=/app/data AEGIS_API_DSN=sqlite:////app/data/aegis.db

RUN apt-get update && apt-get install -y --no-install-recommends git curl libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv

WORKDIR /app
COPY pyproject.toml README.md ./
COPY aegis ./aegis
COPY lab ./lab
COPY bench ./bench
COPY training ./training
RUN uv pip install --no-cache -e "."

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --retries=10 CMD curl -fsS http://localhost:8000/health || exit 1
CMD ["python", "-m", "aegis.cli", "serve", "--host", "0.0.0.0", "--port", "8000"]
