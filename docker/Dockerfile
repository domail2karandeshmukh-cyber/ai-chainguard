# AI-ChainGuard image: API, dashboard, pipeline and CLI share one image.
# Build from the repository root:  docker build -f docker/Dockerfile -t ai-chainguard .
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CHAINGUARD_HOME=/workspace

WORKDIR /app

# CPU-only PyTorch keeps the image ~1 GB smaller than the default CUDA wheel.
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY chainguard ./chainguard
COPY cli ./cli
COPY api ./api
COPY ml_pipeline ./ml_pipeline
COPY deployment ./deployment
COPY attacks ./attacks
COPY dashboard ./dashboard
COPY scripts ./scripts
COPY config ./config
COPY data/samples ./data/samples
COPY .streamlit ./.streamlit
COPY pyproject.toml README.md Makefile ./

# Run as an unprivileged user; the workspace (keys, DB, artifacts) is a volume.
RUN useradd --create-home --uid 10001 chainguard \
    && mkdir -p /workspace && chown chainguard:chainguard /workspace
USER chainguard
VOLUME ["/workspace"]

EXPOSE 8000 8501
# Health check: defined per service in docker-compose.yml (only the API serves /health).
CMD ["uvicorn", "api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
