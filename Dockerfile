# syntax=docker/dockerfile:1.7
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ---- build layer: install deps (cached unless pyproject changes)
FROM base AS build
COPY pyproject.toml README.md ./
COPY ash ./ash
COPY scripts ./scripts
COPY config ./config
RUN pip install --upgrade pip && pip install ".[production]"

# ---- runtime image: non-root, minimal
FROM base AS runtime
RUN groupadd -r ash && useradd -r -g ash -d /app -s /sbin/nologin ash
COPY --from=build /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=build /usr/local/bin/ash /usr/local/bin/ash
COPY --from=build /app /app
RUN mkdir -p /data && chown -R ash:ash /app /data
USER ash

ENV ASH_DATABASE_URL=sqlite:////data/ash.db \
    ASH_POLICY_FILE=/app/config/policy.yaml \
    ASH_ENVIRONMENT=production

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health').status==200 else 1)"

CMD ["ash", "serve", "--host", "0.0.0.0", "--port", "8080"]
