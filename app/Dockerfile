# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Build stage: install pinned deps into an isolated target dir.
# ---------------------------------------------------------------------------
FROM python:3.15-slim-trixie AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN pip install --target /deps -r requirements.txt

# ---------------------------------------------------------------------------
# Runtime stage: distroless (no shell, no package manager), non-root UID 65532.
# Python minor version matches the build stage (3.13, Debian 13 "trixie").
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/python3-debian13:nonroot
LABEL org.opencontainers.image.title="secure-app" \
      org.opencontainers.image.source="https://github.com/ahmedlab8/cloud-security-blueprint" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONPATH=/deps:/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /deps /deps
COPY src/ /app/
WORKDIR /app
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["python3", "-m", "gunicorn", "-c", "/app/gunicorn.conf.py", "app:app"]
