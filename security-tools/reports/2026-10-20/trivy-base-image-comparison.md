# Trivy base-image comparison (2026-10-20)

Real `trivy image` scans (Trivy 0.76.0, run on 2026-10-20) of the candidate base images.
This is the evidence behind choosing the runtime base in `app/Dockerfile`.

| Image | Debian | CRITICAL | HIGH | MEDIUM | LOW | Fixable CRITICAL | Fixable HIGH |
|---|---|---|---|---|---|---|---|
| `python:3.11-bookworm` (full Debian 12) | 12.15 | 21 | 586 | 2790 | 1945 | 0 | 81 |
| `python:3.11-slim-bookworm` | 12.15 | 2 | 63 | 117 | 108 | 0 | 2 |
| `gcr.io/distroless/python3-debian12:nonroot` | 12.13 | 2 | 61 | 153 | 74 | 0 | 43 |
| `python:3.13-slim-trixie` (build stage) | 13.7 | 0 | 48 | 60 | 61 | 0 | 4 |
| `gcr.io/distroless/python3-debian13:nonroot` (runtime base) | 13.7 | 0 | 26 | 87 | 49 | 0 | 0 |
