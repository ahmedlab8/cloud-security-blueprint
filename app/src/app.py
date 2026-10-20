"""secure-app: a deliberately small Flask service used to demonstrate the
DevSecOps pipeline end to end (SAST, SCA, image scanning, DAST, runtime).

Endpoints
  GET  /           - hello
  GET  /healthz    - liveness/readiness
  POST /login      - demo login; emits auth success/failure metrics for Grafana
  GET  /metrics    - Prometheus metrics
"""

from __future__ import annotations

import hmac
import logging
import os
import sys

from flask import Flask, Response, jsonify, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest

logging.basicConfig(
    stream=sys.stdout,
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger("secure-app")

LOGIN_ATTEMPTS = Counter(
    "app_login_attempts_total",
    "Login attempts by result",
    ["result"],
)
HTTP_REQUESTS = Counter(
    "app_http_requests_total",
    "HTTP requests by endpoint and status",
    ["endpoint", "status"],
)

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
}


def _load_secret(name: str) -> str:
    """Read a secret from <NAME>_FILE if set (preferred), else from the env var."""
    path = os.environ.get(f"{name}_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            log.error("a configured *_FILE secret mount could not be read")
            return ""
    return os.environ.get(name, "")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=16 * 1024,  # small bodies only
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )

    # Demo credential is injected at runtime as a mounted file (Secrets Store CSI / K8s Secret),
    # never baked into the image. DEMO_PASSWORD env is only a fallback for local tests.
    expected_password = _load_secret("DEMO_PASSWORD")

    @app.after_request
    def _harden(resp: Response) -> Response:
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers.pop("Server", None)
        HTTP_REQUESTS.labels(endpoint=request.endpoint or "unknown", status=resp.status_code).inc()
        return resp

    @app.get("/")
    def index():
        return jsonify(service="secure-app", status="ok")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="healthy")

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        password = str(body.get("password", ""))
        ok = bool(expected_password) and hmac.compare_digest(password, expected_password)
        result = "success" if ok else "failure"
        LOGIN_ATTEMPTS.labels(result=result).inc()
        # Never log the submitted credential.
        log.info("login result=%s remote=%s", result, request.remote_addr)
        if not ok:
            return jsonify(error="invalid credentials"), 401
        return jsonify(status="authenticated")

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    @app.get("/robots.txt")
    def robots():
        return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")

    return app


app = create_app()
