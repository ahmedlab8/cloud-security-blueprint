import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ["DEMO_PASSWORD"] = "unit-test-only"

from app import create_app


def client():
    return create_app().test_client()


def test_health():
    r = client().get("/healthz")
    assert r.status_code == 200
    assert r.json["status"] == "healthy"


def test_security_headers_present():
    r = client().get("/")
    for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
        assert h in r.headers


def test_login_failure_and_success():
    c = client()
    assert c.post("/login", json={"password": "wrong"}).status_code == 401
    assert c.post("/login", json={"password": "unit-test-only"}).status_code == 200


def test_metrics_exposes_login_counter():
    c = client()
    c.post("/login", json={"password": "nope"})
    body = c.get("/metrics").get_data(as_text=True)
    assert 'app_login_attempts_total{result="failure"}' in body
