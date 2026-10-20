# Gunicorn hardening: bind non-privileged port, bounded workers/timeouts, no server banner.
bind = "0.0.0.0:8080"
# Single worker + threads: prometheus_client keeps metrics per process, so one process per
# pod keeps /metrics consistent. Scale horizontally with replicas/HPA instead.
workers = 1
threads = 4
timeout = 30
graceful_timeout = 20
keepalive = 5
limit_request_line = 4094
limit_request_fields = 50
worker_tmp_dir = "/tmp"  # noqa: S108 - per-pod memory-backed emptyDir (root FS is read-only)
accesslog = "-"
errorlog = "-"

# Hide the server banner (ZAP rule 10036 / information disclosure).
import gunicorn

gunicorn.SERVER = "undisclosed"
