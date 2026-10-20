#!/usr/bin/env python3
"""Generate the Grafana dashboards in dashboards/ (keeps panel JSON consistent and reviewable).

python3 monitoring/grafana/build_dashboards.py
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
DS = {"type": "prometheus", "uid": "${datasource}"}


def templating(extra: list[dict] | None = None) -> dict:
    items = [
        {"name": "datasource", "type": "datasource", "query": "prometheus", "label": "Data source"},
        {
            "name": "namespace",
            "type": "query",
            "datasource": DS,
            "query": "label_values(kube_pod_info, namespace)",
            "includeAll": True,
            "multi": True,
            "current": {"text": "All", "value": "$__all"},
            "refresh": 2,
        },
    ]
    return {"list": items + (extra or [])}


def panel(
    pid: int,
    title: str,
    kind: str,
    exprs: list[tuple[str, str]],
    x: int,
    y: int,
    w: int = 12,
    h: int = 8,
    unit: str = "short",
    thresholds: list | None = None,
) -> dict:
    p = {
        "id": pid,
        "title": title,
        "type": kind,
        "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [{"refId": chr(65 + i), "expr": e, "legendFormat": lf, "datasource": DS} for i, (e, lf) in enumerate(exprs)],
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "thresholds": {
                    "mode": "absolute",
                    "steps": thresholds or [{"color": "green", "value": None}, {"color": "red", "value": 1}],
                },
            },
            "overrides": [],
        },
        "options": {},
    }
    if kind == "timeseries":
        p["options"] = {"legend": {"displayMode": "table", "placement": "bottom"}, "tooltip": {"mode": "multi"}}
    if kind == "stat":
        p["options"] = {"colorMode": "background", "reduceOptions": {"calcs": ["lastNotNull"]}}
    return p


def dashboard(uid: str, title: str, panels: list[dict], tags: list[str]) -> dict:
    return {
        "uid": uid,
        "title": title,
        "tags": ["cloud-security-blueprint", *tags],
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "refresh": "1m",
        "time": {"from": "now-24h", "to": "now"},
        "templating": templating(),
        "annotations": {"list": []},
        "panels": panels,
    }


FALCO = "falcosecurity_falcosidekick_falco_events_total"

dashboards = {
    "security-alerts.json": dashboard(
        "csb-security-alerts",
        "Security Alerts (Falco + Gatekeeper)",
        [
            panel(
                1,
                "Critical runtime events (24h)",
                "stat",
                [(f'sum(increase({FALCO}{{priority=~"critical|alert|emergency"}}[24h]))', "critical")],
                0,
                0,
                6,
                5,
            ),
            panel(
                2,
                "All Falco events (24h)",
                "stat",
                [(f"sum(increase({FALCO}[24h]))", "events")],
                6,
                0,
                6,
                5,
                thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 10}],
            ),
            panel(3, "Gatekeeper audit violations", "stat", [("sum(gatekeeper_violations)", "violations")], 12, 0, 6, 5),
            panel(
                4,
                "Admission requests denied (1h)",
                "stat",
                [('sum(increase(gatekeeper_validation_request_count_total{admission_status="deny"}[1h]))', "denied")],
                18,
                0,
                6,
                5,
            ),
            panel(
                5,
                "Falco events by rule",
                "timeseries",
                [(f'sum by (rule) (rate({FALCO}{{k8s_ns_name=~"$namespace"}}[5m]))', "{{rule}}")],
                0,
                5,
                12,
                9,
                "ops",
            ),
            panel(
                6,
                "Falco events by priority",
                "timeseries",
                [(f"sum by (priority) (rate({FALCO}[5m]))", "{{priority}}")],
                12,
                5,
                12,
                9,
                "ops",
            ),
            panel(
                7,
                "Top pods by Falco events (24h)",
                "table",
                [(f'topk(10, sum by (k8s_ns_name, k8s_pod_name, rule) (increase({FALCO}{{k8s_ns_name=~"$namespace"}}[24h])))', "")],
                0,
                14,
                12,
                9,
            ),
            panel(
                8,
                "Gatekeeper violations by constraint",
                "timeseries",
                [("sum by (enforcement_action) (gatekeeper_violations)", "{{enforcement_action}}")],
                12,
                14,
                12,
                9,
            ),
            panel(9, "Firing security alerts", "table", [('ALERTS{alertstate="firing", team="security"}', "{{alertname}}")], 0, 23, 24, 7),
        ],
        ["security", "falco", "gatekeeper"],
    ),
    "failed-logins.json": dashboard(
        "csb-failed-logins",
        "Authentication - Failed Logins",
        [
            panel(
                1,
                "Failed logins (1h)",
                "stat",
                [('sum(increase(app_login_attempts_total{result="failure", namespace=~"$namespace"}[1h]))', "failed")],
                0,
                0,
                8,
                5,
                thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 50}, {"color": "red", "value": 500}],
            ),
            panel(
                2,
                "Successful logins (1h)",
                "stat",
                [('sum(increase(app_login_attempts_total{result="success", namespace=~"$namespace"}[1h]))', "success")],
                8,
                0,
                8,
                5,
                thresholds=[{"color": "green", "value": None}],
            ),
            panel(
                3,
                "Failure ratio (15m)",
                "stat",
                [
                    (
                        'sum(rate(app_login_attempts_total{result="failure", namespace=~"$namespace"}[15m])) / clamp_min(sum(rate(app_login_attempts_total{namespace=~"$namespace"}[15m])), 0.001)',
                        "ratio",
                    )
                ],
                16,
                0,
                8,
                5,
                "percentunit",
                [{"color": "green", "value": None}, {"color": "orange", "value": 0.5}, {"color": "red", "value": 0.8}],
            ),
            panel(
                4,
                "Login attempts per second by result",
                "timeseries",
                [('sum by (result) (rate(app_login_attempts_total{namespace=~"$namespace"}[5m]))', "{{result}}")],
                0,
                5,
                24,
                9,
                "ops",
            ),
            panel(
                5,
                "Failed logins by pod",
                "timeseries",
                [('sum by (pod) (rate(app_login_attempts_total{result="failure", namespace=~"$namespace"}[5m]))', "{{pod}}")],
                0,
                14,
                12,
                8,
                "ops",
            ),
            panel(
                6,
                "HTTP 401 responses",
                "timeseries",
                [('sum by (endpoint) (rate(app_http_requests_total{status="401", namespace=~"$namespace"}[5m]))', "{{endpoint}}")],
                12,
                14,
                12,
                8,
                "ops",
            ),
        ],
        ["security", "authentication"],
    ),
    "container-restarts.json": dashboard(
        "csb-container-restarts",
        "Workloads - Container Restarts",
        [
            panel(
                1,
                "Restarts (1h)",
                "stat",
                [('sum(increase(kube_pod_container_status_restarts_total{namespace=~"$namespace"}[1h]))', "restarts")],
                0,
                0,
                8,
                5,
                thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 3}, {"color": "red", "value": 10}],
            ),
            panel(
                2,
                "OOMKilled containers",
                "stat",
                [
                    (
                        'count(kube_pod_container_status_last_terminated_reason{reason="OOMKilled", namespace=~"$namespace"} == 1) or vector(0)',
                        "oom",
                    )
                ],
                8,
                0,
                8,
                5,
            ),
            panel(
                3,
                "CrashLoopBackOff containers",
                "stat",
                [
                    (
                        'count(kube_pod_container_status_waiting_reason{reason="CrashLoopBackOff", namespace=~"$namespace"} == 1) or vector(0)',
                        "crashloop",
                    )
                ],
                16,
                0,
                8,
                5,
            ),
            panel(
                4,
                "Restarts by container (rate)",
                "timeseries",
                [
                    (
                        'sum by (namespace, pod, container) (increase(kube_pod_container_status_restarts_total{namespace=~"$namespace"}[15m]))',
                        "{{namespace}}/{{pod}}/{{container}}",
                    )
                ],
                0,
                5,
                24,
                10,
            ),
            panel(
                5,
                "Top restarting containers (24h)",
                "table",
                [
                    (
                        'topk(15, sum by (namespace, pod, container) (increase(kube_pod_container_status_restarts_total{namespace=~"$namespace"}[24h])))',
                        "",
                    )
                ],
                0,
                15,
                24,
                8,
            ),
        ],
        ["workloads", "reliability"],
    ),
    "cpu-memory.json": dashboard(
        "csb-cpu-memory",
        "Workloads - CPU & Memory",
        [
            panel(
                1,
                "CPU usage by pod (cores)",
                "timeseries",
                [
                    (
                        'sum by (namespace, pod) (rate(container_cpu_usage_seconds_total{container!="", container!="POD", namespace=~"$namespace"}[5m]))',
                        "{{namespace}}/{{pod}}",
                    )
                ],
                0,
                0,
                12,
                9,
            ),
            panel(
                2,
                "CPU % of limit",
                "timeseries",
                [
                    (
                        'sum by (namespace, pod) (rate(container_cpu_usage_seconds_total{container!="", container!="POD", namespace=~"$namespace"}[5m])) / sum by (namespace, pod) (kube_pod_container_resource_limits{resource="cpu", namespace=~"$namespace"})',
                        "{{namespace}}/{{pod}}",
                    )
                ],
                12,
                0,
                12,
                9,
                "percentunit",
                [{"color": "green", "value": None}, {"color": "orange", "value": 0.7}, {"color": "red", "value": 0.9}],
            ),
            panel(
                3,
                "Memory working set by pod",
                "timeseries",
                [
                    (
                        'sum by (namespace, pod) (container_memory_working_set_bytes{container!="", container!="POD", namespace=~"$namespace"})',
                        "{{namespace}}/{{pod}}",
                    )
                ],
                0,
                9,
                12,
                9,
                "bytes",
            ),
            panel(
                4,
                "Memory % of limit",
                "timeseries",
                [
                    (
                        'sum by (namespace, pod) (container_memory_working_set_bytes{container!="", container!="POD", namespace=~"$namespace"}) / sum by (namespace, pod) (kube_pod_container_resource_limits{resource="memory", namespace=~"$namespace"})',
                        "{{namespace}}/{{pod}}",
                    )
                ],
                12,
                9,
                12,
                9,
                "percentunit",
                [{"color": "green", "value": None}, {"color": "orange", "value": 0.7}, {"color": "red", "value": 0.9}],
            ),
            panel(
                5,
                "CPU throttling",
                "timeseries",
                [
                    (
                        'sum by (namespace, pod) (rate(container_cpu_cfs_throttled_periods_total{namespace=~"$namespace"}[5m])) / clamp_min(sum by (namespace, pod) (rate(container_cpu_cfs_periods_total{namespace=~"$namespace"}[5m])), 1)',
                        "{{namespace}}/{{pod}}",
                    )
                ],
                0,
                18,
                24,
                8,
                "percentunit",
            ),
        ],
        ["workloads", "capacity", "cryptomining"],
    ),
}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, d in dashboards.items():
        (OUT / name).write_text(json.dumps(d, indent=2) + "\n")
        print(f"wrote dashboards/{name}")


if __name__ == "__main__":
    main()
