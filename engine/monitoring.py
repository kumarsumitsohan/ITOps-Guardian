"""MONITOR: simulated metric polling, tables for the UI, and network diagnostics."""
from __future__ import annotations

import random
from datetime import datetime

import pandas as pd

from data.infrastructure import AD, AZURE, LINUX, NETWORK, SQL, WINDOWS, sync_ad_metrics  # noqa: F401
from engine.detection import detect_all, health_from_alerts
from utils.helpers import format_timestamp, health_label, prettify

METRIC_LABELS = {
    "cpu": "CPU %", "memory": "Memory %", "disk": "Disk %",
    "service_status": "Service Status", "log_errors": "Log Errors",
    "app_response_sec": "App Response (s)", "sql_conn_failures": "SQL Conn Failures (app side)",
    "event_errors": "Event Errors", "account_lockouts": "Account Lockouts",
    "locked_accounts": "Locked Accounts", "password_reset_requests": "Password Reset Requests",
    "access_issues": "Access Issues", "db_status": "Database Status",
    "blocking_sessions": "Blocking Sessions", "connection_failures": "Connection Failures",
    "log_space_pct": "Log Space Used %", "backup_status": "Backup Status",
    "ping": "Ping", "dns": "DNS", "tcp_connectivity": "TCP Connectivity",
    "packet_loss_pct": "Packet Loss %", "latency_ms": "Latency (ms)",
    "vm_status": "VM Status", "network_mbps": "Network (Mbps)", "active_alerts": "Active Alerts",
}


def metric_label(metric: str) -> str:
    if metric.startswith("user:"):
        return f"Account status ({metric[5:]})"
    return METRIC_LABELS.get(metric, prettify(metric))


def read_metric(component: dict, metric: str):
    """Read a metric; 'user:<name>' reads an AD account status."""
    if metric.startswith("user:"):
        name = metric[5:]
        for user in component["details"].get("users", []):
            if user["user"] == name:
                return user["status"]
        return "UNKNOWN"
    return component["metrics"].get(metric)


def jitter_metrics(components: list[dict], rng: random.Random) -> None:
    """Apply small random changes to healthy-range metrics (simulated polling).

    Values that are already high (a fault is active) are left alone so the
    simulated fault does not disappear by accident.
    """
    for c in components:
        m = c["metrics"]
        for key in ("cpu", "memory"):
            if isinstance(m.get(key), (int, float)) and m[key] < 70:
                m[key] = round(min(75, max(5, m[key] + rng.uniform(-4, 4))), 1)
        if isinstance(m.get("latency_ms"), (int, float)) and m["latency_ms"] < 100:
            m["latency_ms"] = round(min(120, max(2, m["latency_ms"] + rng.uniform(-3, 3))), 1)
        if isinstance(m.get("network_mbps"), (int, float)):
            m["network_mbps"] = round(min(400, max(5, m["network_mbps"] + rng.uniform(-10, 10))), 1)


def history_rows(components: list[dict], ts: datetime) -> list[dict]:
    """One row per component for the trend charts."""
    rows = []
    for c in components:
        m = c["metrics"]
        if any(k in m for k in ("cpu", "memory", "disk", "latency_ms")):
            rows.append({"Time": ts, "Component": c["name"], "Type": c["type"],
                         "cpu": m.get("cpu"), "memory": m.get("memory"),
                         "disk": m.get("disk"), "latency_ms": m.get("latency_ms")})
    return rows


def chart_dataframe(components: list[dict], metric: str) -> pd.DataFrame:
    rows = [{"Component": c["name"], "Type": c["type"], "Value": c["metrics"][metric]}
            for c in components if isinstance(c["metrics"].get(metric), (int, float))]
    return pd.DataFrame(rows, columns=["Component", "Type", "Value"])


def metrics_dataframe(components: list[dict], component_type: str, health: dict[str, str]) -> pd.DataFrame:
    """Metric table for one component type."""
    rows = []
    for c in components:
        if c["type"] != component_type:
            continue
        row = {"Component": c["name"]}
        row.update({metric_label(k): v for k, v in c["metrics"].items()})
        row["Health"] = health_label(health.get(c["name"], "Healthy"))
        rows.append(row)
    return pd.DataFrame(rows)


def inventory_dataframe(components: list[dict], alerts: list) -> pd.DataFrame:
    by_component: dict[str, list] = {}
    for a in alerts:
        by_component.setdefault(a.component, []).append(a)
    rows = []
    for c in components:
        comp_alerts = by_component.get(c["name"], [])
        rows.append({
            "Component": c["name"], "Type": c["type"], "Role": c["role"],
            "Health": health_label(health_from_alerts(comp_alerts)),
            "Active Alerts": len(comp_alerts), "Last Check": format_timestamp(c.get("last_check")),
        })
    return pd.DataFrame(rows)


def network_decision_tree(component: dict) -> dict:
    """Simulated troubleshooting tree: Ping -> DNS -> TCP.

    The first failing step is reported as the probable failure point.
    """
    m, d = component["metrics"], component["details"]
    target, port = d.get("target", "SQL-01"), d.get("port", 1433)
    plan = [
        ("Ping", f"ping {target}", "ping", "Network reachability (ICMP)"),
        ("DNS", f"nslookup {target}", "dns", "DNS resolution"),
        ("TCP", f"Test-NetConnection {target} -Port {port}", "tcp_connectivity", "TCP port connectivity"),
    ]
    steps, failure = [], None
    for name, command, metric, label in plan:
        if failure:
            steps.append({"Step": name, "Command": command, "Result": "SKIPPED",
                          "Meaning": "Not tested because an earlier step failed"})
            continue
        ok = m.get(metric) == "OK"
        steps.append({"Step": name, "Command": command, "Result": "PASS" if ok else "FAIL",
                      "Meaning": f"{label} is working" if ok else f"{label} is NOT working"})
        if not ok:
            failure = label
    return {"steps": steps, "failure_point": failure}
