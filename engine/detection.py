"""DETECT: turn raw (simulated) metrics into alerts using simple thresholds."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from data.infrastructure import AD, AZURE, LINUX, NETWORK, SQL, WINDOWS

WARNING = "WARNING"
CRITICAL = "CRITICAL"

THRESHOLDS = {
    "cpu_warning": 85,        # CPU > 85%  -> HIGH CPU
    "cpu_critical": 95,
    "memory_warning": 90,
    "disk_warning": 80,
    "disk_critical": 90,      # Disk > 90% -> CRITICAL DISK
    "app_response_sec": 3.0,
    "sql_conn_failures": 20,
    "event_errors": 25,
    "account_lockouts": 3,    # lockouts per user above this -> ACCOUNT LOCKOUT ISSUE
    "access_issues": 5,
    "log_space_pct": 85,
    "log_space_critical": 95,
    "packet_loss_pct": 10,    # Packet loss > 10% -> NETWORK ISSUE
    "packet_loss_critical": 30,
    "latency_ms": 150,
}


@dataclass
class Alert:
    """One threshold breach on one component."""

    component: str
    component_type: str
    category: str          # e.g. "CRITICAL DISK"
    severity: str          # WARNING or CRITICAL
    metric: str
    value: object
    threshold: object
    message: str
    timestamp: datetime
    subject: str = ""      # extra identity, e.g. the AD user name
    details: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable identity used to check whether an alert is still present."""
        return ":".join(part for part in (self.component, self.category, self.subject) if part)


def _alert(component: dict, now: datetime, category: str, severity: str,
           metric: str, value, threshold, message: str,
           subject: str = "", details: dict | None = None) -> Alert:
    return Alert(
        component=component["name"], component_type=component["type"],
        category=category, severity=severity, metric=metric, value=value,
        threshold=threshold, message=message, timestamp=now,
        subject=subject, details=details or {},
    )


def _detect_server(c: dict, now: datetime) -> list[Alert]:
    """Rules shared by Linux and Windows servers."""
    m, t, alerts = c["metrics"], THRESHOLDS, []

    cpu = m.get("cpu", 0)
    if cpu > t["cpu_critical"]:
        alerts.append(_alert(c, now, "HIGH CPU", CRITICAL, "cpu", cpu, t["cpu_warning"],
                             f"CPU at {cpu}% (limit {t['cpu_warning']}%)"))
    elif cpu > t["cpu_warning"]:
        alerts.append(_alert(c, now, "HIGH CPU", WARNING, "cpu", cpu, t["cpu_warning"],
                             f"CPU at {cpu}% (limit {t['cpu_warning']}%)"))

    memory = m.get("memory", 0)
    if memory > t["memory_warning"]:
        alerts.append(_alert(c, now, "HIGH MEMORY", WARNING, "memory", memory, t["memory_warning"],
                             f"Memory at {memory}% (limit {t['memory_warning']}%)"))

    disk = m.get("disk", 0)
    if disk > t["disk_critical"]:
        alerts.append(_alert(c, now, "CRITICAL DISK", CRITICAL, "disk", disk, t["disk_critical"],
                             f"Disk at {disk}% (critical limit {t['disk_critical']}%)"))
    elif disk > t["disk_warning"]:
        alerts.append(_alert(c, now, "DISK WARNING", WARNING, "disk", disk, t["disk_warning"],
                             f"Disk at {disk}% (warning limit {t['disk_warning']}%)"))

    if m.get("service_status", "RUNNING") != "RUNNING":
        service = c["details"].get("service_name", "service")
        alerts.append(_alert(c, now, "SERVICE FAILURE", CRITICAL, "service_status",
                             m["service_status"], "RUNNING", f"{service} is {m['service_status']}"))
    return alerts


def _detect_linux(c: dict, now: datetime) -> list[Alert]:
    m, t = c["metrics"], THRESHOLDS
    alerts = _detect_server(c, now)
    if m.get("log_errors") == "HIGH":
        alerts.append(_alert(c, now, "HIGH LOG ERRORS", WARNING, "log_errors", "HIGH", "LOW/MEDIUM",
                             "Application log error rate is HIGH"))
    if m.get("app_response_sec", 0) > t["app_response_sec"]:
        alerts.append(_alert(c, now, "SLOW APPLICATION RESPONSE", WARNING, "app_response_sec",
                             m["app_response_sec"], t["app_response_sec"],
                             f"Application response {m['app_response_sec']} s (limit {t['app_response_sec']} s)"))
    if m.get("sql_conn_failures", 0) > t["sql_conn_failures"]:
        alerts.append(_alert(c, now, "SQL CONNECTION FAILURES", WARNING, "sql_conn_failures",
                             m["sql_conn_failures"], t["sql_conn_failures"],
                             f"{m['sql_conn_failures']} SQL connection failures seen by the application"))
    return alerts


def _detect_windows(c: dict, now: datetime) -> list[Alert]:
    m, t = c["metrics"], THRESHOLDS
    alerts = _detect_server(c, now)
    if m.get("event_errors", 0) > t["event_errors"]:
        alerts.append(_alert(c, now, "HIGH EVENT ERRORS", WARNING, "event_errors",
                             m["event_errors"], t["event_errors"],
                             f"{m['event_errors']} Event Log errors (limit {t['event_errors']})"))
    return alerts


def _detect_ad(c: dict, now: datetime) -> list[Alert]:
    t, alerts = THRESHOLDS, []
    for user in c["details"].get("users", []):
        if user["status"] == "LOCKED" and user["lockout_count"] > t["account_lockouts"]:
            alerts.append(_alert(
                c, now, "ACCOUNT LOCKOUT ISSUE", WARNING, "account_lockouts",
                user["lockout_count"], t["account_lockouts"],
                f"{user['user']} is LOCKED after {user['lockout_count']} lockouts",
                subject=user["user"],
                details={"user": user["user"], "lockout_count": user["lockout_count"],
                         "lockout_source": user["lockout_source"],
                         "source_share_pct": user["source_share_pct"]}))
    if c["metrics"].get("access_issues", 0) > t["access_issues"]:
        alerts.append(_alert(c, now, "ACCESS ISSUE", WARNING, "access_issues",
                             c["metrics"]["access_issues"], t["access_issues"],
                             "Multiple access-denied reports"))
    return alerts


def _detect_sql(c: dict, now: datetime) -> list[Alert]:
    m, t, alerts = c["metrics"], THRESHOLDS, []
    if m.get("db_status", "ONLINE") != "ONLINE":
        alerts.append(_alert(c, now, "DATABASE OFFLINE", CRITICAL, "db_status", m["db_status"], "ONLINE",
                             f"Database status is {m['db_status']}"))
    if m.get("blocking_sessions", 0) > 0:
        alerts.append(_alert(c, now, "DATABASE PERFORMANCE ISSUE", WARNING, "blocking_sessions",
                             m["blocking_sessions"], 0,
                             f"{m['blocking_sessions']} blocked session(s) detected"))
    if m.get("connection_failures", 0) > t["sql_conn_failures"]:
        alerts.append(_alert(c, now, "SQL CONNECTION FAILURES", WARNING, "connection_failures",
                             m["connection_failures"], t["sql_conn_failures"],
                             f"{m['connection_failures']} connection failures"))
    log_space = m.get("log_space_pct", 0)
    if log_space > t["log_space_pct"]:
        severity = CRITICAL if log_space > t["log_space_critical"] else WARNING
        alerts.append(_alert(c, now, "SQL LOG SPACE LOW", severity, "log_space_pct", log_space,
                             t["log_space_pct"], f"Transaction log {log_space}% full"))
    if m.get("backup_status", "SUCCESS") != "SUCCESS":
        alerts.append(_alert(c, now, "BACKUP FAILURE", WARNING, "backup_status", m["backup_status"],
                             "SUCCESS", f"Last backup status: {m['backup_status']}"))
    return alerts


def _detect_network(c: dict, now: datetime) -> list[Alert]:
    m, t, alerts = c["metrics"], THRESHOLDS, []
    if m.get("ping", "OK") != "OK":
        alerts.append(_alert(c, now, "NETWORK UNREACHABLE", CRITICAL, "ping", m["ping"], "OK",
                             "Ping failed"))
    if m.get("dns", "OK") != "OK":
        alerts.append(_alert(c, now, "DNS FAILURE", CRITICAL, "dns", m["dns"], "OK",
                             "DNS resolution failed"))
    if m.get("tcp_connectivity", "OK") != "OK":
        alerts.append(_alert(c, now, "TCP CONNECTIVITY FAILURE", CRITICAL, "tcp_connectivity",
                             m["tcp_connectivity"], "OK", "TCP connection to the database port failed"))
    loss = m.get("packet_loss_pct", 0)
    if loss > t["packet_loss_pct"]:
        severity = CRITICAL if loss > t["packet_loss_critical"] else WARNING
        alerts.append(_alert(c, now, "NETWORK ISSUE", severity, "packet_loss_pct", loss,
                             t["packet_loss_pct"], f"Packet loss {loss}% (limit {t['packet_loss_pct']}%)"))
    if m.get("latency_ms", 0) > t["latency_ms"]:
        alerts.append(_alert(c, now, "HIGH LATENCY", WARNING, "latency_ms", m["latency_ms"],
                             t["latency_ms"], f"Latency {m['latency_ms']} ms (limit {t['latency_ms']} ms)"))
    return alerts


def _detect_azure(c: dict, now: datetime) -> list[Alert]:
    m, t, alerts = c["metrics"], THRESHOLDS, []
    if m.get("vm_status", "RUNNING") != "RUNNING":
        alerts.append(_alert(c, now, "AZURE VM DOWN", CRITICAL, "vm_status", m["vm_status"], "RUNNING",
                             f"VM status is {m['vm_status']}"))
    cpu = m.get("cpu", 0)
    if cpu > t["cpu_warning"]:
        severity = CRITICAL if cpu > t["cpu_critical"] else WARNING
        alerts.append(_alert(c, now, "AZURE PERFORMANCE ALERT", severity, "cpu", cpu, t["cpu_warning"],
                             f"VM CPU at {cpu}% (limit {t['cpu_warning']}%)"))
    memory = m.get("memory", 0)
    if memory > t["memory_warning"]:
        alerts.append(_alert(c, now, "HIGH MEMORY", WARNING, "memory", memory, t["memory_warning"],
                             f"VM memory at {memory}% (limit {t['memory_warning']}%)"))
    return alerts


_DETECTORS = {
    LINUX: _detect_linux, WINDOWS: _detect_windows, AD: _detect_ad,
    SQL: _detect_sql, NETWORK: _detect_network, AZURE: _detect_azure,
}


def detect_component(component: dict, now: datetime | None = None) -> list[Alert]:
    """Return all alerts for one component."""
    now = now or datetime.now()
    return _DETECTORS[component["type"]](component, now)


def detect_all(components: list[dict], now: datetime | None = None) -> list[Alert]:
    """Return all alerts for the whole environment."""
    now = now or datetime.now()
    alerts: list[Alert] = []
    for component in components:
        alerts.extend(detect_component(component, now))
    return alerts


def health_from_alerts(alerts: list[Alert]) -> str:
    """Healthy / Warning / Critical based on the worst alert severity."""
    if any(a.severity == CRITICAL for a in alerts):
        return "Critical"
    if alerts:
        return "Warning"
    return "Healthy"


def component_health(component: dict, now: datetime | None = None) -> str:
    return health_from_alerts(detect_component(component, now))
