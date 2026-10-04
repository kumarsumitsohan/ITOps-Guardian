"""Simulated enterprise infrastructure.

Every component is a plain dictionary:

    {"name": "APP-LNX-01", "type": "Linux", "role": "...",
     "metrics": {...}, "details": {...}, "last_check": datetime | None}

All numbers are SIMULATED. Nothing here talks to a real system.
"""
from __future__ import annotations

LINUX = "Linux"
WINDOWS = "Windows"
AD = "Active Directory"
SQL = "SQL Server"
NETWORK = "Network"
AZURE = "Azure VM"

COMPONENT_TYPES = [LINUX, WINDOWS, AD, SQL, NETWORK, AZURE]

# Values a metric returns to once its problem is fixed (used by remediation).
HEALTHY_VALUES = {
    "cpu": 40,
    "memory": 55,
    "disk": 60,
    "service_status": "RUNNING",
    "log_errors": "LOW",
    "app_response_sec": 0.8,
    "sql_conn_failures": 1,
    "connection_failures": 2,
    "event_errors": 3,
    "access_issues": 0,
    "blocking_sessions": 0,
    "db_status": "ONLINE",
    "log_space_pct": 40,
    "backup_status": "SUCCESS",
    "ping": "OK",
    "dns": "OK",
    "tcp_connectivity": "OK",
    "packet_loss_pct": 0.5,
    "latency_ms": 15,
    "vm_status": "RUNNING",
    "active_alerts": 0,
}


def _linux(name: str, role: str, cpu: float, memory: float, disk: float,
           service: str, response: float) -> dict:
    return {
        "name": name, "type": LINUX, "role": role, "last_check": None,
        "metrics": {
            "cpu": cpu, "memory": memory, "disk": disk,
            "service_status": "RUNNING", "log_errors": "LOW",
            "app_response_sec": response, "sql_conn_failures": 1,
        },
        "details": {"service_name": service},
    }


def _windows(name: str, role: str, cpu: float, memory: float, disk: float,
             service: str) -> dict:
    return {
        "name": name, "type": WINDOWS, "role": role, "last_check": None,
        "metrics": {
            "cpu": cpu, "memory": memory, "disk": disk,
            "service_status": "RUNNING", "event_errors": 3,
        },
        "details": {"service_name": service},
    }


def _ad_user(user: str, groups: list[str]) -> dict:
    return {
        "user": user, "status": "ACTIVE", "groups": groups,
        "lockout_count": 0, "lockout_source": "", "source_share_pct": 0,
    }


def _sql(name: str, role: str, log_space: float, databases: list[str]) -> dict:
    return {
        "name": name, "type": SQL, "role": role, "last_check": None,
        "metrics": {
            "db_status": "ONLINE", "blocking_sessions": 0,
            "connection_failures": 2, "log_space_pct": log_space,
            "backup_status": "SUCCESS",
        },
        "details": {"databases": databases, "blocker": None},
    }


def _network(name: str, role: str, latency: float, target: str) -> dict:
    return {
        "name": name, "type": NETWORK, "role": role, "last_check": None,
        "metrics": {
            "ping": "OK", "dns": "OK", "tcp_connectivity": "OK",
            "packet_loss_pct": 0.5, "latency_ms": latency,
        },
        "details": {"target": target, "port": 1433},
    }


def _azure(name: str, role: str, cpu: float, memory: float, mbps: float) -> dict:
    return {
        "name": name, "type": AZURE, "role": role, "last_check": None,
        "metrics": {
            "vm_status": "RUNNING", "cpu": cpu, "memory": memory,
            "network_mbps": mbps, "active_alerts": 0,
        },
        "details": {"region": "simulated-region"},
    }


def sync_ad_metrics(component: dict) -> None:
    """Recalculate AD summary metrics from the user list."""
    users = component["details"]["users"]
    component["metrics"]["locked_accounts"] = sum(u["status"] == "LOCKED" for u in users)
    component["metrics"]["account_lockouts"] = sum(u["lockout_count"] for u in users)


def build_infrastructure() -> list[dict]:
    """Create a fresh, healthy simulated environment (12 components)."""
    ad = {
        "name": "AD-01", "type": AD, "role": "Domain controller", "last_check": None,
        "metrics": {"password_reset_requests": 2, "access_issues": 0},
        "details": {"users": [
            _ad_user("user01", ["Domain Users", "App-Users"]),
            _ad_user("user02", ["Domain Users", "HR-Share"]),
            _ad_user("user03", ["Domain Users", "App-Users", "VPN-Users"]),
            _ad_user("user04", ["Domain Users", "IT-Support"]),
            _ad_user("user05", ["Domain Users", "Finance-Share"]),
            _ad_user("user06", ["Domain Users", "VPN-Users"]),
        ]},
    }
    sync_ad_metrics(ad)

    return [
        _linux("APP-LNX-01", "Application server", 42, 58, 55, "app-service", 0.8),
        _linux("WEB-LNX-01", "Web server", 30, 47, 48, "web-service", 0.5),
        _linux("DB-LNX-01", "Database host (Linux)", 55, 66, 62, "db-service", 0.9),
        _windows("WIN-SRV-01", "Windows application server", 38, 52, 57, "Windows Application Service"),
        _windows("WIN-SRV-02", "Windows file server", 25, 44, 63, "File Services"),
        ad,
        _sql("SQL-01", "Primary SQL Server", 45, ["AppDB", "OrdersDB"]),
        _sql("SQL-02", "Reporting SQL Server", 38, ["ReportingDB"]),
        _network("CORE-SW-01", "Core switch", 8, "APP-NET-01"),
        _network("APP-NET-01", "Application network segment", 12, "SQL-01"),
        _azure("AZ-VM-01", "Azure application VM", 35, 52, 120),
        _azure("AZ-VM-02", "Azure utility VM", 28, 44, 80),
    ]


def get_component(components: list[dict], name: str) -> dict:
    """Find a component by name or raise KeyError."""
    for component in components:
        if component["name"] == name:
            return component
    raise KeyError(f"Unknown component: {name}")
