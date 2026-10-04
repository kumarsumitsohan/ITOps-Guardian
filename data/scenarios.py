"""Demo scenarios. Each one injects a SIMULATED fault into the environment."""
from __future__ import annotations

from data.infrastructure import get_component, sync_ad_metrics


def _inject_disk(components, **_):
    get_component(components, "APP-LNX-01")["metrics"].update(
        disk=94, log_errors="HIGH", app_response_sec=4.8, sql_conn_failures=45)


def _inject_service(components, **_):
    get_component(components, "WIN-SRV-01")["metrics"].update(service_status="STOPPED", event_errors=40)


def _inject_lockout(components, **_):
    ad = get_component(components, "AD-01")
    for user in ad["details"]["users"]:
        if user["user"] == "user03":
            user.update(status="LOCKED", lockout_count=6,
                        lockout_source="WKSTN-114 (mapped drive using an old password)",
                        source_share_pct=93)
    sync_ad_metrics(ad)


def _inject_sql_blocking(components, **_):
    sql = get_component(components, "SQL-01")
    sql["metrics"].update(blocking_sessions=3, connection_failures=25)
    sql["details"]["blocker"] = {
        "blocker_session": 57, "blocker_login": "app_batch_user", "blocked_sessions": [61, 64, 70],
        "wait_seconds": 340, "database": "OrdersDB",
        "affected_query": "UPDATE Orders SET Status = 'Processed' WHERE BatchId = 1042",
    }


def _inject_network(components, variant="DNS", **_):
    net = get_component(components, "APP-NET-01")["metrics"]
    net.update(ping="OK", dns="OK", tcp_connectivity="OK")
    net[{"Ping": "ping", "DNS": "dns", "TCP": "tcp_connectivity"}[variant]] = "FAIL"
    get_component(components, "APP-LNX-01")["metrics"].update(sql_conn_failures=60, app_response_sec=6.2)


def _inject_azure(components, **_):
    get_component(components, "AZ-VM-01")["metrics"].update(cpu=92, active_alerts=1)


SCENARIOS = [
    {
        "id": "S1", "tab": "1 Linux Disk", "name": "Linux Disk Exhaustion",
        "summary": "APP-LNX-01 disk is nearly full and the application is slowing down.",
        "initial": "Disk 94%, log errors HIGH, application response 4.8 s, SQL connection failures HIGH.",
        "expected": {"problem": "Application Performance Degradation", "component": "APP-LNX-01",
                     "root_cause": "Linux Disk Exhaustion", "priority": "P2",
                     "ending": "Simulated log cleanup, disk 94% -> 61%, incident RESOLVED."},
        "inject": _inject_disk,
        "watch": [("APP-LNX-01", "disk"), ("APP-LNX-01", "log_errors"),
                  ("APP-LNX-01", "app_response_sec"), ("APP-LNX-01", "sql_conn_failures")],
        "talking_point": "Four alerts become ONE incident, and the disk is identified as the root cause.",
    },
    {
        "id": "S2", "tab": "2 Windows Service", "name": "Windows Service Failure",
        "summary": "The Windows application service on WIN-SRV-01 is stopped.",
        "initial": "Service STOPPED, Event Log errors high.",
        "expected": {"problem": "Windows Service Failure", "component": "WIN-SRV-01",
                     "root_cause": "Application service stopped", "priority": "P2",
                     "ending": "Simulated service restart, service RUNNING, incident RESOLVED."},
        "inject": _inject_service,
        "watch": [("WIN-SRV-01", "service_status"), ("WIN-SRV-01", "event_errors")],
        "talking_point": "Service failure plus Event Log errors on the same server are linked.",
    },
    {
        "id": "S3", "tab": "3 AD Lockout", "name": "Active Directory Lockout",
        "summary": "user03 is locked out repeatedly.",
        "initial": "user03 LOCKED after 6 lockouts, 93% of bad attempts from one workstation.",
        "expected": {"problem": "Repeated Account Lockout", "component": "AD-01",
                     "root_cause": "Probable stale credentials", "priority": "P3",
                     "ending": "Simulated unlock, account ACTIVE, incident RESOLVED."},
        "inject": _inject_lockout,
        "watch": [("AD-01", "user:user03"), ("AD-01", "account_lockouts"), ("AD-01", "locked_accounts")],
        "talking_point": "One source retrying an old password points to stale credentials, not an attack.",
    },
    {
        "id": "S4", "tab": "4 SQL Blocking", "name": "SQL Blocking",
        "summary": "A blocking session on SQL-01 is holding up other queries.",
        "initial": "3 blocked sessions, blocker SPID 57, 25 connection failures.",
        "expected": {"problem": "Database Performance Degradation", "component": "SQL-01",
                     "root_cause": "SQL blocking session", "priority": "P2",
                     "ending": "Escalated to DBA. The session is NOT terminated automatically."},
        "inject": _inject_sql_blocking,
        "escalation_only": True,
        "watch": [("SQL-01", "blocking_sessions"), ("SQL-01", "connection_failures")],
        "talking_point": "Controlled remediation: some fixes must be done by a human, so the tool escalates.",
    },
    {
        "id": "S5", "tab": "5 Network", "name": "Network Connectivity",
        "summary": "The application server cannot reach the database. Run the Ping -> DNS -> TCP decision tree.",
        "initial": "One network check fails and the application reports SQL connection failures.",
        "expected": {"problem": "Application Cannot Reach Database", "component": "APP-NET-01",
                     "root_cause": "Depends on the failure point you choose", "priority": "P1",
                     "ending": "Simulated troubleshooting, all three checks PASS, incident RESOLVED."},
        "inject": _inject_network,
        "options": {"variant": {"label": "Failure point to simulate", "choices": ["DNS", "TCP", "Ping"], "default": "DNS"}},
        "watch": [("APP-NET-01", "ping"), ("APP-NET-01", "dns"), ("APP-NET-01", "tcp_connectivity"),
                  ("APP-LNX-01", "sql_conn_failures"), ("APP-LNX-01", "app_response_sec")],
        "talking_point": "A decision tree finds the first failing step instead of guessing.",
    },
    {
        "id": "S6", "tab": "6 Azure VM", "name": "Azure VM CPU Alert",
        "summary": "AZ-VM-01 CPU is above the alert threshold.",
        "initial": "VM CPU 92%, one active alert.",
        "expected": {"problem": "Azure VM Performance Alert", "component": "AZ-VM-01",
                     "root_cause": "High CPU on Azure VM", "priority": "P3",
                     "ending": "Alert acknowledged, simulated recovery, CPU normal, incident RESOLVED."},
        "inject": _inject_azure,
        "watch": [("AZ-VM-01", "cpu"), ("AZ-VM-01", "active_alerts")],
        "talking_point": "Cloud monitoring concepts: thresholds, alert acknowledgement, recovery, verification.",
    },
]

SCENARIO_BY_ID = {s["id"]: s for s in SCENARIOS}


def get_scenario(scenario_id: str) -> dict:
    return SCENARIO_BY_ID[scenario_id]
