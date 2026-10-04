"""REMEDIATE + VERIFY: safe, SIMULATED fixes with before/after, verification and audit.

Nothing here touches a real system. Every action only changes the in-memory
simulated environment. SQL blocking is NEVER fixed automatically: the session is
not terminated, the incident is escalated to a DBA instead.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from data.infrastructure import HEALTHY_VALUES, get_component, sync_ad_metrics
from engine.correlation import SYMPTOM_CATEGORIES
from engine.detection import detect_component
from engine.monitoring import metric_label, read_metric

ACTOR_AUTOMATION = "ITOps Guardian (simulated automation)"
ACTOR_DBA = "DBA (simulated)"


@dataclass(frozen=True)
class RemediationAction:
    key: str
    label: str
    recommendation: str
    automatic: bool                 # False -> human escalation only
    simulated_minutes: int          # simulated time the fix takes
    steps: tuple                    # what an engineer would do (shown in the UI)
    effect: Callable | None = None  # changes the simulated component


# ------------------------------------------------------------- effects ----
def recover_metric(component: dict, metric: str) -> None:
    """Return a metric to its healthy value."""
    if metric in HEALTHY_VALUES:
        component["metrics"][metric] = HEALTHY_VALUES[metric]


def _fx_log_cleanup(component, alerts):
    before = component["metrics"]["disk"]
    component["metrics"]["disk"] = 61 if before > 61 else before
    return [f"Disk usage reduced from {before}% to {component['metrics']['disk']}% (simulated)"]


def _fx_windows_disk(component, alerts):
    before = component["metrics"]["disk"]
    component["metrics"]["disk"] = 58 if before > 58 else before
    return [f"Disk usage reduced from {before}% to {component['metrics']['disk']}% (simulated)"]


def _fx_service_restart(component, alerts):
    component["metrics"]["service_status"] = "RUNNING"
    return [f"{component['details'].get('service_name', 'Service')} restarted (simulated)"]


def _fx_cpu(component, alerts):
    component["metrics"]["cpu"] = 45
    return ["Heavy process restarted; CPU back to normal range (simulated)"]


def _fx_memory(component, alerts):
    component["metrics"]["memory"] = 55
    return ["Memory released; usage back to normal range (simulated)"]


def _fx_ad_unlock(component, alerts):
    names = {a.subject for a in alerts if a.subject}
    notes = []
    for user in component["details"]["users"]:
        if user["status"] == "LOCKED" and (not names or user["user"] in names):
            source = user["lockout_source"] or "unknown source"
            user["status"], user["lockout_count"] = "ACTIVE", 0
            notes.append(f"{user['user']} unlocked. Stale credentials on {source} must also be updated "
                         "so the account does not lock again (simulated)")
    sync_ad_metrics(component)
    return notes


def _fx_network(component, alerts):
    m, notes = component["metrics"], []
    if m.get("ping") != "OK":
        m["ping"] = "OK"
        notes.append("Ping: interface and route checked, link restored (simulated)")
    if m.get("dns") != "OK":
        m["dns"] = "OK"
        notes.append("DNS: resolver cache flushed and DNS server entry corrected (simulated)")
    if m.get("tcp_connectivity") != "OK":
        m["tcp_connectivity"] = "OK"
        notes.append("TCP: firewall/port rule reviewed and corrected (simulated)")
    for metric in ("packet_loss_pct", "latency_ms"):
        if any(a.metric == metric for a in alerts):
            recover_metric(component, metric)
            notes.append(f"{metric_label(metric)} back to normal (simulated)")
    return notes


def _fx_azure(component, alerts):
    m, notes = component["metrics"], []
    m["active_alerts"] = 0
    notes.append("Alert acknowledged in the simulated Azure portal")
    if m["cpu"] > 85:
        m["cpu"] = 40
        notes.append("Runaway workload stopped / VM load reduced; CPU back to normal (simulated)")
    if m["memory"] > 90:
        m["memory"] = 55
    return notes


def _fx_azure_start(component, alerts):
    component["metrics"]["vm_status"] = "RUNNING"
    component["metrics"]["cpu"] = 30
    return ["VM started (simulated)"]


def _fx_log_backup(component, alerts):
    component["metrics"]["log_space_pct"] = 40
    return ["Transaction log backup completed; log space released (simulated)"]


def _fx_rerun_backup(component, alerts):
    component["metrics"]["backup_status"] = "SUCCESS"
    return ["Backup job re-run successfully (simulated)"]


def _fx_investigate(component, alerts):
    for alert in alerts:
        recover_metric(component, alert.metric)
    return ["Cause investigated and cleared (simulated)"]


ACTIONS: dict[str, RemediationAction] = {a.key: a for a in [
    RemediationAction(
        "linux_log_cleanup", "Simulated log cleanup / log rotation",
        "Perform log cleanup / log rotation, then verify disk usage.", True, 25,
        ("df -h  (confirm which filesystem is full)", "du -sh /var/log/* | sort -h  (find large logs)",
         "Rotate and compress old logs (logrotate)", "Archive or delete logs older than the retention period",
         "df -h  (verify disk usage)"), _fx_log_cleanup),
    RemediationAction(
        "windows_disk_cleanup", "Simulated disk cleanup",
        "Clean temporary files and old logs, then verify free disk space.", True, 20,
        ("Check drive usage in Explorer / Get-PSDrive", "Clear temp files and old logs", "Verify free space"),
        _fx_windows_disk),
    RemediationAction(
        "service_restart", "Simulated service restart",
        "Restart the stopped service, then verify it is RUNNING.", True, 10,
        ("Get-Service  (confirm STOPPED)", "Check Event Viewer for the reason", "Check service dependencies",
         "Restart-Service  (simulated)", "Get-Service  (verify RUNNING)"), _fx_service_restart),
    RemediationAction(
        "reduce_cpu_load", "Simulated high-CPU remediation",
        "Identify the top CPU process and restart or tune it, then verify CPU.", True, 15,
        ("Identify top CPU process", "Restart or tune the process (simulated)", "Verify CPU"), _fx_cpu),
    RemediationAction(
        "reduce_memory", "Simulated memory remediation",
        "Identify the memory-heavy process and restart it, then verify memory.", True, 15,
        ("Identify top memory process", "Restart process (simulated)", "Verify memory"), _fx_memory),
    RemediationAction(
        "ad_unlock_account", "Simulated account unlock",
        "Unlock the account, update stale credentials on the source device (reset password if required), "
        "then verify the account is ACTIVE.", True, 15,
        ("Identify lockout source (DC security event 4740)", "Check for stale credentials on the source",
         "Unlock-ADAccount  (simulated)", "Reset password if required", "Verify account status = ACTIVE"),
        _fx_ad_unlock),
    RemediationAction(
        "network_troubleshoot", "Simulated network troubleshooting",
        "Follow Ping -> DNS -> TCP, fix the failing step, then verify connectivity.", True, 30,
        ("ping target", "nslookup target", "Test-NetConnection target -Port 1433",
         "Fix the first failing step (simulated)", "Re-run the three checks to verify"), _fx_network),
    RemediationAction(
        "azure_ack_recover", "Simulated alert acknowledgement and recovery",
        "Acknowledge the alert, investigate the workload, recover the VM, then verify CPU is normal.", True, 20,
        ("Acknowledge alert in the portal", "Check VM CPU/memory metrics", "Identify the heavy workload",
         "Recover the VM (simulated)", "Verify CPU is normal"), _fx_azure),
    RemediationAction(
        "azure_start_vm", "Simulated VM start",
        "Start the VM and verify it is RUNNING.", True, 10,
        ("Check VM status", "Start VM (simulated)", "Verify RUNNING"), _fx_azure_start),
    RemediationAction(
        "sql_log_backup", "Simulated transaction log backup",
        "Take a transaction log backup, then verify log space.", True, 20,
        ("Check log space", "Run log backup (simulated)", "Verify log space"), _fx_log_backup),
    RemediationAction(
        "sql_rerun_backup", "Simulated backup re-run",
        "Check the backup job error, re-run the backup, then verify status.", True, 30,
        ("Check job history", "Re-run backup (simulated)", "Verify status = SUCCESS"), _fx_rerun_backup),
    RemediationAction(
        "investigate_symptoms", "Simulated investigation and clean-up",
        "Investigate the logs and the application, fix the cause, then verify the metric.", True, 20,
        ("Review logs", "Identify the cause", "Apply a fix (simulated)", "Verify the metric"), _fx_investigate),
    RemediationAction(
        "sql_dba_escalation", "Escalate to DBA (no automatic session termination)",
        "Document the blocker and affected query, then escalate to the DBA. Do NOT terminate sessions automatically.",
        False, 45,
        ("Identify the blocking session", "Identify the blocked query", "Check database health",
         "Document findings", "Escalate to DBA on-call (simulated ticket)"), None),
]}


def get_action(key: str) -> RemediationAction:
    try:
        return ACTIONS[key]
    except KeyError:
        raise ValueError(f"Unknown remediation action: {key}") from None


# ------------------------------------------------------ snapshots / verify ----
def _watch_pairs(incident, action_primary_metrics=()) -> list[tuple[str, str]]:
    """(component, metric) pairs worth showing before/after."""
    pairs: list[tuple[str, str]] = []
    for alert in incident.alerts:
        pairs.append((alert.component, alert.metric))
        if alert.subject:
            pairs.append((alert.component, f"user:{alert.subject}"))
    return list(dict.fromkeys(pairs))


def snapshot(components: list[dict], pairs: list[tuple[str, str]]) -> dict:
    return {(name, metric): read_metric(get_component(components, name), metric) for name, metric in pairs}


def verify_incident(components: list[dict], incident, now: datetime) -> dict:
    """Re-run detection: every alert of the incident must be gone."""
    still_present: set[str] = set()
    for name in dict.fromkeys(a.component for a in incident.alerts):
        still_present.update(a.key for a in detect_component(get_component(components, name), now))
    checks, passed = [], True
    for alert in incident.alerts:
        component = get_component(components, alert.component)
        metric = f"user:{alert.subject}" if alert.subject else alert.metric
        present = alert.key in still_present
        passed = passed and not present
        checks.append({"Check": f"{alert.category} on {alert.component}", "Metric": metric_label(metric),
                       "Current Value": read_metric(component, metric),
                       "Result": "FAIL" if present else "PASS"})
    return {"passed": passed, "checks": checks, "verified_at": now}


def _recover_symptoms(components: list[dict], incident) -> None:
    """After the root cause is fixed, symptom metrics return to normal too."""
    for alert in incident.alerts:
        if alert.category in SYMPTOM_CATEGORIES:
            recover_metric(get_component(components, alert.component), alert.metric)


def _audit(now, incident, actor, component, action, outcome) -> dict:
    return {"Timestamp": now.strftime("%Y-%m-%d %H:%M:%S"), "Incident ID": incident.incident_id,
            "Actor": actor, "Component": component, "Action": action, "Outcome": outcome}


def _changes(before: dict, after: dict) -> list[dict]:
    return [{"Component": name, "Metric": metric_label(metric), "Before": before[(name, metric)],
             "After": after[(name, metric)]} for (name, metric) in before]


# ------------------------------------------------------------ entry points ----
def execute_remediation(components: list[dict], incident, now: datetime) -> dict:
    """Run the incident's simulated remediation: Before -> Action -> After -> Verify -> Audit."""
    action = get_action(incident.action_key)
    if not action.automatic or action.effect is None:
        raise ValueError(f"'{action.label}' is not automatic. Use escalation instead.")

    pairs = _watch_pairs(incident)
    before = snapshot(components, pairs)

    primary = get_component(components, incident.component)
    notes = action.effect(primary, incident.alerts_for(primary["name"]))
    _recover_symptoms(components, incident)

    after = snapshot(components, pairs)
    verification = verify_incident(components, incident, now)
    outcome = "Verified - condition cleared" if verification["passed"] else "Verification FAILED"
    return {
        "incident_id": incident.incident_id, "action_key": action.key, "action_label": action.label,
        "actor": ACTOR_AUTOMATION, "timestamp": now, "steps": list(action.steps), "notes": notes,
        "changes": _changes(before, after), "verification": verification,
        "passed": verification["passed"], "simulated_minutes": action.simulated_minutes,
        "audit": _audit(now, incident, ACTOR_AUTOMATION, incident.component, action.label, outcome),
    }


def escalate_incident(incident, now: datetime) -> dict:
    """Escalate to a human (used for SQL blocking). Changes NOTHING in the environment."""
    action = get_action(incident.action_key)
    label = "Escalated to DBA - sessions NOT terminated automatically"
    return {
        "incident_id": incident.incident_id, "action_key": action.key, "action_label": label,
        "actor": ACTOR_AUTOMATION, "timestamp": now, "steps": list(action.steps),
        "notes": ["No session was killed. The blocker and blocked query are documented for the DBA."],
        "changes": [], "verification": {"passed": None, "checks": [], "verified_at": now,
                                        "note": "Pending: verification happens after the DBA acts."},
        "passed": None, "simulated_minutes": 0,
        "audit": _audit(now, incident, ACTOR_AUTOMATION, incident.component, label, "Awaiting DBA"),
    }


def simulate_dba_resolution(components: list[dict], incident, now: datetime) -> dict:
    """Simulate the DBA clearing the problem (done by a human, not by this tool)."""
    pairs = _watch_pairs(incident)
    before = snapshot(components, pairs)
    for alert in incident.alerts:
        component = get_component(components, alert.component)
        recover_metric(component, alert.metric)
        if alert.metric == "blocking_sessions":
            component["details"]["blocker"] = None
    after = snapshot(components, pairs)
    verification = verify_incident(components, incident, now)
    label = "DBA resolved the problem (simulated external action)"
    outcome = "Verified - condition cleared" if verification["passed"] else "Verification FAILED"
    return {
        "incident_id": incident.incident_id, "action_key": incident.action_key, "action_label": label,
        "actor": ACTOR_DBA, "timestamp": now,
        "steps": ["DBA reviewed the blocking session and the business process behind it",
                  "DBA decided how to release the blocker (outside this tool)"],
        "notes": [], "changes": _changes(before, after), "verification": verification,
        "passed": verification["passed"], "simulated_minutes": 45,
        "audit": _audit(now, incident, ACTOR_DBA, incident.component, label, outcome),
    }
