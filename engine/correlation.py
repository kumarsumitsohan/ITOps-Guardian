"""CORRELATE: group related alerts into ONE incident with a probable root cause.

This is RULE-BASED correlation (hand-written if/then rules). It is NOT machine
learning. Each rule looks for a known "trigger" alert plus supporting symptoms.
"""
from __future__ import annotations

from dataclasses import dataclass

from data.infrastructure import LINUX, NETWORK, SQL, WINDOWS
from engine.detection import CRITICAL, Alert

# Alerts that are usually SYMPTOMS of another problem rather than a cause.
SYMPTOM_CATEGORIES = {
    "HIGH LOG ERRORS", "SLOW APPLICATION RESPONSE",
    "SQL CONNECTION FAILURES", "HIGH EVENT ERRORS",
}

NETWORK_PATH_ORDER = ["NETWORK UNREACHABLE", "DNS FAILURE", "TCP CONNECTIVITY FAILURE"]
NETWORK_ROOT_CAUSES = {
    "NETWORK UNREACHABLE": "Network path failure (ping / ICMP unreachable)",
    "DNS FAILURE": "DNS resolution failure",
    "TCP CONNECTIVITY FAILURE": "TCP connectivity failure to the database port",
}


@dataclass(frozen=True)
class Template:
    """Default incident wording for a single, uncorrelated alert."""

    title: str
    root_cause: str
    action_key: object        # str, or {component_type: str, "default": str}
    impact: str
    urgency: str
    impact_reason: str
    urgency_reason: str
    kb_id: object = ""


def _t(title, root, action, impact, urgency, impact_reason, urgency_reason, kb=""):
    return Template(title, root, action, impact, urgency, impact_reason, urgency_reason, kb)


_DISK_ACTION = {LINUX: "linux_log_cleanup", WINDOWS: "windows_disk_cleanup", "default": "linux_log_cleanup"}

ALERT_TEMPLATES: dict[str, Template] = {
    "CRITICAL DISK": _t("Critical Disk Usage", "Disk space exhaustion", _DISK_ACTION, "Medium", "Medium",
                        "Disk is nearly full on one server; services may start failing.",
                        "No outage yet, but the risk grows as the disk fills.",
                        {LINUX: "KB-LNX-DISK"}),
    "DISK WARNING": _t("Disk Usage Warning", "Disk filling up", _DISK_ACTION, "Low", "Medium",
                       "No service impact yet.", "Should be fixed before it becomes critical.",
                       {LINUX: "KB-LNX-DISK"}),
    "HIGH CPU": _t("High CPU Utilisation", "Sustained high CPU load", "reduce_cpu_load", "Medium", "Medium",
                   "Server is slower than normal.", "Needs attention during working hours."),
    "HIGH MEMORY": _t("High Memory Utilisation", "Memory pressure",
                      {"Azure VM": "azure_ack_recover", "default": "reduce_memory"}, "Medium", "Medium",
                      "Server may start swapping and slow down.", "Needs attention during working hours."),
    "SERVICE FAILURE": _t("Service Failure", "Service stopped", "service_restart", "Medium", "High",
                          "A service is unavailable on one server.",
                          "Users of that service are affected right now.",
                          {WINDOWS: "KB-WIN-SVC"}),
    "HIGH LOG ERRORS": _t("High Application Log Errors", "Application errors (cause not identified)",
                          "investigate_symptoms", "Low", "Medium",
                          "Errors logged but service still works.", "Investigate before it worsens."),
    "SLOW APPLICATION RESPONSE": _t("Slow Application Response", "Application latency (cause not identified)",
                                    "investigate_symptoms", "Medium", "Medium",
                                    "Users experience slow responses.", "Needs investigation soon."),
    "SQL CONNECTION FAILURES": _t("SQL Connection Failures", "Database connectivity problem (cause not identified)",
                                  {SQL: "sql_dba_escalation", "default": "investigate_symptoms"},
                                  "Medium", "Medium",
                                  "Some database connections fail.", "Needs investigation soon."),
    "HIGH EVENT ERRORS": _t("High Windows Event Errors", "Repeated errors in the Windows Event Log",
                            "investigate_symptoms", "Low", "Medium",
                            "Errors logged but service still works.", "Investigate before it worsens.",
                            {WINDOWS: "KB-WIN-SVC"}),
    "ACCOUNT LOCKOUT ISSUE": _t("Repeated Account Lockout", "Repeated failed logons", "ad_unlock_account",
                                "Low", "High", "Single user affected.", "The user cannot work until unlocked.",
                                "KB-AD-LOCKOUT"),
    "ACCESS ISSUE": _t("Access Issues Reported", "Permission or group membership problem",
                       "investigate_symptoms", "Low", "Medium",
                       "A few users affected.", "Needs investigation."),
    "DATABASE PERFORMANCE ISSUE": _t("Database Blocking Detected", "SQL blocking session", "sql_dba_escalation",
                                     "Medium", "Medium", "Blocked queries wait for the blocker.",
                                     "Blocking can grow quickly; DBA should look soon.", "KB-SQL-BLOCKING"),
    "DATABASE OFFLINE": _t("Database Offline", "Database is not online", "sql_dba_escalation",
                           "High", "High", "Applications that use the database are down.",
                           "Complete outage for the database.", "KB-SQL-BLOCKING"),
    "SQL LOG SPACE LOW": _t("SQL Log Space Low", "Transaction log nearly full", "sql_log_backup",
                            "Medium", "Medium", "Writes may fail if the log fills.",
                            "Fix before the log is full."),
    "BACKUP FAILURE": _t("SQL Backup Failure", "Last backup failed", "sql_rerun_backup",
                         "Medium", "Medium", "Recovery point is at risk.", "Re-run within the working day."),
    "NETWORK UNREACHABLE": _t("Network Device Unreachable", "Ping failure", "network_troubleshoot",
                              "Medium", "High", "Devices behind this path may be cut off.",
                              "Connectivity is down now.", "KB-NET-CONN"),
    "DNS FAILURE": _t("DNS Resolution Failure", "DNS resolution failure", "network_troubleshoot",
                      "Medium", "High", "Name lookups fail.", "Connectivity by name is down now.", "KB-NET-CONN"),
    "TCP CONNECTIVITY FAILURE": _t("TCP Connectivity Failure", "TCP port not reachable", "network_troubleshoot",
                                   "Medium", "High", "Port-based services are unreachable.",
                                   "Connectivity is down now.", "KB-NET-CONN"),
    "NETWORK ISSUE": _t("Network Packet Loss", "Packet loss on the network path", "network_troubleshoot",
                        "Medium", "Medium", "Slow or unreliable connections.", "Needs investigation soon.",
                        "KB-NET-CONN"),
    "HIGH LATENCY": _t("High Network Latency", "Slow network path", "network_troubleshoot",
                       "Low", "Medium", "Applications feel slower.", "Investigate soon.", "KB-NET-CONN"),
    "AZURE PERFORMANCE ALERT": _t("Azure VM Performance Alert", "High CPU on Azure VM", "azure_ack_recover",
                                  "Medium", "Medium", "Performance degraded but the VM is still running.",
                                  "Investigate within the working day.", "KB-AZ-VM"),
    "AZURE VM DOWN": _t("Azure VM Not Running", "VM stopped or deallocated", "azure_start_vm",
                        "Medium", "High", "Workloads on the VM are unavailable.", "Outage is happening now.",
                        "KB-AZ-VM"),
}

_DEFAULT_TEMPLATE = _t("Infrastructure Alert", "Unknown", "investigate_symptoms", "Low", "Medium",
                       "Unknown impact.", "Needs triage.")


def _pick(value, component_type: str) -> str:
    """Pick a per-component-type value from either a string or a dict."""
    if isinstance(value, dict):
        return value.get(component_type, value.get("default", ""))
    return value


@dataclass
class CorrelatedGroup:
    """Several related alerts that become ONE incident."""

    title: str
    root_cause: str
    alerts: list           # alerts[0] is the probable root-cause alert
    confidence: str        # High / Medium / Low
    reasoning: str
    action_key: str
    impact: str
    urgency: str
    impact_reason: str
    urgency_reason: str
    rule: str
    kb_id: str = ""

    @property
    def primary(self) -> Alert:
        return self.alerts[0]

    @property
    def component(self) -> str:
        return self.alerts[0].component


def _build(primary: Alert, related: list, rule: str, confidence: str, reasoning: str, **override) -> CorrelatedGroup:
    template = ALERT_TEMPLATES.get(primary.category, _DEFAULT_TEMPLATE)
    ctype = primary.component_type
    fields = dict(
        title=template.title, root_cause=template.root_cause,
        action_key=_pick(template.action_key, ctype) or "investigate_symptoms",
        impact=template.impact, urgency=template.urgency,
        impact_reason=template.impact_reason, urgency_reason=template.urgency_reason,
        kb_id=_pick(template.kb_id, ctype),
    )
    fields.update(override)
    return CorrelatedGroup(alerts=[primary] + list(related), confidence=confidence,
                           reasoning=reasoning, rule=rule, **fields)


# ---------------------------------------------------------------- rules ----
def _rule_disk_cascade(alerts: list[Alert]):
    """Full Linux disk + app/log/SQL symptoms on the same server -> one incident."""
    symptoms_wanted = {"HIGH LOG ERRORS", "SLOW APPLICATION RESPONSE", "SQL CONNECTION FAILURES"}
    groups, used = [], set()
    for trigger in alerts:
        if trigger.category != "CRITICAL DISK" or trigger.component_type != LINUX:
            continue
        support = [a for a in alerts if a.component == trigger.component
                   and a.category in symptoms_wanted and a.key not in used]
        if len(support) < 2:
            continue
        names = ", ".join(a.category.title() for a in support)
        reasoning = (
            f"Rule 'Disk exhaustion cascade': disk on {trigger.component} is {trigger.value}% "
            f"(critical limit {trigger.threshold}%). On the SAME server we also see: {names}. "
            "A full disk stops logs and temp files from being written, which slows the application "
            "and breaks its database connections. The disk alert is therefore treated as the probable "
            "root cause and the other alerts as symptoms."
        )
        confidence = "High" if len(support) >= 3 else "Medium"
        groups.append(_build(
            trigger, support, "Disk exhaustion cascade", confidence, reasoning,
            title="Application Performance Degradation", root_cause="Linux Disk Exhaustion",
            action_key="linux_log_cleanup", impact="High", urgency="Medium",
            impact_reason="Application affected but service remains partially available.",
            urgency_reason="Degradation is growing, but users can still work.",
            kb_id="KB-LNX-DISK"))
        used.update([trigger.key] + [a.key for a in support])
    return groups, [a for a in alerts if a.key not in used]


def _rule_network_to_database(alerts: list[Alert]):
    """Network path failure + SQL connection failures -> 'cannot reach database'."""
    path = [a for a in alerts if a.component_type == NETWORK and a.category in NETWORK_PATH_ORDER]
    # Only APPLICATION-side symptoms (Linux/Windows servers), not the SQL server's own alerts.
    symptoms = [a for a in alerts if a.component_type in (LINUX, WINDOWS)
                and a.category in ("SQL CONNECTION FAILURES", "SLOW APPLICATION RESPONSE")]
    if not path or not any(a.category == "SQL CONNECTION FAILURES" for a in symptoms):
        return [], alerts
    first_component = path[0].component
    path = [a for a in path if a.component == first_component]
    path.sort(key=lambda a: NETWORK_PATH_ORDER.index(a.category))
    root = path[0]                       # first failing step in Ping -> DNS -> TCP
    related = path[1:] + symptoms
    steps = " -> ".join(a.category for a in path)
    reasoning = (
        f"Rule 'Network path to database': the application reports SQL connection failures while "
        f"{first_component} fails its connectivity checks ({steps}). Following the decision tree "
        "Ping -> DNS -> TCP, the FIRST failing step is the probable failure point: "
        f"{NETWORK_ROOT_CAUSES[root.category]}."
    )
    has_both = {"SQL CONNECTION FAILURES", "SLOW APPLICATION RESPONSE"} <= {a.category for a in symptoms}
    group = _build(
        root, related, "Network path to database", "High" if has_both else "Medium", reasoning,
        title="Application Cannot Reach Database", root_cause=NETWORK_ROOT_CAUSES[root.category],
        action_key="network_troubleshoot", impact="High", urgency="High",
        impact_reason="The application cannot reach its database: a full functional outage for that application.",
        urgency_reason="The outage is happening now and users are blocked.", kb_id="KB-NET-CONN")
    used = {a.key for a in [root] + related}
    return [group], [a for a in alerts if a.key not in used]


def _rule_sql_blocking(alerts: list[Alert]):
    """Blocking session plus connection failures / slow application -> one incident."""
    groups, used = [], set()
    for trigger in alerts:
        if trigger.category != "DATABASE PERFORMANCE ISSUE":
            continue
        support = [a for a in alerts if a.key not in used and (
            (a.category == "SQL CONNECTION FAILURES")
            or (a.category == "SLOW APPLICATION RESPONSE"))]
        if not support:
            continue
        names = ", ".join(f"{a.category.title()} ({a.component})" for a in support)
        reasoning = (
            f"Rule 'SQL blocking cascade': {trigger.component} has {trigger.value} blocked session(s). "
            f"Related symptoms: {names}. Blocked queries hold connections open, so new connections fail "
            "and the application slows down. The blocking session is the probable root cause."
        )
        groups.append(_build(
            trigger, support, "SQL blocking cascade", "High" if len(support) >= 2 else "Medium", reasoning,
            title="Database Performance Degradation", root_cause="SQL blocking session",
            action_key="sql_dba_escalation", impact="High", urgency="Medium",
            impact_reason="Applications using this database are slow and some connections fail.",
            urgency_reason="Service is partially available, but blocking can spread.",
            kb_id="KB-SQL-BLOCKING"))
        used.update([trigger.key] + [a.key for a in support])
    return groups, [a for a in alerts if a.key not in used]


def _rule_windows_service(alerts: list[Alert]):
    """Stopped Windows service with Event Log errors on the same server."""
    groups, used = [], set()
    for trigger in alerts:
        if trigger.category != "SERVICE FAILURE" or trigger.component_type != WINDOWS:
            continue
        support = [a for a in alerts if a.component == trigger.component and a.category == "HIGH EVENT ERRORS"]
        if not support:
            continue
        reasoning = (
            f"Rule 'Windows service failure': {trigger.message} on {trigger.component}, and the Event Log "
            f"shows {support[0].value} errors on the same server. The stopped service explains the errors."
        )
        groups.append(_build(
            trigger, support, "Windows service failure", "High", reasoning,
            title="Windows Service Failure", root_cause="Application service stopped",
            action_key="service_restart", impact="Medium", urgency="High",
            impact_reason="The application service is down on one server.",
            urgency_reason="Users of this service are affected right now.", kb_id="KB-WIN-SVC"))
        used.update([trigger.key] + [a.key for a in support])
    return groups, [a for a in alerts if a.key not in used]


def _rule_ad_lockout(alerts: list[Alert]):
    """One incident per repeatedly locked user; judge stale credentials vs. other causes."""
    groups, used = [], set()
    for trigger in alerts:
        if trigger.category != "ACCOUNT LOCKOUT ISSUE":
            continue
        user = trigger.details.get("user", trigger.subject)
        source = trigger.details.get("lockout_source") or "unknown source"
        share = trigger.details.get("source_share_pct", 0)
        if share >= 80:
            root, confidence = f"Probable stale credentials on {source}", "High"
            reasoning = (
                f"Rule 'Repeated lockout': {user} was locked {trigger.value} times and {share}% of the bad "
                f"password attempts come from ONE source ({source}). A single device repeatedly retrying an "
                "old password points to stale or cached credentials (mapped drive, saved password, service, "
                "mobile mail profile)."
            )
        else:
            root, confidence = "Repeated failed logons from several sources", "Medium"
            reasoning = (
                f"Rule 'Repeated lockout': {user} was locked {trigger.value} times, but the failed attempts "
                "come from several sources. This could be stale credentials on more than one device or "
                "possibly a password attack; check the source devices and involve security if needed."
            )
        groups.append(_build(
            trigger, [], "Repeated account lockout", confidence, reasoning,
            title=f"Repeated Account Lockout ({user})", root_cause=root))
        used.add(trigger.key)
    return groups, [a for a in alerts if a.key not in used]


_RULES = [_rule_disk_cascade, _rule_network_to_database, _rule_sql_blocking,
          _rule_windows_service, _rule_ad_lockout]


def _fallback_groups(alerts: list[Alert]) -> list[CorrelatedGroup]:
    """Alerts no rule claimed: one incident per (component, category)."""
    grouped: dict[tuple, list] = {}
    for alert in alerts:
        grouped.setdefault((alert.component, alert.category), []).append(alert)
    groups = []
    for (component, category), items in grouped.items():
        reasoning = (
            f"No multi-alert correlation rule matched. {category} on {component} is a direct "
            "threshold breach, so it becomes its own incident."
        )
        groups.append(_build(items[0], items[1:], "Direct threshold breach", "High", reasoning))
    return groups


def correlate(alerts: list[Alert]) -> list[CorrelatedGroup]:
    """Turn raw alerts into correlated incident candidates (most severe first)."""
    remaining, groups = list(alerts), []
    for rule in _RULES:
        found, remaining = rule(remaining)
        groups.extend(found)
    groups.extend(_fallback_groups(remaining))
    groups.sort(key=lambda g: (0 if g.primary.severity == CRITICAL else 1, g.component))
    return groups
