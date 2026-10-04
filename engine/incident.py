"""PRIORITIZE + track incidents: impact/urgency matrix, incident records, history."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import pandas as pd

from engine.correlation import CorrelatedGroup
from engine.detection import Alert
from engine.remediation import get_action
from engine.sla import evaluate_sla
from utils.helpers import format_timedelta, format_timestamp

LEVELS = ("High", "Medium", "Low")

# ITIL-style matrix: (impact, urgency) -> priority
PRIORITY_MATRIX = {
    ("High", "High"): "P1", ("High", "Medium"): "P2", ("High", "Low"): "P3",
    ("Medium", "High"): "P2", ("Medium", "Medium"): "P3", ("Medium", "Low"): "P4",
    ("Low", "High"): "P3", ("Low", "Medium"): "P4", ("Low", "Low"): "P4",
}

OPEN, ESCALATED, RESOLVED = "Open", "Escalated", "Resolved"


def calculate_priority(impact: str, urgency: str) -> str:
    """Impact x Urgency -> P1..P4."""
    try:
        return PRIORITY_MATRIX[(impact, urgency)]
    except KeyError:
        raise ValueError(f"Invalid impact/urgency: {impact!r}/{urgency!r}") from None


@dataclass
class Incident:
    incident_id: str
    created_at: datetime
    component: str
    component_type: str
    problem: str
    root_cause: str
    priority: str
    impact: str
    urgency: str
    priority_reason: str
    confidence: str
    reasoning: str
    recommended_action: str
    action_key: str
    alerts: list
    rule: str
    kb_id: str = ""
    status: str = OPEN
    resolved_at: datetime | None = None
    remediation_records: list = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.status != RESOLVED

    @property
    def fingerprint(self) -> str:
        return f"{self.component}|{self.problem}"

    def alerts_for(self, component_name: str) -> list[Alert]:
        return [a for a in self.alerts if a.component == component_name]


class IncidentManager:
    """Keeps incident records for the current session (no database needed)."""

    def __init__(self) -> None:
        self.incidents: list[Incident] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"INC-{self._counter:04d}"

    def create_from_group(self, group: CorrelatedGroup, now: datetime) -> Incident:
        priority = calculate_priority(group.impact, group.urgency)
        reason = (f"Impact {group.impact}: {group.impact_reason} "
                  f"Urgency {group.urgency}: {group.urgency_reason}")
        incident = Incident(
            incident_id=self._next_id(), created_at=now, component=group.component,
            component_type=group.primary.component_type, problem=group.title,
            root_cause=group.root_cause, priority=priority, impact=group.impact,
            urgency=group.urgency, priority_reason=reason, confidence=group.confidence,
            reasoning=group.reasoning, recommended_action=get_action(group.action_key).recommendation,
            action_key=group.action_key, alerts=list(group.alerts), rule=group.rule, kb_id=group.kb_id,
        )
        self.incidents.append(incident)
        return incident

    def find_open(self, fingerprint: str) -> Incident | None:
        for incident in self.incidents:
            if incident.is_open and incident.fingerprint == fingerprint:
                return incident
        return None

    def sync(self, groups: list[CorrelatedGroup], now: datetime) -> list[Incident]:
        """Create incidents for new groups; refresh the ones already open (no duplicates)."""
        created = []
        for group in groups:
            existing = self.find_open(f"{group.component}|{group.title}")
            if existing:
                existing.alerts = list(group.alerts)
            else:
                created.append(self.create_from_group(group, now))
        return created

    def get(self, incident_id: str) -> Incident | None:
        return next((i for i in self.incidents if i.incident_id == incident_id), None)

    def open_incidents(self) -> list[Incident]:
        return [i for i in self.incidents if i.is_open]

    def resolved_incidents(self) -> list[Incident]:
        return [i for i in self.incidents if not i.is_open]

    def resolve(self, incident: Incident, resolved_at: datetime) -> None:
        incident.status = RESOLVED
        incident.resolved_at = resolved_at

    def to_dataframe(self, now: datetime) -> pd.DataFrame:
        columns = ["Incident ID", "Timestamp", "Component", "Problem", "Root Cause", "Priority",
                   "SLA", "SLA Remaining", "Recommended Action", "Status", "Resolution Time"]
        rows = []
        for i in sorted(self.incidents, key=lambda x: x.incident_id, reverse=True):
            sla = evaluate_sla(i.created_at, i.priority, now, i.resolved_at)
            rows.append({
                "Incident ID": i.incident_id, "Timestamp": format_timestamp(i.created_at),
                "Component": i.component, "Problem": i.problem, "Root Cause": i.root_cause,
                "Priority": i.priority, "SLA": sla.status, "SLA Remaining": sla.remaining_text,
                "Recommended Action": i.recommended_action, "Status": i.status,
                "Resolution Time": format_timedelta(i.resolved_at - i.created_at) if i.resolved_at else "-",
            })
        return pd.DataFrame(rows, columns=columns)
