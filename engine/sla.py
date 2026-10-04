"""SLA management using PROJECT-DEFINED, SIMULATED targets (not a real company policy)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from utils.helpers import format_timedelta

SLA_LABEL = "Simulated Project SLA Targets (project-defined, not a real company SLA policy)"

# Resolution targets in hours.
SLA_TARGET_HOURS = {"P1": 4, "P2": 8, "P3": 24, "P4": 72}

# An open incident is "At Risk" when 25% or less of its SLA time is left.
AT_RISK_FRACTION = 0.25

WITHIN, AT_RISK, BREACHED = "Within SLA", "At Risk", "Breached"


@dataclass
class SLAInfo:
    target_hours: int
    due_at: datetime
    remaining: timedelta | None   # None once the incident is resolved
    status: str                   # Within SLA / At Risk / Breached
    remaining_text: str


def sla_target_hours(priority: str) -> int:
    if priority not in SLA_TARGET_HOURS:
        raise ValueError(f"Unknown priority: {priority}")
    return SLA_TARGET_HOURS[priority]


def evaluate_sla(created_at: datetime, priority: str, now: datetime,
                 resolved_at: datetime | None = None) -> SLAInfo:
    """Work out SLA status for an open or resolved incident."""
    hours = sla_target_hours(priority)
    due_at = created_at + timedelta(hours=hours)

    if resolved_at is not None:                     # resolved: was the target met?
        met = resolved_at <= due_at
        took = format_timedelta(resolved_at - created_at)
        return SLAInfo(hours, due_at, None, WITHIN if met else BREACHED,
                       f"Resolved in {took}" + ("" if met else " (target missed)"))

    remaining = due_at - now
    if remaining.total_seconds() <= 0:
        status = BREACHED
        text = f"Overdue by {format_timedelta(-remaining)}"
    elif remaining <= timedelta(hours=hours) * AT_RISK_FRACTION:
        status = AT_RISK
        text = format_timedelta(remaining)
    else:
        status = WITHIN
        text = format_timedelta(remaining)
    return SLAInfo(hours, due_at, remaining, status, text)
