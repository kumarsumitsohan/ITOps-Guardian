"""Small shared helpers used across the project (formatting and constants)."""
from __future__ import annotations

from datetime import datetime, timedelta

SIMULATION_NOTICE = (
    "All infrastructure, metrics, incidents, SLA targets and remediation results "
    "shown here are SIMULATED. ITOps Guardian is a self-developed simulated "
    "enterprise infrastructure environment, not a real production system."
)

PRIORITY_NAMES = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low"}

HEALTH_ICONS = {
    "Healthy": "🟢 Healthy",
    "Warning": "🟡 Warning",
    "Critical": "🔴 Critical",
}


def format_timedelta(delta: timedelta) -> str:
    """Format a time span as '7h 59m'. Negative spans become '-1h 10m'."""
    total_seconds = int(delta.total_seconds())
    sign = "-" if total_seconds < 0 else ""
    hours, rest = divmod(abs(total_seconds), 3600)
    return f"{sign}{hours}h {rest // 60:02d}m"


def format_timestamp(ts: datetime | None) -> str:
    """Format a datetime for tables ('-' when missing)."""
    return "-" if ts is None else ts.strftime("%Y-%m-%d %H:%M:%S")


def prettify(name: str) -> str:
    """'log_space_pct' -> 'Log Space Pct'."""
    return name.replace("_", " ").strip().title()


def health_label(health: str) -> str:
    """Add a coloured status icon to a health word."""
    return HEALTH_ICONS.get(health, health)


def priority_label(priority: str) -> str:
    """'P2' -> 'P2 - High'."""
    return f"{priority} - {PRIORITY_NAMES.get(priority, '?')}"
