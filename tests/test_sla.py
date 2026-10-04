from datetime import timedelta

import pytest

from engine.sla import AT_RISK, BREACHED, SLA_TARGET_HOURS, WITHIN, evaluate_sla, sla_target_hours
from tests.helpers import NOW


def test_targets():
    assert SLA_TARGET_HOURS == {"P1": 4, "P2": 8, "P3": 24, "P4": 72}
    assert sla_target_hours("P2") == 8


def test_unknown_priority():
    with pytest.raises(ValueError):
        sla_target_hours("P9")


def test_within_sla():
    info = evaluate_sla(NOW, "P2", NOW + timedelta(hours=1))
    assert info.status == WITHIN
    assert info.remaining == timedelta(hours=7)
    assert info.due_at == NOW + timedelta(hours=8)


def test_at_risk_when_quarter_left():
    assert evaluate_sla(NOW, "P2", NOW + timedelta(hours=6.5)).status == AT_RISK


def test_breached_after_target():
    info = evaluate_sla(NOW, "P1", NOW + timedelta(hours=5))
    assert info.status == BREACHED and "Overdue" in info.remaining_text


def test_resolved_incident_met_or_missed():
    assert evaluate_sla(NOW, "P3", NOW + timedelta(days=5), NOW + timedelta(hours=2)).status == WITHIN
    assert evaluate_sla(NOW, "P3", NOW + timedelta(days=5), NOW + timedelta(hours=30)).status == BREACHED
