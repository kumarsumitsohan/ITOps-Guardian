from datetime import datetime, timedelta

from engine.session import SimulationSession

FIXED = datetime(2026, 1, 1, 9, 0, 0)


def make():
    return SimulationSession(clock=lambda: FIXED)


def test_all_six_scenarios_end_as_expected():
    session = make()
    for sid in ("S1", "S2", "S3", "S4", "S5", "S6"):
        session.scenario_run_all(sid)
    statuses = {sid: session.incidents.get(session.scenario_state[sid]["incident_id"]).status
                for sid in session.scenario_state}
    assert statuses == {"S1": "Resolved", "S2": "Resolved", "S3": "Resolved",
                        "S4": "Escalated", "S5": "Resolved", "S6": "Resolved"}
    assert len(session.incidents.incidents) == 6        # no duplicate or stray incidents
    assert len(session.audit_log) == 6


def test_poll_keeps_a_healthy_environment_healthy():
    session = make()
    for _ in range(25):
        session.poll()
    assert session.alerts == [] and session.incidents.incidents == []


def test_poll_keeps_an_injected_fault():
    session = make()
    session.scenario_inject("S6")
    for _ in range(5):
        session.poll()
    assert any(a.category == "AZURE PERFORMANCE ALERT" for a in session.alerts)


def test_clock_offset_moves_sla_status():
    session = make()
    session.scenario_inject("S1")
    session.scenario_detect("S1")
    assert session.kpis()["sla_at_risk"] == 0
    session.clock_offset_hours = 7          # P2 target is 8h, so < 25% left
    assert session.kpis()["sla_at_risk"] == 1
    session.clock_offset_hours = 9
    assert session.kpis()["sla_breached"] == 1


def test_reset_clears_everything():
    session = make()
    session.scenario_run_all("S1")
    session.reset()
    assert session.incidents.incidents == [] and session.audit_log == []


def test_resolution_time_uses_simulated_duration():
    session = make()
    session.scenario_run_all("S1")
    incident = session.incidents.incidents[0]
    assert incident.resolved_at - incident.created_at == timedelta(minutes=25)
