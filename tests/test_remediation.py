import pytest

from data.scenarios import get_scenario
from engine.correlation import correlate
from engine.detection import detect_all
from engine.incident import IncidentManager
from engine.remediation import (execute_remediation, escalate_incident, simulate_dba_resolution,
                                verify_incident)
from tests.helpers import NOW, comp, environment


def setup(scenario_id, **options):
    env = environment()
    get_scenario(scenario_id)["inject"](env, **options)
    manager = IncidentManager()
    manager.sync(correlate(detect_all(env, NOW)), NOW)
    return env, manager.incidents[0]


def test_disk_cleanup_goes_94_to_61_and_verifies():
    env, incident = setup("S1")
    record = execute_remediation(env, incident, NOW)
    assert record["passed"] is True
    disk = next(c for c in record["changes"] if c["Metric"] == "Disk %")
    assert (disk["Before"], disk["After"]) == (94, 61)
    assert comp(env, "APP-LNX-01")["metrics"]["log_errors"] == "LOW"     # symptoms recovered too
    assert record["audit"]["Incident ID"] == incident.incident_id
    assert detect_all(env, NOW) == []


def test_service_restart_verifies_running():
    env, incident = setup("S2")
    assert execute_remediation(env, incident, NOW)["passed"] is True
    assert comp(env, "WIN-SRV-01")["metrics"]["service_status"] == "RUNNING"


def test_ad_unlock_verifies_active():
    env, incident = setup("S3")
    assert execute_remediation(env, incident, NOW)["passed"] is True
    user = next(u for u in comp(env, "AD-01")["details"]["users"] if u["user"] == "user03")
    assert user["status"] == "ACTIVE"


@pytest.mark.parametrize("variant", ["Ping", "DNS", "TCP"])
def test_network_troubleshooting_fixes_every_variant(variant):
    env, incident = setup("S5", variant=variant)
    assert execute_remediation(env, incident, NOW)["passed"] is True
    assert detect_all(env, NOW) == []


def test_azure_recovery_normalises_cpu():
    env, incident = setup("S6")
    assert execute_remediation(env, incident, NOW)["passed"] is True
    assert comp(env, "AZ-VM-01")["metrics"]["cpu"] <= 85


def test_sql_blocking_is_never_remediated_automatically():
    env, incident = setup("S4")
    with pytest.raises(ValueError):
        execute_remediation(env, incident, NOW)
    record = escalate_incident(incident, NOW)
    assert record["passed"] is None
    assert comp(env, "SQL-01")["metrics"]["blocking_sessions"] == 3     # nothing was killed
    assert "NOT" in record["audit"]["Action"]


def test_dba_resolution_is_a_separate_simulated_human_action():
    env, incident = setup("S4")
    record = simulate_dba_resolution(env, incident, NOW)
    assert record["actor"].startswith("DBA") and record["passed"] is True


def test_verification_fails_when_problem_still_present():
    env, incident = setup("S1")
    result = verify_incident(env, incident, NOW)          # nothing fixed yet
    assert result["passed"] is False
    assert any(check["Result"] == "FAIL" for check in result["checks"])
