import pytest

from data.scenarios import get_scenario
from engine.correlation import correlate
from engine.detection import detect_all
from engine.incident import IncidentManager, calculate_priority
from tests.helpers import NOW, environment


def test_priority_matrix():
    assert calculate_priority("High", "High") == "P1"
    assert calculate_priority("High", "Medium") == "P2"
    assert calculate_priority("Medium", "Medium") == "P3"
    assert calculate_priority("Low", "Low") == "P4"


def test_invalid_priority_input_raises():
    with pytest.raises(ValueError):
        calculate_priority("Huge", "High")


def make_manager(scenario_id, **options):
    env = environment()
    get_scenario(scenario_id)["inject"](env, **options)
    manager = IncidentManager()
    manager.sync(correlate(detect_all(env, NOW)), NOW)
    return manager


def test_disk_scenario_is_p2_with_reason():
    incident = make_manager("S1").incidents[0]
    assert incident.priority == "P2"
    assert incident.incident_id == "INC-0001"
    assert "partially available" in incident.priority_reason


def test_expected_priorities_for_all_scenarios():
    expected = {"S1": "P2", "S2": "P2", "S3": "P3", "S4": "P2", "S5": "P1", "S6": "P3"}
    for sid, priority in expected.items():
        assert make_manager(sid).incidents[0].priority == priority, sid


def test_sync_does_not_create_duplicates():
    env = environment()
    get_scenario("S1")["inject"](env)
    manager = IncidentManager()
    groups = correlate(detect_all(env, NOW))
    manager.sync(groups, NOW)
    manager.sync(groups, NOW)
    assert len(manager.incidents) == 1


def test_resolve_and_dataframe():
    manager = make_manager("S6")
    incident = manager.incidents[0]
    manager.resolve(incident, NOW)
    assert not incident.is_open
    df = manager.to_dataframe(NOW)
    assert list(df["Status"]) == ["Resolved"]
    assert {"Incident ID", "Timestamp", "Component", "Problem", "Root Cause", "Priority", "SLA",
            "Recommended Action", "Status", "Resolution Time"} <= set(df.columns)
