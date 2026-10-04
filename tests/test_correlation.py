from data.scenarios import get_scenario
from engine.correlation import correlate
from engine.detection import detect_all
from tests.helpers import NOW, comp, environment


def run(env):
    alerts = detect_all(env, NOW)
    return alerts, correlate(alerts)


def test_disk_cascade_becomes_one_incident():
    env = environment()
    get_scenario("S1")["inject"](env)
    alerts, groups = run(env)
    assert len(alerts) == 4                      # four separate raw alerts ...
    assert len(groups) == 1                      # ... but ONE incident
    group = groups[0]
    assert group.title == "Application Performance Degradation"
    assert group.root_cause == "Linux Disk Exhaustion"
    assert group.primary.category == "CRITICAL DISK"
    assert group.confidence == "High"
    assert len(group.alerts) == 4


def test_unrelated_alerts_stay_separate():
    env = environment()
    comp(env, "APP-LNX-01")["metrics"]["disk"] = 95
    comp(env, "AZ-VM-01")["metrics"]["cpu"] = 92
    _, groups = run(env)
    assert len(groups) == 2


def test_disk_without_symptoms_is_not_a_cascade():
    env = environment()
    comp(env, "APP-LNX-01")["metrics"]["disk"] = 95
    _, groups = run(env)
    assert len(groups) == 1 and groups[0].title == "Critical Disk Usage"


def test_windows_service_correlated_with_event_errors():
    env = environment()
    get_scenario("S2")["inject"](env)
    _, groups = run(env)
    assert len(groups) == 1 and groups[0].title == "Windows Service Failure"


def test_sql_blocking_with_connection_failures():
    env = environment()
    get_scenario("S4")["inject"](env)
    _, groups = run(env)
    assert len(groups) == 1
    assert groups[0].root_cause == "SQL blocking session"
    assert groups[0].action_key == "sql_dba_escalation"


def test_network_decision_order_picks_first_failing_step():
    for variant, expected in (("Ping", "ping"), ("DNS", "DNS resolution"), ("TCP", "TCP connectivity")):
        env = environment()
        get_scenario("S5")["inject"](env, variant=variant)
        _, groups = run(env)
        assert len(groups) == 1
        assert groups[0].title == "Application Cannot Reach Database"
        assert expected.lower() in groups[0].root_cause.lower()


def test_network_rule_does_not_steal_sql_server_alerts():
    env = environment()
    get_scenario("S4")["inject"](env)
    get_scenario("S5")["inject"](env, variant="DNS")
    _, groups = run(env)
    titles = {g.title for g in groups}
    assert "Application Cannot Reach Database" in titles
    assert "Database Performance Degradation" in titles


def test_ad_lockout_identifies_stale_credentials():
    env = environment()
    get_scenario("S3")["inject"](env)
    _, groups = run(env)
    assert "stale credentials" in groups[0].root_cause.lower()
