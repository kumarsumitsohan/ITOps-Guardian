from data.scenarios import get_scenario
from engine.detection import CRITICAL, WARNING, component_health, detect_all, detect_component
from tests.helpers import NOW, comp, environment


def categories(alerts):
    return {a.category for a in alerts}


def test_healthy_environment_has_no_alerts():
    assert detect_all(environment(), NOW) == []


def test_high_cpu_threshold_boundary():
    env = environment()
    comp(env, "APP-LNX-01")["metrics"]["cpu"] = 85          # exactly at the limit: no alert
    assert "HIGH CPU" not in categories(detect_component(comp(env, "APP-LNX-01"), NOW))
    comp(env, "APP-LNX-01")["metrics"]["cpu"] = 86
    assert "HIGH CPU" in categories(detect_component(comp(env, "APP-LNX-01"), NOW))


def test_critical_disk_above_90():
    env = environment()
    comp(env, "APP-LNX-01")["metrics"]["disk"] = 94
    alerts = detect_component(comp(env, "APP-LNX-01"), NOW)
    assert alerts[0].category == "CRITICAL DISK" and alerts[0].severity == CRITICAL


def test_disk_warning_between_80_and_90():
    env = environment()
    comp(env, "WIN-SRV-02")["metrics"]["disk"] = 85
    alert = detect_component(comp(env, "WIN-SRV-02"), NOW)[0]
    assert alert.category == "DISK WARNING" and alert.severity == WARNING


def test_service_failure():
    env = environment()
    comp(env, "WIN-SRV-01")["metrics"]["service_status"] = "STOPPED"
    assert "SERVICE FAILURE" in categories(detect_component(comp(env, "WIN-SRV-01"), NOW))
    assert component_health(comp(env, "WIN-SRV-01"), NOW) == "Critical"


def test_network_packet_loss_over_10_percent():
    env = environment()
    comp(env, "CORE-SW-01")["metrics"]["packet_loss_pct"] = 12
    assert "NETWORK ISSUE" in categories(detect_component(comp(env, "CORE-SW-01"), NOW))


def test_ad_lockout_needs_repeated_lockouts():
    env = environment()
    get_scenario("S3")["inject"](env)
    alerts = detect_component(comp(env, "AD-01"), NOW)
    assert [a.category for a in alerts] == ["ACCOUNT LOCKOUT ISSUE"]
    assert alerts[0].subject == "user03"


def test_sql_blocking_detected():
    env = environment()
    comp(env, "SQL-01")["metrics"]["blocking_sessions"] = 2
    assert "DATABASE PERFORMANCE ISSUE" in categories(detect_component(comp(env, "SQL-01"), NOW))


def test_azure_cpu_alert():
    env = environment()
    comp(env, "AZ-VM-01")["metrics"]["cpu"] = 92
    assert "AZURE PERFORMANCE ALERT" in categories(detect_component(comp(env, "AZ-VM-01"), NOW))
