"""One simulation session: ties MONITOR -> DETECT -> CORRELATE -> PRIORITIZE -> REMEDIATE -> VERIFY.

The Streamlit app keeps a single SimulationSession in st.session_state. All logic
lives here (not in the UI) so it can be tested without Streamlit.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Callable

import pandas as pd

from data.infrastructure import build_infrastructure, get_component
from data.scenarios import get_scenario
from engine.correlation import correlate
from engine.detection import detect_all, health_from_alerts
from engine.incident import ESCALATED, IncidentManager
from engine.monitoring import (history_rows, inventory_dataframe, jitter_metrics,
                               network_decision_tree, read_metric)
from engine.remediation import (escalate_incident, execute_remediation, get_action,
                                simulate_dba_resolution)
from engine.sla import AT_RISK, BREACHED, evaluate_sla

MAX_HISTORY_ROWS = 600


class SimulationSession:
    def __init__(self, seed: int = 42, clock: Callable[[], datetime] | None = None) -> None:
        self.seed = seed
        self._clock = clock or datetime.now
        self.clock_offset_hours = 0.0      # "time travel" to demo SLA At Risk / Breached
        self.reset()

    # ---------------------------------------------------------- lifecycle ----
    def reset(self) -> None:
        self.rng = random.Random(self.seed)
        self.components = build_infrastructure()
        self.incidents = IncidentManager()
        self.audit_log: list[dict] = []
        self.history: list[dict] = []
        self.scenario_state: dict[str, dict] = {}
        self.alerts: list = []
        self.groups: list = []
        self.last_analysis: datetime | None = None
        self.poll_count = 0
        self._touch_checks()
        self._record_history()

    def now(self) -> datetime:
        return self._clock() + timedelta(hours=self.clock_offset_hours)

    def _touch_checks(self) -> None:
        now = self.now()
        for component in self.components:
            component["last_check"] = now

    def _record_history(self) -> None:
        self.history.extend(history_rows(self.components, self.now()))
        self.history = self.history[-MAX_HISTORY_ROWS:]

    # ------------------------------------------------- monitor/detect/correlate ----
    def poll(self) -> list:
        """Simulated polling cycle: new metric values, then detection and correlation."""
        jitter_metrics(self.components, self.rng)
        self.poll_count += 1
        self._record_history()
        return self.analyze()

    def analyze(self) -> list:
        """DETECT + CORRELATE + PRIORITIZE. Returns newly created incidents."""
        now = self.now()
        self._touch_checks()
        self.alerts = detect_all(self.components, now)
        self.groups = correlate(self.alerts)
        created = self.incidents.sync(self.groups, now)
        self.last_analysis = now
        return created

    # ------------------------------------------------------------- views ----
    def health_map(self) -> dict[str, str]:
        alerts = detect_all(self.components, self.now())
        by_component: dict[str, list] = {}
        for alert in alerts:
            by_component.setdefault(alert.component, []).append(alert)
        return {c["name"]: health_from_alerts(by_component.get(c["name"], [])) for c in self.components}

    def inventory(self) -> pd.DataFrame:
        return inventory_dataframe(self.components, detect_all(self.components, self.now()))

    def kpis(self) -> dict:
        health = list(self.health_map().values())
        now = self.now()
        open_incidents = self.incidents.open_incidents()
        statuses = [evaluate_sla(i.created_at, i.priority, now).status for i in open_incidents]
        return {
            "total": len(self.components), "healthy": health.count("Healthy"),
            "warning": health.count("Warning"), "critical": health.count("Critical"),
            "open": len(open_incidents), "resolved": len(self.incidents.resolved_incidents()),
            "sla_at_risk": statuses.count(AT_RISK), "sla_breached": statuses.count(BREACHED),
        }

    def history_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(self.history)

    # ------------------------------------------------------ incident actions ----
    def remediate(self, incident_id: str) -> dict | None:
        incident = self.incidents.get(incident_id)
        if incident is None or not incident.is_open:
            return None
        now = self.now()
        record = execute_remediation(self.components, incident, now)
        incident.remediation_records.append(record)
        self.audit_log.append(record["audit"])
        if record["passed"]:
            self.incidents.resolve(incident, now + timedelta(minutes=record["simulated_minutes"]))
        self.analyze()
        return record

    def escalate(self, incident_id: str) -> dict | None:
        incident = self.incidents.get(incident_id)
        if incident is None or not incident.is_open:
            return None
        record = escalate_incident(incident, self.now())
        incident.remediation_records.append(record)
        incident.status = ESCALATED
        self.audit_log.append(record["audit"])
        return record

    def dba_resolve(self, incident_id: str) -> dict | None:
        incident = self.incidents.get(incident_id)
        if incident is None or incident.status != ESCALATED:
            return None
        now = self.now()
        record = simulate_dba_resolution(self.components, incident, now)
        incident.remediation_records.append(record)
        self.audit_log.append(record["audit"])
        if record["passed"]:
            self.incidents.resolve(incident, now + timedelta(minutes=record["simulated_minutes"]))
        self.analyze()
        return record

    # ------------------------------------------------------------ scenarios ----
    def _watch_rows(self, scenario: dict) -> list[dict]:
        from engine.monitoring import metric_label
        return [{"Component": name, "Metric": metric_label(metric),
                 "Value": read_metric(get_component(self.components, name), metric)}
                for name, metric in scenario["watch"]]

    def scenario_inject(self, scenario_id: str, **options) -> None:
        scenario = get_scenario(scenario_id)
        scenario["inject"](self.components, **options)
        self.scenario_state[scenario_id] = {
            "stage": 1, "options": options, "before": self._watch_rows(scenario),
            "after": None, "incident_id": None, "tree_before": None, "tree_after": None, "record": None,
        }

    def scenario_detect(self, scenario_id: str) -> str | None:
        scenario, state = get_scenario(scenario_id), self.scenario_state[scenario_id]
        self.analyze()
        expected = scenario["expected"]
        candidates = [i for i in self.incidents.open_incidents()
                      if i.component == expected["component"] and i.problem.startswith(expected["problem"])]
        state["incident_id"] = candidates[-1].incident_id if candidates else None
        if scenario_id == "S5":
            state["tree_before"] = network_decision_tree(get_component(self.components, "APP-NET-01"))
        state["stage"] = 2
        return state["incident_id"]

    def scenario_resolve(self, scenario_id: str) -> dict | None:
        scenario, state = get_scenario(scenario_id), self.scenario_state[scenario_id]
        if not state["incident_id"]:
            return None
        incident = self.incidents.get(state["incident_id"])
        if get_action(incident.action_key).automatic:
            record = self.remediate(incident.incident_id)
        else:
            record = self.escalate(incident.incident_id)
        state["record"], state["after"], state["stage"] = record, self._watch_rows(scenario), 3
        if scenario_id == "S5":
            state["tree_after"] = network_decision_tree(get_component(self.components, "APP-NET-01"))
        return record

    def scenario_run_all(self, scenario_id: str, **options) -> None:
        self.scenario_inject(scenario_id, **options)
        self.scenario_detect(scenario_id)
        self.scenario_resolve(scenario_id)
