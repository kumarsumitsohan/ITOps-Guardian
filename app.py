"""ITOps Guardian - IT Infrastructure Health & Incident Simulator.

A self-developed SIMULATION project. All data is simulated.
Run with:  python -m streamlit run app.py
"""
from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from data.infrastructure import COMPONENT_TYPES
from data.knowledge_base import ARTICLES, get_article, search_articles
from data.scenarios import SCENARIOS
from engine.detection import THRESHOLDS
from engine.incident import ESCALATED, OPEN, RESOLVED
from engine.monitoring import chart_dataframe, metric_label, metrics_dataframe, read_metric
from engine.remediation import get_action
from engine.session import SimulationSession
from engine.sla import AT_RISK, BREACHED, SLA_LABEL, SLA_TARGET_HOURS, WITHIN, evaluate_sla
from utils.helpers import (PRIORITY_NAMES, SIMULATION_NOTICE, format_timedelta, format_timestamp,
                           priority_label)

st.set_page_config(page_title="ITOps Guardian", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

PAGES = ["Dashboard", "Infrastructure", "Incidents", "Monitoring", "Demo Scenarios",
         "Knowledge Base", "Reports"]
PIPELINE = ["Monitor", "Detect", "Correlate", "Prioritize", "Remediate", "Verify"]
NORMAL, ALERT = "#4C78A8", "#C0392B"
STATUS_COLORS = {OPEN: "#C0392B", ESCALATED: "#E67E22", RESOLVED: "#4C78A8"}

st.markdown(
    """
    <style>
    div[data-testid="stMetric"] {background: rgba(128,128,128,0.08);
        border: 1px solid rgba(128,128,128,0.30); padding: 10px 14px; border-radius: 6px;}
    .pipeline {display:flex; gap:8px; flex-wrap:wrap; margin-bottom:6px;}
    .pipeline span {border:1px solid rgba(128,128,128,0.45); border-radius:4px;
        padding:2px 10px; font-size:0.85rem;}
    </style>
    """,
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------- helpers ----
def get_session() -> SimulationSession:
    if "sim" not in st.session_state:
        st.session_state["sim"] = SimulationSession()
    return st.session_state["sim"]


def show_table(df: pd.DataFrame) -> None:
    """Show a table full-width (works on old and new Streamlit versions)."""
    df = df.copy()
    for column in df.columns:                      # mixed text/number columns -> text
        if df[column].dtype == object:
            df[column] = df[column].astype(str)
    try:
        st.dataframe(df, width="stretch", hide_index=True)
    except Exception:
        st.dataframe(df, use_container_width=True, hide_index=True)


def show_chart(fig, key: str) -> None:
    try:
        st.plotly_chart(fig, width="stretch", key=key)
    except Exception:
        st.plotly_chart(fig, use_container_width=True, key=key)


def style_fig(fig, height: int = 300):
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=45, b=10), showlegend=False,
                      title_font_size=15)
    return fig


def threshold_bar(df: pd.DataFrame, title: str, threshold: float | None, unit: str, key: str) -> None:
    """Bar chart; bars above the threshold are highlighted."""
    if df.empty:
        st.caption(f"No data for {title}.")
        return
    df = df.copy()
    limit = threshold if threshold is not None else float("inf")
    df["State"] = df["Value"].apply(lambda v: "Above threshold" if v > limit else "Normal")
    fig = px.bar(df, x="Component", y="Value", color="State", text_auto=".0f", title=title,
                 color_discrete_map={"Normal": NORMAL, "Above threshold": ALERT})
    if threshold is not None:
        fig.add_hline(y=threshold, line_dash="dash", line_color="gray",
                      annotation_text=f"Threshold {threshold}{unit}", annotation_position="top left")
    fig.update_yaxes(title=unit.strip() or None)
    show_chart(style_fig(fig), key)


def pipeline_banner() -> None:
    steps = "".join(f"<span>{s}</span>" for s in PIPELINE)
    st.markdown(f'<div class="pipeline">{steps}</div>', unsafe_allow_html=True)


def poll_buttons(session: SimulationSession, prefix: str) -> None:
    c1, c2, _ = st.columns([1.2, 1.6, 4])
    if c1.button("Poll metrics (simulated)", key=f"{prefix}_poll"):
        session.poll()
        st.rerun()
    if c2.button("Run detection & correlation", key=f"{prefix}_analyze"):
        session.analyze()
        st.rerun()


# ----------------------------------------------------------------- sidebar ----
def render_sidebar(session: SimulationSession) -> str:
    st.sidebar.title("🛡️ ITOps Guardian")
    st.sidebar.caption("Simulated NOC / IT operations console")
    page = st.sidebar.radio("Navigation", PAGES, key="nav", label_visibility="collapsed")
    st.sidebar.divider()
    st.sidebar.markdown("**Simulated clock**")
    offset = st.sidebar.slider("Hours advanced", 0, 96, 0, key="clock_offset",
                               help="Move simulated time forward to see SLA go from Within SLA to "
                                    "At Risk to Breached.")
    session.clock_offset_hours = float(offset)
    st.sidebar.caption(f"Simulated time: {format_timestamp(session.now())}")
    if st.sidebar.button("Reset environment", key="reset_env"):
        session.reset()
        st.rerun()
    st.sidebar.divider()
    st.sidebar.caption("Mode: SIMULATION")
    st.sidebar.caption("Rule-based correlation (not machine learning)")
    return page


# ------------------------------------------------------ incident rendering ----
def render_record(record: dict) -> None:
    """BEFORE -> ACTION -> AFTER -> VERIFICATION -> AUDIT LOG."""
    st.markdown(f"**{record['action_label']}**  |  by {record['actor']}  |  {format_timestamp(record['timestamp'])}")
    st.markdown("**BEFORE → AFTER**")
    if record["changes"]:
        show_table(pd.DataFrame(record["changes"]))
    else:
        st.caption("No change was made to the environment.")
    st.markdown("**ACTION**")
    for step in record["steps"]:
        st.write(f"- {step}")
    for note in record["notes"]:
        st.write(f"- ✔ {note}")
    st.markdown("**VERIFICATION**")
    verification = record["verification"]
    if verification["checks"]:
        show_table(pd.DataFrame(verification["checks"]))
    if verification["passed"] is True:
        st.success("Verification successful: the condition is cleared.")
    elif verification["passed"] is False:
        st.error("Verification failed: the condition is still present.")
    else:
        st.warning(verification.get("note", "Verification pending."))
    st.markdown("**AUDIT LOG ENTRY**")
    show_table(pd.DataFrame([record["audit"]]))


def render_incident_detail(session: SimulationSession, incident, ctx: str) -> None:
    now = session.now()
    sla = evaluate_sla(incident.created_at, incident.priority, now, incident.resolved_at)
    action = get_action(incident.action_key)

    st.markdown("##### 1. Related events (correlated alerts)")
    rows = [{"Role": "Probable root cause" if n == 0 else "Symptom", "Component": a.component,
             "Alert": a.category, "Severity": a.severity, "Detail": a.message}
            for n, a in enumerate(incident.alerts)]
    show_table(pd.DataFrame(rows))
    if len(incident.alerts) > 1:
        st.success(f"Correlation: {len(incident.alerts)} alerts grouped into ONE incident.")

    st.markdown("##### 2. Probable root cause")
    st.markdown(f"**{incident.root_cause}**  |  Confidence: **{incident.confidence}**  |  Rule: {incident.rule}")
    st.caption(incident.reasoning)

    st.markdown("##### 3. Priority")
    c1, c2, c3 = st.columns(3)
    c1.metric("Impact", incident.impact)
    c2.metric("Urgency", incident.urgency)
    c3.metric("Priority", priority_label(incident.priority))
    st.caption(f"Reason: {incident.priority_reason}")

    st.markdown("##### 4. SLA")
    st.caption(SLA_LABEL)
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Created", format_timestamp(incident.created_at))
    s2.metric("Target", f"{sla.target_hours} hours")
    s3.metric("Remaining" if incident.is_open else "Result", sla.remaining_text)
    s4.metric("SLA status", sla.status)

    st.markdown("##### 5. Recommended action")
    st.info(incident.recommended_action)
    article = get_article(incident.kb_id) if incident.kb_id else None
    if article:
        st.caption(f"Knowledge base article: {article['id']} - {article['title']}")

    st.markdown("##### 6. Remediation")
    if incident.status == RESOLVED:
        st.success(f"Incident RESOLVED at {format_timestamp(incident.resolved_at)} (simulated).")
    elif incident.status == ESCALATED:
        st.warning("Escalated to DBA. Nothing was changed automatically.")
        if st.button("Simulate DBA resolution (external action)", key=f"{ctx}-dba-{incident.incident_id}"):
            session.dba_resolve(incident.incident_id)
            st.rerun()
    elif action.automatic:
        if st.button(f"▶ Execute: {action.label}", key=f"{ctx}-rem-{incident.incident_id}"):
            session.remediate(incident.incident_id)
            st.rerun()
    else:
        st.caption("This problem is NEVER fixed automatically. Sessions are not terminated.")
        if st.button("Escalate to DBA (simulated ticket)", key=f"{ctx}-esc-{incident.incident_id}"):
            session.escalate(incident.incident_id)
            st.rerun()

    for number, record in enumerate(incident.remediation_records, start=1):
        with st.container(border=True):
            st.markdown(f"**Remediation record {number}**")
            render_record(record)


def incident_table(session: SimulationSession, only_open: bool = False) -> pd.DataFrame:
    df = session.incidents.to_dataframe(session.now())
    if only_open and not df.empty:
        df = df[df["Status"] != RESOLVED]
    return df


# -------------------------------------------------------------------- pages ----
def page_dashboard(session: SimulationSession) -> None:
    st.subheader("Operations Dashboard")
    poll_buttons(session, "dash")
    k = session.kpis()
    cols = st.columns(7)
    cols[0].metric("Total Components", k["total"])
    cols[1].metric("Healthy", k["healthy"])
    cols[2].metric("Warnings", k["warning"])
    cols[3].metric("Critical", k["critical"])
    cols[4].metric("Open Incidents", k["open"])
    cols[5].metric("Resolved Incidents", k["resolved"])
    cols[6].metric("SLA At Risk", k["sla_at_risk"], help=f"Breached: {k['sla_breached']}")
    if k["sla_breached"]:
        st.error(f"{k['sla_breached']} open incident(s) have BREACHED the simulated SLA.")

    st.markdown("#### Alert correlation")
    raw, grouped = len(session.alerts), len(session.groups)
    a, b, c = st.columns(3)
    a.metric("Raw alerts (last analysis)", raw)
    b.metric("Correlated incidents", grouped)
    c.metric("Alerts merged", max(raw - grouped, 0))
    st.caption(f"Last analysis: {format_timestamp(session.last_analysis)} (simulated time). "
               "Rule-based correlation groups related symptoms into one incident.")

    st.markdown("#### Health overview")
    comps = session.components
    c1, c2 = st.columns(2)
    with c1:
        threshold_bar(chart_dataframe(comps, "cpu"), "CPU % by component", THRESHOLDS["cpu_warning"], "%", "dash_cpu")
    with c2:
        threshold_bar(chart_dataframe(comps, "memory"), "Memory % by component", THRESHOLDS["memory_warning"], "%", "dash_mem")
    c3, c4 = st.columns(2)
    with c3:
        threshold_bar(chart_dataframe(comps, "disk"), "Disk % by component", THRESHOLDS["disk_critical"], "%", "dash_disk")
    with c4:
        threshold_bar(chart_dataframe(comps, "latency_ms"), "Network latency (ms)", THRESHOLDS["latency_ms"], " ms", "dash_lat")
    df_all = session.incidents.to_dataframe(session.now())
    if df_all.empty:
        st.caption("Incident count: no incidents yet. Use Demo Scenarios to create some.")
    else:
        counts = df_all.groupby(["Priority", "Status"]).size().reset_index(name="Incidents")
        fig = px.bar(counts, x="Priority", y="Incidents", color="Status", barmode="stack",
                     title="Incident count by priority", color_discrete_map=STATUS_COLORS,
                     category_orders={"Priority": ["P1", "P2", "P3", "P4"]})
        fig.update_layout(height=300, margin=dict(l=10, r=10, t=45, b=10), title_font_size=15)
        show_chart(fig, "dash_inc")

    st.markdown("#### Active incidents")
    active = incident_table(session, only_open=True)
    if active.empty:
        st.success("No active incidents.")
    else:
        view = active[["Incident ID", "Component", "Problem", "Root Cause", "Priority", "SLA",
                       "SLA Remaining", "Status"]].rename(columns={"Problem": "Issue"})
        show_table(view)

    st.markdown("#### Infrastructure status")
    show_table(session.inventory()[["Component", "Type", "Health", "Last Check"]])


def page_infrastructure(session: SimulationSession) -> None:
    st.subheader("Infrastructure")
    st.caption("Simulated enterprise infrastructure. All values are simulated.")
    poll_buttons(session, "infra")
    inventory = session.inventory()
    types = st.multiselect("Filter by type", COMPONENT_TYPES, default=COMPONENT_TYPES, key="infra_types")
    show_table(inventory[inventory["Type"].isin(types)])

    st.markdown("#### Component detail")
    selected = st.selectbox("Component", [c["name"] for c in session.components], key="infra_sel")
    comp = next(c for c in session.components if c["name"] == selected)
    st.write(f"**{comp['name']}** - {comp['type']} - {comp['role']}")
    show_table(pd.DataFrame([{"Metric": metric_label(k), "Value": v} for k, v in comp["metrics"].items()]))
    if comp["type"] == "Active Directory":
        users = [{"User": u["user"], "Status": u["status"], "Groups": ", ".join(u["groups"]),
                  "Lockouts (last hour)": u["lockout_count"], "Lockout source": u["lockout_source"] or "-"}
                 for u in comp["details"]["users"]]
        st.markdown("**Users and group membership**")
        show_table(pd.DataFrame(users))
    if comp["type"] == "SQL Server":
        st.write("Databases: " + ", ".join(comp["details"]["databases"]))
        blocker = comp["details"].get("blocker")
        if blocker and comp["metrics"]["blocking_sessions"] > 0:
            st.markdown("**Blocking details**")
            st.json(blocker)
    alerts = [a for a in session.alerts if a.component == selected]
    if alerts:
        st.markdown("**Active alerts (last analysis)**")
        show_table(pd.DataFrame([{"Alert": a.category, "Severity": a.severity, "Detail": a.message} for a in alerts]))


def page_incidents(session: SimulationSession) -> None:
    st.subheader("Incidents")
    st.caption(SLA_LABEL)
    poll_buttons(session, "inc")
    df = incident_table(session)
    if df.empty:
        st.info("No incidents yet. Run Demo Scenarios, or inject a fault there and run detection.")
        return
    f1, f2, f3, f4 = st.columns(4)
    pr = f1.multiselect("Priority", sorted(df["Priority"].unique()), key="f_pr")
    co = f2.multiselect("Component", sorted(df["Component"].unique()), key="f_co")
    stt = f3.multiselect("Status", [OPEN, ESCALATED, RESOLVED], key="f_st")
    sl = f4.multiselect("SLA", [WITHIN, AT_RISK, BREACHED], key="f_sla")
    if pr:
        df = df[df["Priority"].isin(pr)]
    if co:
        df = df[df["Component"].isin(co)]
    if stt:
        df = df[df["Status"].isin(stt)]
    if sl:
        df = df[df["SLA"].isin(sl)]
    st.write(f"Showing {len(df)} incident(s)")
    show_table(df)

    st.markdown("#### Incident details")
    for incident_id in df["Incident ID"]:
        incident = session.incidents.get(incident_id)
        title = f"{incident.incident_id} | {incident.priority} | {incident.problem} | {incident.component} | {incident.status}"
        with st.expander(title):
            render_incident_detail(session, incident, "inc")


def page_monitoring(session: SimulationSession) -> None:
    st.subheader("Monitoring")
    st.caption("Simulated metrics. Press 'Poll metrics' to simulate a new polling cycle.")
    poll_buttons(session, "mon")
    health = session.health_map()
    history = session.history_dataframe()
    tabs = st.tabs(COMPONENT_TYPES)
    trend_metrics = {"Linux": ["cpu", "memory", "disk"], "Windows": ["cpu", "memory", "disk"],
                     "Azure VM": ["cpu", "memory"], "Network": ["latency_ms"]}
    for tab, ctype in zip(tabs, COMPONENT_TYPES):
        with tab:
            show_table(metrics_dataframe(session.components, ctype, health))
            if ctype == "Active Directory":
                ad = next(c for c in session.components if c["type"] == ctype)
                show_table(pd.DataFrame([{"User": u["user"], "Status": u["status"],
                                          "Groups": ", ".join(u["groups"]), "Lockouts": u["lockout_count"]}
                                         for u in ad["details"]["users"]]))
            if ctype in trend_metrics and not history.empty:
                names = [c["name"] for c in session.components if c["type"] == ctype]
                col_a, col_b = st.columns(2)
                comp = col_a.selectbox("Component", names, key=f"trend_c_{ctype}")
                metric = col_b.selectbox("Metric", trend_metrics[ctype], format_func=metric_label,
                                         key=f"trend_m_{ctype}")
                data = history[history["Component"] == comp]
                if len(data) < 2:
                    st.caption("Poll metrics at least twice to see a trend.")
                else:
                    fig = px.line(data, x="Time", y=metric, markers=True, title=f"{comp}: {metric_label(metric)}")
                    show_chart(style_fig(fig), f"trend_{ctype}")


def render_scenario(session: SimulationSession, sc: dict) -> None:
    sid = sc["id"]
    st.markdown(f"**{sc['summary']}**")
    st.write(f"Initial state: {sc['initial']}")
    exp = sc["expected"]
    st.caption(f"Expected: {exp['problem']} | Priority {exp['priority']} | {exp['ending']}")
    options = {}
    for name, spec in sc.get("options", {}).items():
        options[name] = st.selectbox(spec["label"], spec["choices"], key=f"{sid}_opt_{name}")

    state = session.scenario_state.get(sid)
    stage = state["stage"] if state else 0
    last_label = "3. Escalate to DBA" if sc.get("escalation_only") else "3. Remediate & verify"
    b1, b2, b3, b4 = st.columns(4)
    if b1.button("1. Inject fault", key=f"{sid}_b1"):
        session.scenario_inject(sid, **options)
        st.rerun()
    if b2.button("2. Detect & correlate", key=f"{sid}_b2", disabled=stage != 1):
        session.scenario_detect(sid)
        st.rerun()
    if b3.button(last_label, key=f"{sid}_b3", disabled=stage != 2):
        session.scenario_resolve(sid)
        st.rerun()
    if b4.button("▶ Run all steps", key=f"{sid}_b4"):
        session.scenario_run_all(sid, **options)
        st.rerun()

    if not state:
        st.info("Click 'Inject fault' for step-by-step, or 'Run all steps'.")
        return
    st.markdown("##### Step 1 - Fault injected (simulated state)")
    show_table(pd.DataFrame(state["before"]))
    if state["stage"] >= 2:
        st.markdown("##### Step 2 - Detection and correlation")
        if state["tree_before"]:
            st.markdown("**Decision tree: Ping → DNS → TCP**")
            show_table(pd.DataFrame(state["tree_before"]["steps"]))
            st.warning(f"Probable failure point: {state['tree_before']['failure_point']}")
        incident = session.incidents.get(state["incident_id"]) if state["incident_id"] else None
        if incident is None:
            st.error("No matching incident was found.")
            return
        if sid == "S4":
            blocker = next((c["details"]["blocker"] for c in session.components if c["name"] == "SQL-01"), None)
            if blocker:
                st.markdown("**Blocker identified**")
                st.json(blocker)
        if state["stage"] >= 3:
            st.markdown("##### Step 3 - Result (before → after)")
            show_table(pd.DataFrame(state["before"]).merge(
                pd.DataFrame(state["after"]), on=["Component", "Metric"], suffixes=(" (before)", " (after)")))
            if state["tree_after"]:
                st.markdown("**Decision tree after remediation**")
                show_table(pd.DataFrame(state["tree_after"]["steps"]))
            if incident.status == RESOLVED:
                st.success(f"{incident.incident_id} RESOLVED and verified (simulated).")
            elif incident.status == ESCALATED:
                st.warning(f"{incident.incident_id} escalated to the DBA. The session was NOT terminated.")
        st.markdown("##### Incident record")
        render_incident_detail(session, incident, f"scn-{sid}")
    st.caption(f"Interview point: {sc['talking_point']}")


def page_scenarios(session: SimulationSession) -> None:
    st.subheader("Demo Scenarios")
    st.caption("Each scenario injects a SIMULATED fault. Nothing touches a real system.")
    tabs = st.tabs([sc["tab"] for sc in SCENARIOS])
    for tab, sc in zip(tabs, SCENARIOS):
        with tab:
            render_scenario(session, sc)


def page_kb(session: SimulationSession) -> None:
    st.subheader("Knowledge Base")
    st.caption("Troubleshooting articles written for this simulation project.")
    c1, c2 = st.columns([3, 1])
    query = c1.text_input("Search", key="kb_q", placeholder="e.g. disk, lockout, blocking")
    category = c2.selectbox("Category", ["All"] + sorted({a["category"] for a in ARTICLES}), key="kb_cat")
    results = search_articles(query, category)
    st.write(f"{len(results)} article(s)")
    for article in results:
        with st.expander(f"{article['id']} | {article['title']}"):
            st.write(f"**Problem:** {article['problem']}")
            for heading, key in (("Symptoms", "symptoms"), ("Checks", "checks"),
                                 ("Recommended solution", "resolution"), ("Verification", "verification")):
                st.markdown(f"**{heading}**")
                for item in article[key]:
                    st.write(f"- {item}")
            st.markdown(f"**Escalation:** {article['escalation']}")


def page_reports(session: SimulationSession) -> None:
    st.subheader("Reports")
    st.warning("All figures below come from SIMULATED incidents in this session.")
    df = session.incidents.to_dataframe(session.now())
    if df.empty:
        st.info("No incidents yet. Run some Demo Scenarios first.")
    else:
        resolved = df[df["Status"] == RESOLVED]
        times = [(i.resolved_at - i.created_at).total_seconds() for i in session.incidents.resolved_incidents()]
        avg = format_timedelta(pd.Timedelta(seconds=sum(times) / len(times)).to_pytimedelta()) if times else "-"
        met = int((resolved["SLA"] == WITHIN).sum())
        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total incidents", len(df))
        k2.metric("Open / escalated", int((df["Status"] != RESOLVED).sum()))
        k3.metric("Resolved", len(resolved))
        k4.metric("Avg simulated resolution time", avg)
        k5.metric("Resolved within SLA", f"{met}/{len(resolved)}" if len(resolved) else "-")

        c1, c2 = st.columns(2)
        with c1:
            data = df.groupby("Priority").size().reset_index(name="Incidents")
            fig = px.bar(data, x="Priority", y="Incidents", title="Incidents by priority", text_auto=True,
                         color_discrete_sequence=[NORMAL], category_orders={"Priority": ["P1", "P2", "P3", "P4"]})
            show_chart(style_fig(fig), "rep_pr")
        with c2:
            data = df.groupby("Component").size().reset_index(name="Incidents")
            fig = px.bar(data, x="Component", y="Incidents", title="Incidents by component", text_auto=True,
                         color_discrete_sequence=[NORMAL])
            show_chart(style_fig(fig), "rep_co")
        c3, c4 = st.columns(2)
        with c3:
            data = df.groupby("Status").size().reset_index(name="Incidents")
            fig = px.bar(data, x="Status", y="Incidents", color="Status", title="Resolved vs open",
                         text_auto=True, color_discrete_map=STATUS_COLORS)
            show_chart(style_fig(fig), "rep_status")
        with c4:
            data = df.groupby("SLA").size().reset_index(name="Incidents")
            fig = px.bar(data, x="SLA", y="Incidents", title="SLA performance (simulated targets)",
                         text_auto=True, color_discrete_sequence=[NORMAL])
            show_chart(style_fig(fig), "rep_sla")
        data = df.groupby("Problem").size().reset_index(name="Incidents").sort_values("Incidents")
        fig = px.bar(data, x="Incidents", y="Problem", orientation="h", title="Most common issue types",
                     text_auto=True, color_discrete_sequence=[NORMAL])
        show_chart(style_fig(fig, 280), "rep_types")

        st.markdown("#### Incident history export")
        st.download_button("Download incidents (CSV)", df.to_csv(index=False).encode("utf-8"),
                           file_name="itops_guardian_incidents_simulated.csv", mime="text/csv", key="dl_csv")

    st.markdown("#### Simulated SLA targets")
    st.caption(SLA_LABEL)
    show_table(pd.DataFrame([{"Priority": priority_label(p), "Resolution target (hours)": h}
                             for p, h in SLA_TARGET_HOURS.items()]))
    st.markdown("#### Remediation audit log")
    if session.audit_log:
        show_table(pd.DataFrame(session.audit_log))
    else:
        st.caption("No remediation actions yet.")


# -------------------------------------------------------------------- main ----
PAGE_FUNCTIONS = {
    "Dashboard": page_dashboard, "Infrastructure": page_infrastructure, "Incidents": page_incidents,
    "Monitoring": page_monitoring, "Demo Scenarios": page_scenarios, "Knowledge Base": page_kb,
    "Reports": page_reports,
}


def main() -> None:
    session = get_session()
    page = render_sidebar(session)
    st.title("🛡️ ITOps Guardian")
    st.caption("IT Infrastructure Health & Incident Simulator  |  Self-developed simulation project")
    pipeline_banner()
    st.info(SIMULATION_NOTICE)
    PAGE_FUNCTIONS[page](session)


main()
