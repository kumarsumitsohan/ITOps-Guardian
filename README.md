# ITOps Guardian – IT Infrastructure Health & Incident Simulator

> **Self-developed simulation project.** ITOps Guardian runs in a *self-developed simulated enterprise
> infrastructure environment*. It is **not** a real production system, not a company internal tool and
> not a customer project. All servers, metrics, incidents, SLA targets and results are **simulated**.

## 1. Project title

**ITOps Guardian – IT Infrastructure Health & Incident Simulator**

## 2. Project overview

ITOps Guardian is a small NOC-style console built with Python and Streamlit. It simulates 12
infrastructure components (Linux, Windows, Active Directory, SQL Server, network, Azure VMs), checks their
health, turns alerts into meaningful incidents, assigns priority and SLA targets, performs safe simulated
remediation and **verifies** that the problem is really gone.

```
MONITOR -> DETECT -> CORRELATE -> PRIORITIZE -> REMEDIATE -> VERIFY
```

## 3. Problem statement

In a real IT operations team one underlying fault (for example a full disk) creates many alerts: high log
errors, slow application, database connection failures. Treating each alert as a separate ticket creates
noise, duplicated work and slow root-cause analysis. Support engineers need to see *one* incident, the
*probable root cause*, a *priority*, a *deadline* and the *next safe step*.

## 4. Objectives

- Practise the daily work of an infrastructure support engineer in a safe simulated environment.
- Show incident management basics: detection, priority (impact x urgency), SLA, remediation, verification.
- Show **alert correlation** with understandable, rule-based logic.
- Keep the technology simple: Python, Streamlit, Pandas, Plotly. No database, no Docker, no internet.

## 5. Features

| Area | What it does |
|---|---|
| Infrastructure simulator | 12 components: 3 Linux, 2 Windows, 1 AD (6 users), 2 SQL Server, 2 network, 2 Azure VMs |
| Monitoring | Per-type metric tables, simulated polling, trend charts |
| Detection | Threshold rules (CPU > 85%, disk > 90%, packet loss > 10%, service stopped, lockouts, SQL blocking, Azure CPU > 85%) |
| **Correlation engine** | Groups related alerts into ONE incident with root cause, confidence and reasoning |
| Priority | Impact x Urgency matrix -> P1 / P2 / P3 / P4 with a written reason |
| SLA | Simulated targets P1 4h, P2 8h, P3 24h, P4 72h. Within SLA / At Risk / Breached. Simulated clock slider |
| Remediation | Before -> Action -> After -> Verification -> Audit entry |
| Knowledge base | 6 searchable troubleshooting articles |
| Incident history | Filter by priority, component, status, SLA. CSV export |
| Demo scenarios | 6 scenarios, step-by-step or one click |
| Reports | Counts, charts, SLA performance, average simulated resolution time, audit log |
| Tests | 45 pytest tests |

## 6. Architecture

```
app.py (Streamlit UI)  ->  engine/session.py (one simulation session)
                                |
   data/infrastructure.py  ->  engine/monitoring.py  ->  engine/detection.py
                                                              |
                                                     engine/correlation.py
                                                              |
                                  engine/incident.py  +  engine/sla.py
                                                              |
                                                     engine/remediation.py (+ verification)
```

All logic is in `engine/` and is tested without Streamlit. `app.py` only displays things and handles buttons.

## 7. Technology stack

Python 3.12, Streamlit, Pandas, Plotly, Python standard library. pytest for tests.
No Docker, no database, no external API, no internet needed after installation.

## 8. Folder structure

```
ITOps-Guardian/
├── app.py                     Streamlit user interface
├── requirements.txt
├── README.md
├── pytest.ini
├── run.ps1                    optional one-step setup + start script
├── .gitignore
├── data/
│   ├── infrastructure.py      simulated components and healthy baseline values
│   ├── scenarios.py           the six demo scenarios (fault injection)
│   └── knowledge_base.py      troubleshooting articles
├── engine/
│   ├── monitoring.py          polling, tables, network decision tree
│   ├── detection.py           thresholds -> alerts
│   ├── correlation.py         rule-based alert correlation
│   ├── incident.py            priority matrix, incident records, history
│   ├── sla.py                 simulated SLA calculation
│   ├── remediation.py         simulated fixes, verification, audit entries
│   └── session.py             connects all steps for the UI
├── utils/helpers.py           formatting helpers
├── tests/                     pytest tests
└── screenshots/               add your own screenshots here
```

## 9. Installation (Windows PowerShell)

```powershell
cd path\to\ITOps-Guardian
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks the activation script, run once:
`Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

## 10. Running the application

```powershell
python -m streamlit run app.py
```

Open http://localhost:8501 (it opens automatically). Stop with `Ctrl + C`.

## 11. Demo scenarios

Open **Demo Scenarios**. Use *Inject fault -> Detect & correlate -> Remediate* or *Run all steps*.
Use **Reset environment** in the sidebar to start clean.

| # | Scenario | What the system does |
|---|---|---|
| 1 | Linux disk exhaustion | Disk 94%, log errors HIGH, response 4.8 s, SQL failures HIGH -> ONE incident "Application Performance Degradation", root cause "Linux Disk Exhaustion", P2, simulated log cleanup, disk 94% -> 61%, verified, resolved |
| 2 | Windows service failure | Service STOPPED -> P2, restart, RUNNING verified, resolved |
| 3 | Active Directory lockout | Repeated lockouts from one device -> probable stale credentials, unlock, ACTIVE verified |
| 4 | SQL blocking | Shows the blocker and affected query, P2, **escalates to DBA; never kills the session** |
| 5 | Network connectivity | Ping -> DNS -> TCP decision tree (choose the failure point), P1, fix, re-test |
| 6 | Azure VM CPU alert | CPU 92% -> P3, acknowledge, simulated recovery, CPU normal verified |

## 12. Incident correlation explanation

The engine (`engine/correlation.py`) is **rule-based**: hand-written if/then rules. It is **not machine learning**.

Example rule "disk exhaustion cascade": a Linux server with `CRITICAL DISK` **plus at least two** of
`HIGH LOG ERRORS`, `SLOW APPLICATION RESPONSE`, `SQL CONNECTION FAILURES` on the **same server**
becomes one incident. A full disk stops logs and temp files from being written, which slows the application
and breaks its database connections, so the disk is the probable root cause and the rest are symptoms.

Other rules: network path to database (Ping -> DNS -> TCP, first failing step wins), SQL blocking
cascade, Windows service failure with Event Log errors, repeated AD lockout (stale credentials when
most failed attempts come from one source). Alerts no rule claims become their own incident
(one per component and alert type). Each incident shows related events, probable root cause,
confidence, reasoning, priority and recommended action. The Dashboard shows "raw alerts -> correlated incidents".

## 13. SLA explanation

**Simulated Project SLA Targets** (project-defined, not a real company policy):

| Priority | Resolution target |
|---|---|
| P1 Critical | 4 hours |
| P2 High | 8 hours |
| P3 Medium | 24 hours |
| P4 Low | 72 hours |

*Within SLA*: more than 25% of the time left. *At Risk*: 25% or less left. *Breached*: target time passed.
Use the **Simulated clock** slider in the sidebar to move time forward and watch the status change.
Priority comes from the impact x urgency matrix (for example High impact + Medium urgency = P2).

## 14. Remediation explanation

Every remediation shows **Before -> Action -> After -> Verification -> Audit log entry**. Fixes only change
the in-memory simulated environment. Verification re-runs detection: the incident resolves only if every
alert of the incident is gone. SQL blocking is **never** fixed automatically: the incident is escalated to
a DBA and no session is terminated. The "Simulate DBA resolution" button represents a human action.
A simulated duration per fix is used to calculate the simulated resolution time.

## 15. Testing

```powershell
python -m pytest
```

45 tests cover threshold detection, correlation, priority, SLA, remediation and verification, and all six scenarios end to end.

## 16. Screenshots

Add your own screenshots to the `screenshots/` folder after running the app, for example
`dashboard.png`, `incident-correlation.png`, `scenario-disk.png`, then link them here:

```
![Dashboard](screenshots/dashboard.png)
```

## 17. Future enhancements

- Save incident history to a file or SQLite database.
- More correlation rules (for example AD + VPN, cluster failover) and a rule configuration file.
- Event time-line per incident and a real "ticket" workflow (assign, comment, close).
- Import real exported logs/CSV metrics instead of simulated values.
- Learn from history (an actual ML approach), clearly separated from the rule-based engine.

## 18. Interview explanation

**30-second version**

"ITOps Guardian is a self-developed simulated IT infrastructure monitoring and incident-management
platform. It simulates different enterprise infrastructure components, detects health issues, correlates
related alerts into meaningful incidents, assigns priority and project-defined SLA targets, recommends
controlled remediation, and verifies the result."

**Key flow:** Monitor -> Detect -> Correlate -> Prioritize -> Remediate -> Verify.

**Main talking point:** one full disk caused four alerts; the correlation engine made *one* incident
"Application Performance Degradation" with root cause "Linux Disk Exhaustion", priority P2, and verified
that disk went 94% -> 61% after the simulated log cleanup.

**Be honest and clear:**
- It is a self-developed simulation. The data is simulated. It was not used in a real company or for a customer.
- The correlation is rule-based, not machine learning.
- The SLA targets are project-defined examples, not any company's policy.

**Questions you can expect**

- *Why P2 and not P1?* Impact is High (application affected) but urgency is Medium (partially available).
- *Why not kill the blocking SQL session?* It can roll back important work; a DBA must decide.
- *How do you know the fix worked?* Verification re-runs detection; the incident closes only if all alerts are gone.
- *How would you check this on a real Linux server?* `df -h`, `du -sh /var/log/*`, log rotation, then `df -h` again.
- *What would you improve?* Persistent storage, more rules, real log import.
