"""Built-in troubleshooting knowledge base (written for this simulation project)."""
from __future__ import annotations

ARTICLES = [
    {
        "id": "KB-LNX-DISK", "category": "Linux", "title": "Linux disk usage above 90%",
        "problem": "A Linux filesystem is almost full. Applications cannot write logs or temp files and slow down or fail.",
        "symptoms": ["Disk usage above 90%", "Application log errors increase", "Slow application response",
                     "Database connection failures from the application"],
        "checks": ["df -h  (which filesystem is full?)", "du -sh /var/log/* | sort -h  (largest logs)",
                   "ls -lh /var/log  (log files and ages)", "journalctl --disk-usage  (systemd journal size)",
                   "Check whether log rotation is configured: cat /etc/logrotate.conf"],
        "resolution": ["Identify the large log files", "Rotate or compress logs (logrotate -f /etc/logrotate.conf)",
                       "Archive or remove logs older than the retention period",
                       "Fix the cause (for example debug logging left on)"],
        "verification": ["df -h shows usage below 80%", "Application response time is back to normal",
                         "Log error rate returns to LOW"],
        "escalation": "If space does not free up, or the data is not logs, escalate to the Linux/system owner.",
    },
    {
        "id": "KB-WIN-SVC", "category": "Windows", "title": "Windows service failure",
        "problem": "A Windows service is STOPPED and the application that depends on it does not work.",
        "symptoms": ["Service status STOPPED", "Event Log errors increase", "Users cannot use the application"],
        "checks": ["Get-Service -Name <name>  (current status)",
                   "Event Viewer > Windows Logs > System / Application (why did it stop?)",
                   "Get-WinEvent -LogName System -MaxEvents 50",
                   "Check dependencies: Get-Service <name> -DependentServices / -RequiredServices"],
        "resolution": ["Make sure dependent services are running", "Restart-Service <name>",
                       "If it stops again, collect the Event Log error and escalate"],
        "verification": ["Get-Service shows RUNNING", "No new errors in the Event Log", "Application works for a test user"],
        "escalation": "If the service keeps stopping, escalate to the application owner with the Event Log details.",
    },
    {
        "id": "KB-AD-LOCKOUT", "category": "Active Directory", "title": "Active Directory account repeatedly locked",
        "problem": "A user account locks again and again, usually because an old password is saved somewhere.",
        "symptoms": ["Account status LOCKED", "Many lockouts in a short time", "Bad password attempts from one device"],
        "checks": ["Get-ADUser <user> -Properties LockedOut,BadLogonCount  (current state)",
                   "Find the lockout source: security event 4740 on the domain controller",
                   "Check stale credentials on that device: mapped drives, saved passwords, scheduled tasks, "
                   "services, phone mail profile",
                   "Confirm the account is not expired or disabled"],
        "resolution": ["Unlock-ADAccount <user>", "Reset the password if required",
                       "Update or remove the stale credentials on the source device",
                       "Ask the user to sign in again"],
        "verification": ["Account status is ACTIVE", "No new lockouts after 30 minutes"],
        "escalation": "If attempts come from many unknown sources, involve the security team (possible attack).",
    },
    {
        "id": "KB-SQL-BLOCKING", "category": "SQL Server", "title": "SQL Server blocking",
        "problem": "One session holds locks and other sessions wait for it, so queries slow down or time out.",
        "symptoms": ["Blocking sessions detected", "Connection failures increase", "Slow application response"],
        "checks": ["EXEC sp_who2  (look at the BlkBy column)",
                   "SELECT * FROM sys.dm_exec_requests WHERE blocking_session_id <> 0",
                   "Identify the blocked query and how long it has waited",
                   "Check database health and log space"],
        "resolution": ["Document the blocker, the blocked query and the wait time",
                       "Escalate to the DBA", "Do NOT kill sessions without DBA approval"],
        "verification": ["Blocking sessions = 0", "Connection failures back to normal"],
        "escalation": "Always escalate to the DBA. Killing a session can roll back important work.",
    },
    {
        "id": "KB-NET-CONN", "category": "Network", "title": "Network connectivity (application cannot reach database)",
        "problem": "An application server cannot connect to its database server.",
        "symptoms": ["SQL connection failures from the application", "Ping, DNS or TCP checks fail",
                     "Packet loss or high latency"],
        "checks": ["ping <db-server>  (is the host reachable?)", "nslookup <db-server>  (does the name resolve?)",
                   "Test-NetConnection <db-server> -Port 1433  (is the port reachable?)",
                   "Check latency and packet loss: ping -n 20 <db-server>", "tracert <db-server>  (where does it stop?)"],
        "resolution": ["Work in order: Ping, then DNS, then TCP", "Fix the FIRST failing step",
                       "Ping fail: check link, routing. DNS fail: check DNS server and cache. "
                       "TCP fail: check firewall and the database listener"],
        "verification": ["Ping, DNS and TCP all pass", "Application connects to the database"],
        "escalation": "Escalate to the network team if routing or firewall changes are needed.",
    },
    {
        "id": "KB-AZ-VM", "category": "Azure VM", "title": "Azure VM performance alert",
        "problem": "An Azure virtual machine has high CPU or other metrics above the alert threshold.",
        "symptoms": ["VM CPU above 85%", "Active alerts on the VM", "Slow workloads"],
        "checks": ["Check VM CPU and memory metrics in Azure Monitor (concept)", "Check VM status: running / stopped",
                   "Check network in/out for unusual traffic", "Look for a runaway process inside the VM"],
        "resolution": ["Acknowledge the alert", "Identify the heavy workload", "Fix the workload or resize the VM",
                       "Verify the metrics are back to normal"],
        "verification": ["CPU below 85%", "No active alerts"],
        "escalation": "If resizing is needed, escalate to the cloud team for a change request.",
    },
]


def get_article(article_id: str) -> dict | None:
    return next((a for a in ARTICLES if a["id"] == article_id), None)


def search_articles(query: str = "", category: str = "All") -> list[dict]:
    """Simple text search over title, problem, symptoms and checks."""
    query = query.strip().lower()
    results = []
    for article in ARTICLES:
        if category != "All" and article["category"] != category:
            continue
        haystack = " ".join([article["title"], article["problem"], " ".join(article["symptoms"]),
                             " ".join(article["checks"])]).lower()
        if query in haystack:
            results.append(article)
    return results
