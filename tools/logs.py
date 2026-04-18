"""
tools/logs.py
Simulates structured log analysis (Windows Event Log, Sysmon, Syslog).

Analyses:
  - High-risk event IDs (4688 new process, 4624/4625 logon/fail,
    7045 service install, 1102 audit clear, Sysmon EID 13 registry)
  - Failed-then-succeeded authentication patterns (brute force)
  - Audit log clearing events (anti-forensic)
  - Service installation events (persistence)
  - Pattern correlation: identifies if log events corroborate
    or contradict process / timeline findings
"""

from typing import Optional


# Event IDs we care about and their plain-English meanings
HIGH_RISK_EVENT_IDS: dict[int, dict] = {
    4688: {"name": "Process Create",         "severity": "medium", "category": "execution"},
    4624: {"name": "Logon Success",           "severity": "info",   "category": "authentication"},
    4625: {"name": "Logon Failure",           "severity": "medium", "category": "authentication"},
    4648: {"name": "Logon with Explicit Creds","severity": "high",  "category": "authentication"},
    4698: {"name": "Scheduled Task Created",  "severity": "high",  "category": "persistence"},
    4702: {"name": "Scheduled Task Updated",  "severity": "medium","category": "persistence"},
    7045: {"name": "Service Installed",       "severity": "high",   "category": "persistence"},
    1102: {"name": "Audit Log Cleared",       "severity": "critical","category": "anti_forensic"},
    4732: {"name": "Member Added to Group",   "severity": "high",   "category": "privilege_escalation"},
    4720: {"name": "User Account Created",    "severity": "high",   "category": "persistence"},
    13:   {"name": "Registry Value Set (Sysmon)","severity": "high","category": "persistence"},
}

ANTI_FORENSIC_EIDS = {1102, 1100, 104}
PERSISTENCE_EIDS   = {7045, 4698, 4702, 4720, 13}
AUTH_FAIL_EID      = 4625
AUTH_SUCCESS_EID   = 4624


# ------------------------------------------------------------------ #
#  Public tool function                                                #
# ------------------------------------------------------------------ #

def parse_logs(
    data: dict,
    filter_level: str = "all",
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> dict:
    """
    Parse and analyse log entries from forensic data.

    Args:
        data:         Full forensic data dict (must contain 'logs' key).
        filter_level: 'all' | 'critical' | 'high' — restrict output
                      to entries at or above the given severity level.
        start_time:   ISO-8601 string for time-window start (inclusive).
        end_time:     ISO-8601 string for time-window end (inclusive).

    Returns:
        Structured dict with categorised log entries, critical events,
        detected patterns, and statistics.
    """
    raw_logs = data.get("logs", [])

    # Apply time-window filter
    logs = _filter_by_time(raw_logs, start_time, end_time)

    # Apply severity filter
    if filter_level in ("critical", "high"):
        allowed_severities = {"critical"} if filter_level == "critical" else {"critical", "high"}
        logs = [
            l for l in logs
            if _eid_severity(l.get("event_id", 0)) in allowed_severities
        ]

    critical_events:   list[dict] = []
    persistence_events: list[dict] = []
    anti_forensic_events: list[dict] = []
    auth_events:       list[dict] = []
    enriched_logs:     list[dict] = []

    for entry in logs:
        eid = entry.get("event_id", 0)
        meta = HIGH_RISK_EVENT_IDS.get(eid, {})
        severity = meta.get("severity", "info")
        category = meta.get("category", "other")

        enriched = {
            **entry,
            "severity": severity,
            "category": category,
            "eid_name": meta.get("name", f"Event {eid}"),
        }
        enriched_logs.append(enriched)

        if severity == "critical" or eid in (ANTI_FORENSIC_EIDS | PERSISTENCE_EIDS):
            critical_events.append(enriched)

        if eid in ANTI_FORENSIC_EIDS:
            anti_forensic_events.append({
                **enriched,
                "interpretation": _anti_forensic_interpretation(eid),
            })

        if eid in PERSISTENCE_EIDS:
            persistence_events.append({
                **enriched,
                "interpretation": _persistence_interpretation(eid, entry),
            })

        if eid in (AUTH_FAIL_EID, AUTH_SUCCESS_EID):
            auth_events.append(enriched)

    # --- Pattern: brute-force (multiple failures → success) ---
    brute_force_patterns = _detect_brute_force(auth_events)

    # --- Flag correlation gaps ---
    # Were processes created (EID 4688) logged? Compare counts vs process list
    process_create_logs = [l for l in enriched_logs if l.get("event_id") == 4688]
    known_processes = data.get("processes", [])
    log_process_names = {
        l.get("details", {}).get("new_process", "").split("\\")[-1].lower()
        for l in process_create_logs
    }
    data_process_names = {p.get("name", "").lower() for p in known_processes}
    unlogged_processes = data_process_names - log_process_names

    return {
        "tool": "parse_logs",
        "filter_level": filter_level,
        "time_window": {"start": start_time, "end": end_time},
        "log_entries": enriched_logs,
        "critical_events": critical_events,
        "persistence_events": persistence_events,
        "anti_forensic_events": anti_forensic_events,
        "authentication_events": auth_events,
        "brute_force_patterns": brute_force_patterns,
        "correlation_gaps": {
            "unlogged_processes": list(unlogged_processes),
            "description": (
                "Processes present in the process list but absent from Event ID 4688 logs "
                "— this may indicate log tampering or gaps in audit policy."
                if unlogged_processes else "All known processes are represented in the logs."
            ),
        },
        "statistics": {
            "total_log_entries": len(enriched_logs),
            "critical_count": len(critical_events),
            "anti_forensic_count": len(anti_forensic_events),
            "persistence_count": len(persistence_events),
            "auth_failure_count": sum(1 for e in auth_events if e.get("event_id") == AUTH_FAIL_EID),
            "event_id_breakdown": _count_field(raw_logs, "event_id"),
        },
    }


# ------------------------------------------------------------------ #
#  Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _eid_severity(eid: int) -> str:
    return HIGH_RISK_EVENT_IDS.get(eid, {}).get("severity", "info")


def _anti_forensic_interpretation(eid: int) -> str:
    interps = {
        1102: "Security audit log cleared — attacker may be covering tracks",
        1100: "Event log service shut down — possible anti-forensic action",
        104:  "System log cleared",
    }
    return interps.get(eid, "Anti-forensic indicator")


def _persistence_interpretation(eid: int, entry: dict) -> str:
    details = entry.get("details", {})
    if eid == 7045:
        svc = details.get("service_name", "unknown")
        path = details.get("service_file", "unknown")
        return f"Service '{svc}' installed at '{path}' — potential persistence mechanism"
    if eid in (4698, 4702):
        return "Scheduled task created/modified — possible persistence mechanism"
    if eid == 13:
        reg_key = details.get("target_object", "unknown")
        return f"Registry persistence key written: {reg_key}"
    if eid == 4720:
        return "New user account created — possible backdoor account"
    return "Persistence-related event"


def _detect_brute_force(auth_events: list[dict]) -> list[dict]:
    """
    Detect sequences of failed logins followed by a success from the same
    user or source, which may indicate a brute-force / password-spray attack.
    """
    patterns: list[dict] = []
    failures: list[dict] = []

    for event in sorted(auth_events, key=lambda x: x.get("timestamp", "")):
        if event.get("event_id") == AUTH_FAIL_EID:
            failures.append(event)
        elif event.get("event_id") == AUTH_SUCCESS_EID and len(failures) >= 3:
            patterns.append({
                "type": "brute_force_pattern",
                "failure_count": len(failures),
                "first_failure": failures[0].get("timestamp"),
                "success_timestamp": event.get("timestamp"),
                "success_event": event,
                "severity": "high",
                "description": (
                    f"{len(failures)} consecutive login failure(s) followed by a successful "
                    "logon — possible brute-force or credential stuffing attack"
                ),
            })
            failures = []  # reset after pattern captured

    return patterns


def _filter_by_time(logs: list, start: Optional[str], end: Optional[str]) -> list:
    if not start and not end:
        return logs
    result = []
    for entry in logs:
        ts = entry.get("timestamp", "")
        if not ts:
            result.append(entry)
            continue
        if start and ts < start:
            continue
        if end and ts > end:
            continue
        result.append(entry)
    return result


def _count_field(items: list, field: str) -> dict:
    counts: dict = {}
    for item in items:
        val = str(item.get(field, "unknown"))
        counts[val] = counts.get(val, 0) + 1
    return counts
