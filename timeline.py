"""
tools/timeline.py
Simulates forensic timeline analysis (analogous to log2timeline / plaso).

The tool accepts raw forensic data and returns a structured analysis of:
  - Chronologically ordered events
  - Off-hours activity anomalies
  - Rapid-fire event clusters (suggesting automation)
  - Suspicious file paths
  - Deep-mode: registry persistence artefacts

In a real SIFT environment this would call log2timeline, mactime, or plaso.
"""

from datetime import datetime, timezone
from typing import Optional


# Hours considered "off-hours" for a typical corporate workstation
BUSINESS_HOURS_START = 6   # 06:00 UTC
BUSINESS_HOURS_END = 22    # 22:00 UTC

# File path fragments that suggest malicious intent
SUSPICIOUS_PATH_FRAGMENTS = [
    "\\appdata\\local\\temp\\",
    "\\temp\\",
    "\\tmp\\",
    "payload",
    "\\programdata\\",
    ".exe",
    ".bat",
    ".ps1",
    ".vbs",
    ".hta",
    ".jar",
]

# Minimum gap (seconds) between events; below this suggests scripted/automated activity
RAPID_EVENT_THRESHOLD_SECONDS = 3.0


# ------------------------------------------------------------------ #
#  Public tool function                                                #
# ------------------------------------------------------------------ #

def get_timeline(
    data: dict,
    focus_window: Optional[str] = None,
    depth: str = "standard",
) -> dict:
    """
    Perform timeline analysis on forensic data.

    Args:
        data:         Full forensic data dict (must contain 'events' key).
        focus_window: Optional ISO-8601 range string "start,end" to
                      restrict analysis to a specific time window.
        depth:        'standard' for normal analysis, 'deep' for extended
                      artefact recovery (registry, MFT changes, etc.).

    Returns:
        Structured dict with events, anomalies, and statistics.
    """
    raw_events = data.get("events", [])

    # Apply optional time window filter
    events = _filter_by_window(raw_events, focus_window)

    # Sort chronologically
    events = sorted(events, key=lambda x: x.get("timestamp", ""))

    anomalies = []
    suspicious_timeframes = []

    # --- Anomaly: off-hours activity ---
    for event in events:
        ts = event.get("timestamp", "")
        if ts:
            dt = _parse_ts(ts)
            if dt and (dt.hour < BUSINESS_HOURS_START or dt.hour >= BUSINESS_HOURS_END):
                anomalies.append({
                    "type": "off_hours_activity",
                    "severity": "medium",
                    "timestamp": ts,
                    "hour_utc": dt.hour,
                    "description": (
                        f"Activity at {dt.hour:02d}:{dt.minute:02d} UTC — "
                        f"outside business hours ({BUSINESS_HOURS_START:02d}:00–{BUSINESS_HOURS_END:02d}:00 UTC)"
                    ),
                    "event_ref": event,
                })

    # --- Anomaly: rapid succession of events (possible automation) ---
    for i in range(1, len(events)):
        t_prev = _parse_ts(events[i - 1].get("timestamp", ""))
        t_curr = _parse_ts(events[i].get("timestamp", ""))
        if t_prev and t_curr:
            delta = (t_curr - t_prev).total_seconds()
            if 0 <= delta < RAPID_EVENT_THRESHOLD_SECONDS:
                suspicious_timeframes.append({
                    "start": events[i - 1].get("timestamp"),
                    "end": events[i].get("timestamp"),
                    "gap_seconds": round(delta, 2),
                    "description": (
                        f"Events separated by only {delta:.1f}s — "
                        "possible scripted/automated execution"
                    ),
                    "events": [events[i - 1], events[i]],
                })

    # --- Anomaly: suspicious file paths ---
    for event in events:
        path = event.get("path", "").lower()
        matched = [f for f in SUSPICIOUS_PATH_FRAGMENTS if f in path]
        if matched and not any(
            a.get("event_ref") == event for a in anomalies
        ):
            anomalies.append({
                "type": "suspicious_path",
                "severity": "high",
                "timestamp": event.get("timestamp"),
                "matched_fragments": matched,
                "description": (
                    f"Event involves suspicious path: {event.get('path', 'N/A')}"
                    f" (matched: {', '.join(matched)})"
                ),
                "event_ref": event,
            })

    # --- Deep mode: network-related events and registry artefacts ---
    deep_artifacts = []
    if depth == "deep":
        for event in events:
            if event.get("type") == "registry_write":
                deep_artifacts.append({
                    "artifact_type": "registry_persistence",
                    "severity": "high",
                    "timestamp": event.get("timestamp"),
                    "description": (
                        f"Registry write to persistence key: {event.get('path', 'N/A')}"
                    ),
                    "event_ref": event,
                })
            if event.get("type") in ("shadow_copy_deletion",):
                deep_artifacts.append({
                    "artifact_type": "anti_forensic",
                    "severity": "critical",
                    "timestamp": event.get("timestamp"),
                    "description": (
                        "Anti-forensic action detected: shadow copy deletion prevents recovery"
                    ),
                    "event_ref": event,
                })

    # --- Large data transfer detection ---
    for event in events:
        bytes_sent = event.get("bytes_sent", 0)
        if bytes_sent > 1_000_000:  # > 1 MB outbound
            anomalies.append({
                "type": "data_exfiltration_indicator",
                "severity": "critical",
                "timestamp": event.get("timestamp"),
                "bytes_sent": bytes_sent,
                "description": (
                    f"Large outbound transfer: {bytes_sent / 1_048_576:.1f} MB sent to "
                    f"{event.get('destination_ip', 'unknown')}:{event.get('destination_port', '?')}"
                ),
                "event_ref": event,
            })

    return {
        "tool": "get_timeline",
        "analysis_depth": depth,
        "focus_window": focus_window,
        "events": events,
        "anomalies": anomalies,
        "suspicious_timeframes": suspicious_timeframes,
        "deep_artifacts": deep_artifacts,
        "statistics": {
            "total_events": len(events),
            "anomaly_count": len(anomalies),
            "suspicious_timeframe_count": len(suspicious_timeframes),
            "deep_artifact_count": len(deep_artifacts),
            "event_type_breakdown": _count_field(events, "type"),
            "earliest_event": events[0].get("timestamp") if events else None,
            "latest_event": events[-1].get("timestamp") if events else None,
        },
    }


# ------------------------------------------------------------------ #
#  Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _parse_ts(ts: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp string, returning None on failure."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _filter_by_window(events: list, window: Optional[str]) -> list:
    """Return only events within the 'start,end' window (if provided)."""
    if not window:
        return events
    try:
        start_str, end_str = window.split(",")
        start = _parse_ts(start_str.strip())
        end = _parse_ts(end_str.strip())
        if not start or not end:
            return events
        return [
            e for e in events
            if start <= (_parse_ts(e.get("timestamp", "")) or start) <= end
        ]
    except Exception:
        return events


def _count_field(items: list, field: str) -> dict:
    """Count occurrences of each unique value for a given field."""
    counts: dict = {}
    for item in items:
        val = item.get(field, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts
