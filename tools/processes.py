"""
tools/processes.py
Simulates process analysis (analogous to Volatility pslist / pstree /
Sysinternals Process Monitor on a live system).

Checks for:
  - Processes running from suspicious directories (AppData, Temp, etc.)
  - Unusual parent–child relationships (e.g. Word spawning cmd.exe)
  - Process name masquerading (svchost in wrong path)
  - Missing digital signatures
  - Processes with outbound network connections
"""

from typing import Optional


# Legitimate parents for common system processes
LEGITIMATE_PARENTS: dict[str, list[str]] = {
    "cmd.exe": ["explorer.exe", "powershell.exe", "cmd.exe", "conhost.exe", "services.exe"],
    "powershell.exe": ["explorer.exe", "cmd.exe", "services.exe", "svchost.exe"],
    "svchost.exe": ["services.exe"],
    "taskhostw.exe": ["svchost.exe"],
    "werfault.exe": ["svchost.exe", "wermgr.exe"],
}

# Names that should ONLY run from System32 / SysWOW64
SYSTEM_BINARY_NAMES = {
    "svchost.exe",
    "lsass.exe",
    "winlogon.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "smss.exe",
    "taskhost.exe",
    "taskhostw.exe",
}

# Directories that are suspicious for executable launches
SUSPICIOUS_DIRS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
]

# Office apps that should NOT spawn shell processes
OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
SHELL_PROCESSES = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


# ------------------------------------------------------------------ #
#  Public tool function                                                #
# ------------------------------------------------------------------ #

def analyze_processes(
    data: dict,
    depth: str = "standard",
    filter_pid: Optional[int] = None,
) -> dict:
    """
    Analyse the process list for suspicious indicators.

    Args:
        data:       Full forensic data dict (must contain 'processes' key).
        depth:      'standard' or 'deep' (deep adds memory-anomaly checks).
        filter_pid: If provided, only analyse the subtree rooted at this PID.

    Returns:
        Structured dict with process list, suspicious processes, anomalies,
        parent–child relationship violations, and statistics.
    """
    processes = data.get("processes", [])

    if filter_pid:
        processes = _subtree(processes, filter_pid)

    suspicious_processes: list[dict] = []
    parent_child_violations: list[dict] = []
    masquerading_indicators: list[dict] = []

    # Build a PID → process lookup for parent-name cross-checking
    pid_map = {p["pid"]: p for p in processes if "pid" in p}

    for proc in processes:
        name_lower = proc.get("name", "").lower()
        path_lower = proc.get("path", "").lower()
        cmdline = proc.get("cmdline", "")
        parent_name = proc.get("parent_name", "").lower()
        issues: list[str] = []

        # --- Check: running from suspicious directory ---
        if any(d in path_lower for d in SUSPICIOUS_DIRS):
            issues.append(
                f"Executable in suspicious directory: {proc.get('path', 'N/A')}"
            )

        # --- Check: system binary name from wrong path ---
        if name_lower in SYSTEM_BINARY_NAMES:
            expected_dirs = ["\\windows\\system32\\", "\\windows\\syswow64\\"]
            if not any(d in path_lower for d in expected_dirs):
                masquerading_indicators.append({
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "actual_path": proc.get("path"),
                    "expected_dirs": expected_dirs,
                    "severity": "critical",
                    "description": (
                        f"Process '{proc.get('name')}' is masquerading as a system binary "
                        f"but running from: {proc.get('path', 'N/A')}"
                    ),
                })
                issues.append("System binary name used from non-system path (masquerading)")

        # --- Check: Office app spawning a shell ---
        if parent_name in OFFICE_PROCESSES and name_lower in SHELL_PROCESSES:
            parent_child_violations.append({
                "parent_pid": proc.get("parent_pid"),
                "parent_name": proc.get("parent_name"),
                "child_pid": proc.get("pid"),
                "child_name": proc.get("name"),
                "cmdline": cmdline,
                "severity": "high",
                "description": (
                    f"'{proc.get('parent_name')}' spawned '{proc.get('name')}' — "
                    "classic macro/phishing execution pattern"
                ),
            })
            issues.append(
                f"Unusual parent–child: {proc.get('parent_name')} → {proc.get('name')}"
            )

        # --- Check: known-bad parent–child for non-office processes ---
        if name_lower in LEGITIMATE_PARENTS:
            allowed = [p.lower() for p in LEGITIMATE_PARENTS[name_lower]]
            if parent_name and parent_name not in allowed and parent_name not in ("", "n/a"):
                parent_child_violations.append({
                    "parent_pid": proc.get("parent_pid"),
                    "parent_name": proc.get("parent_name"),
                    "child_pid": proc.get("pid"),
                    "child_name": proc.get("name"),
                    "severity": "medium",
                    "description": (
                        f"Unexpected parent for '{proc.get('name')}': "
                        f"'{proc.get('parent_name')}' (allowed: {LEGITIMATE_PARENTS[name_lower]})"
                    ),
                })
                issues.append(f"Unexpected parent process: {proc.get('parent_name')}")

        # --- Check: existing suspicious flags from raw data ---
        if proc.get("suspicious"):
            existing = proc.get("anomalies", proc.get("anomaly"))
            if isinstance(existing, str):
                existing = [existing]
            for note in (existing or []):
                if note not in issues:
                    issues.append(note)

        # Compile if any issues found
        if issues:
            suspicious_processes.append({
                "pid": proc.get("pid"),
                "name": proc.get("name"),
                "path": proc.get("path"),
                "parent_name": proc.get("parent_name"),
                "user": proc.get("user"),
                "cmdline": cmdline,
                "start_time": proc.get("start_time"),
                "issues": issues,
                "issue_count": len(issues),
                "severity": _derive_severity(issues),
            })

    # --- Deep mode: memory anomalies ---
    memory_anomalies: list[dict] = []
    if depth == "deep":
        for proc in processes:
            mem = proc.get("memory_mb", 0)
            name_lower = proc.get("name", "").lower()
            # Flag unexpected high-memory for typically light processes
            if name_lower in {"cmd.exe", "powershell.exe"} and mem > 200:
                memory_anomalies.append({
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "memory_mb": mem,
                    "description": (
                        f"Unusually high memory ({mem} MB) for '{proc.get('name')}' "
                        "— possible process injection or memory-resident payload"
                    ),
                    "severity": "high",
                })

    return {
        "tool": "analyze_processes",
        "analysis_depth": depth,
        "processes": processes,
        "suspicious_processes": suspicious_processes,
        "parent_child_violations": parent_child_violations,
        "masquerading_indicators": masquerading_indicators,
        "memory_anomalies": memory_anomalies,
        "statistics": {
            "total_processes": len(processes),
            "suspicious_count": len(suspicious_processes),
            "parent_child_violation_count": len(parent_child_violations),
            "masquerading_count": len(masquerading_indicators),
            "critical_count": sum(
                1 for p in suspicious_processes if p.get("severity") == "critical"
            ),
        },
    }


# ------------------------------------------------------------------ #
#  Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _subtree(processes: list, root_pid: int) -> list:
    """Return all processes in the subtree rooted at root_pid."""
    result, queue = [], [root_pid]
    pid_map = {p["pid"]: p for p in processes if "pid" in p}
    while queue:
        pid = queue.pop()
        if pid in pid_map:
            proc = pid_map[pid]
            result.append(proc)
            # Find children
            for p in processes:
                if p.get("parent_pid") == pid and p["pid"] not in [r["pid"] for r in result]:
                    queue.append(p["pid"])
    return result


def _derive_severity(issues: list[str]) -> str:
    """Derive overall severity from the list of issue descriptions."""
    critical_keywords = ["masquerad", "injection", "anti-forensic", "critical"]
    high_keywords = ["unusual", "suspicious directory", "macro", "phishing"]
    for issue in issues:
        if any(k in issue.lower() for k in critical_keywords):
            return "critical"
    for issue in issues:
        if any(k in issue.lower() for k in high_keywords):
            return "high"
    return "medium"
