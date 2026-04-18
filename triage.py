"""
agents/triage.py
Triage Agent — performs the initial (and subsequent) forensic analysis.

On each pass it:
  1. Decides which tools to run (guided by the planner on iteration > 1)
  2. Runs those tools against the forensic data
  3. Sends ALL tool outputs to Claude for structured finding extraction
  4. Persists findings + tool results to shared LangGraph state

The agent explicitly does NOT assume facts without evidence; confidence
scores reflect how many independent sources corroborate each finding.
"""

import json
from typing import Any

import anthropic

from tools.timeline  import get_timeline
from tools.processes import analyze_processes
from tools.logs      import parse_logs
from utils.logger    import dfir_logger
from utils.scoring   import compute_finding_confidence, assign_flag


# Default tool set for the first pass
DEFAULT_TOOLS = ["get_timeline", "analyze_processes"]


# ------------------------------------------------------------------ #
#  System prompt for the triage analyst persona                       #
# ------------------------------------------------------------------ #
TRIAGE_SYSTEM_PROMPT = """
You are a senior DFIR (Digital Forensics & Incident Response) analyst.
Your job is to examine structured output from forensic tools and produce
a concise, evidence-based list of findings.

RULES:
- Do NOT assume facts that are not present in the tool output.
- Every finding must cite its evidence (specific field names / values).
- Assign a confidence score (0.0–1.0) to each finding based on how
  strongly the evidence supports it.
- If evidence from only ONE tool supports a claim, cap confidence at 0.65.
- If multiple independent tool outputs converge, you may go up to 0.95.
- Flag as 'inconsistent' any finding where data contradicts itself.
- Be explicit about what is NOT yet known or analysed.

Return ONLY a valid JSON object — no markdown, no commentary.
Schema:
{
  "findings": [
    {
      "id": "F001",
      "title": "Short one-line title",
      "description": "Detailed explanation of the finding",
      "evidence": ["evidence item 1", "evidence item 2"],
      "confidence": 0.75,
      "flag": "confirmed|suspicious|inconsistent",
      "supporting_tools": ["get_timeline"],
      "mitre_technique": "T1059.003"   // best-effort, null if unsure
    }
  ],
  "tools_used": ["get_timeline", "analyze_processes"],
  "missing_analysis": [
    "What additional tools / data sources would materially improve confidence"
  ],
  "analyst_summary": "One-paragraph narrative of current understanding"
}
"""


# ------------------------------------------------------------------ #
#  Node function (called by LangGraph)                                #
# ------------------------------------------------------------------ #

def run_triage(state: dict) -> dict:
    """
    LangGraph node: Triage Agent.

    Reads the shared state, runs the appropriate tools, calls Claude
    to synthesise findings, and returns an updated state dict.
    """
    iteration     = state.get("iteration", 1)
    forensic_data = state.get("forensic_data", {})
    api_key       = state.get("api_key", "")

    # Determine which tools to run this iteration
    tools_to_run    = state.get("tools_to_run", DEFAULT_TOOLS)
    tool_parameters = state.get("tool_parameters", {})

    dfir_logger.info(
        f"Triage starting — iteration {iteration}",
        agent="triage",
        iteration=iteration,
        details={"tools_to_run": tools_to_run, "tool_parameters": tool_parameters},
    )

    # ---------------------------------------------------------------- #
    #  Step 1: Run selected tools                                       #
    # ---------------------------------------------------------------- #
    tool_results: dict[str, Any] = {}

    if "get_timeline" in tools_to_run:
        params = tool_parameters.get("get_timeline", {})
        result = get_timeline(forensic_data, **params)
        tool_results["get_timeline"] = result
        dfir_logger.tool_call(
            tool="get_timeline",
            agent="triage",
            parameters=params,
            result_summary=(
                f"{result['statistics']['total_events']} events, "
                f"{result['statistics']['anomaly_count']} anomalies"
            ),
            iteration=iteration,
        )

    if "analyze_processes" in tools_to_run:
        params = tool_parameters.get("analyze_processes", {})
        result = analyze_processes(forensic_data, **params)
        tool_results["analyze_processes"] = result
        dfir_logger.tool_call(
            tool="analyze_processes",
            agent="triage",
            parameters=params,
            result_summary=(
                f"{result['statistics']['total_processes']} processes, "
                f"{result['statistics']['suspicious_count']} suspicious"
            ),
            iteration=iteration,
        )

    if "parse_logs" in tools_to_run:
        params = tool_parameters.get("parse_logs", {})
        result = parse_logs(forensic_data, **params)
        tool_results["parse_logs"] = result
        dfir_logger.tool_call(
            tool="parse_logs",
            agent="triage",
            parameters=params,
            result_summary=(
                f"{result['statistics']['total_log_entries']} log entries, "
                f"{result['statistics']['critical_count']} critical"
            ),
            iteration=iteration,
        )

    # ---------------------------------------------------------------- #
    #  Step 2: Ask Claude to synthesise findings                        #
    # ---------------------------------------------------------------- #
    user_message = _build_user_message(
        forensic_data=forensic_data,
        tool_results=tool_results,
        iteration=iteration,
        previous_findings=state.get("triage_findings", []),
        focus_areas=state.get("focus_areas", []),
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=TRIAGE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = response.content[0].text.strip()
        # Strip any accidental markdown fences
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
        triage_output = json.loads(raw_text)
    except json.JSONDecodeError as e:
        dfir_logger.error(
            f"JSON parse error from Claude: {e}",
            agent="triage",
            iteration=iteration,
        )
        triage_output = _fallback_output(tool_results)
    except Exception as e:
        dfir_logger.error(
            f"API call failed: {e}",
            agent="triage",
            iteration=iteration,
        )
        triage_output = _fallback_output(tool_results)

    # ---------------------------------------------------------------- #
    #  Step 3: Post-process confidence scores using our scoring module  #
    # ---------------------------------------------------------------- #
    findings = triage_output.get("findings", [])
    for finding in findings:
        num_sources = len(finding.get("supporting_tools", []))
        # Re-apply scoring logic to ensure consistency
        adjusted = compute_finding_confidence(
            base_score=finding.get("confidence", 0.5),
            num_corroborating_sources=num_sources,
            is_single_source=(num_sources <= 1),
        )
        finding["confidence"] = round(adjusted, 3)
        finding["flag"]       = assign_flag(adjusted)

    # ---------------------------------------------------------------- #
    #  Step 4: Snapshot this iteration and update audit trail           #
    # ---------------------------------------------------------------- #
    iteration_snapshot = {
        "iteration": iteration,
        "tools_run": list(tool_results.keys()),
        "tool_results_summary": {
            t: _summarise_tool(r) for t, r in tool_results.items()
        },
        "findings": findings,
        "analyst_summary": triage_output.get("analyst_summary", ""),
        "missing_analysis": triage_output.get("missing_analysis", []),
    }

    dfir_logger.info(
        f"Triage complete — {len(findings)} findings generated",
        agent="triage",
        iteration=iteration,
        details={"finding_count": len(findings)},
    )

    # Accumulate history across iterations
    history = list(state.get("iteration_history", []))
    history.append(iteration_snapshot)

    # Merge tool results with any previously collected results
    all_tool_results = dict(state.get("tool_results", {}))
    all_tool_results.update(tool_results)

    return {
        **state,
        "triage_findings":   findings,
        "tool_results":      all_tool_results,
        "iteration_history": history,
        "current_step":      "triage_complete",
        "missing_analysis":  triage_output.get("missing_analysis", []),
        "analyst_summary":   triage_output.get("analyst_summary", ""),
    }


# ------------------------------------------------------------------ #
#  Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _build_user_message(
    forensic_data: dict,
    tool_results: dict,
    iteration: int,
    previous_findings: list,
    focus_areas: list,
) -> str:
    """Construct the Claude user message with all available context."""
    case_id  = forensic_data.get("case_id", "UNKNOWN")
    hostname = forensic_data.get("hostname", "UNKNOWN")
    notes    = forensic_data.get("analyst_notes", "")

    parts = [
        f"# DFIR Triage — Iteration {iteration}",
        f"Case: {case_id} | Host: {hostname}",
        f"Analyst notes: {notes}",
        "",
    ]

    if focus_areas:
        parts += [
            "## Focus areas for this iteration (from planner):",
            *[f"- {a}" for a in focus_areas],
            "",
        ]

    if previous_findings and iteration > 1:
        parts += [
            "## Previous iteration findings (for continuity):",
            json.dumps(previous_findings, indent=2),
            "",
        ]

    parts += ["## Tool outputs:"]
    for tool_name, result in tool_results.items():
        parts += [
            f"### {tool_name}",
            json.dumps(result, indent=2),
            "",
        ]

    if forensic_data.get("file_hash_results"):
        parts += [
            "## File hash intelligence:",
            json.dumps(forensic_data["file_hash_results"], indent=2),
            "",
        ]

    parts.append(
        "Produce a structured JSON analysis following your system prompt schema. "
        "Be specific, cite evidence, and flag anything requiring further investigation."
    )

    return "\n".join(parts)


def _summarise_tool(result: dict) -> dict:
    """Return only the statistics block of a tool result for compact logging."""
    return result.get("statistics", {})


def _fallback_output(tool_results: dict) -> dict:
    """Minimal fallback if Claude API fails — derived purely from tool outputs."""
    findings = []
    for tool, result in tool_results.items():
        if tool == "analyze_processes":
            for sp in result.get("suspicious_processes", [])[:3]:
                findings.append({
                    "id": f"F{len(findings)+1:03d}",
                    "title": f"Suspicious process: {sp.get('name')}",
                    "description": "; ".join(sp.get("issues", [])),
                    "evidence": sp.get("issues", []),
                    "confidence": 0.55,
                    "flag": "suspicious",
                    "supporting_tools": ["analyze_processes"],
                    "mitre_technique": None,
                })
    return {
        "findings": findings,
        "tools_used": list(tool_results.keys()),
        "missing_analysis": ["Claude API unavailable — manual review required"],
        "analyst_summary": "Automated analysis degraded — Claude API call failed.",
    }
