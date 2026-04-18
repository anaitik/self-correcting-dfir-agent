"""
agents/planner.py
Planner Agent — reads the critic's feedback and decides what to do next.

Responsibilities:
  - Determine whether another triage iteration is warranted
  - Select which tools to run next (and with what parameters)
  - Identify focus areas to guide the triage analyst
  - Enforce the max_iterations ceiling

The planner is the strategic brain of the self-correction loop.
"""

import json

import anthropic

from utils.logger import dfir_logger


# ------------------------------------------------------------------ #
#  System prompt for the planner persona                              #
# ------------------------------------------------------------------ #
PLANNER_SYSTEM_PROMPT = """
You are the senior analyst directing a DFIR investigation.
You have received a critic's review of the initial findings.
Your job is to translate that critique into a concrete action plan.

TOOLS AVAILABLE:
  - get_timeline(focus_window="ISO_START,ISO_END", depth="standard|deep")
  - analyze_processes(depth="standard|deep", filter_pid=<pid>)
  - parse_logs(filter_level="all|critical|high", start_time="ISO", end_time="ISO")

RULES:
  - If quality_score >= 0.80 AND no critical issues remain → set decision="finalize"
  - If max_iterations would be exceeded → set decision="finalize" regardless
  - Always explain WHY each tool is being re-run and with what parameters
  - Be as specific as possible about time windows and focus areas
  - Do NOT repeat tools with identical parameters — always refine
  - If parse_logs has never been run and log data exists → always add it

Return ONLY a valid JSON object — no markdown, no commentary.
Schema:
{
  "decision": "rerun|finalize",
  "reasoning": "Why this decision was made",
  "tools_to_run": ["parse_logs", "get_timeline"],
  "tool_parameters": {
    "parse_logs":    {"filter_level": "all"},
    "get_timeline":  {"depth": "deep", "focus_window": "2024-01-15T08:10:00Z,2024-01-15T08:25:00Z"}
  },
  "focus_areas": [
    "Corroborate process execution with Event ID 4688 logs",
    "Confirm persistence mechanism via registry keys"
  ],
  "updated_hypothesis": "Current best explanation of what happened",
  "risk_level": "critical|high|medium|low"
}
"""


# ------------------------------------------------------------------ #
#  Node function (called by LangGraph)                                #
# ------------------------------------------------------------------ #

def run_planner(state: dict) -> dict:
    """
    LangGraph node: Planner Agent.

    Reads critic feedback and determines whether to loop back to triage
    or proceed to final report generation.
    """
    iteration      = state.get("iteration", 1)
    max_iterations = state.get("max_iterations", 3)
    api_key        = state.get("api_key", "")
    critic_feedback = state.get("critic_feedback", {})
    findings        = state.get("triage_findings", [])
    tool_results    = state.get("tool_results", {})
    forensic_data   = state.get("forensic_data", {})
    iteration_history = state.get("iteration_history", [])

    dfir_logger.info(
        f"Planner deciding next step (iteration {iteration}/{max_iterations})",
        agent="planner",
        iteration=iteration,
    )

    # Hard ceiling: if we've reached max iterations, finalize regardless
    force_finalize = iteration >= max_iterations
    if force_finalize:
        dfir_logger.warning(
            f"Max iterations ({max_iterations}) reached — forcing finalization",
            agent="planner",
            iteration=iteration,
        )

    user_message = _build_planner_message(
        forensic_data=forensic_data,
        findings=findings,
        critic_feedback=critic_feedback,
        tool_results=tool_results,
        iteration=iteration,
        max_iterations=max_iterations,
        force_finalize=force_finalize,
        iteration_history=iteration_history,
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            system=PLANNER_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = response.content[0].text.strip()
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
        planner_output = json.loads(raw_text)
    except json.JSONDecodeError as e:
        dfir_logger.error(
            f"JSON parse error from planner Claude: {e}",
            agent="planner",
            iteration=iteration,
        )
        planner_output = _fallback_planner(critic_feedback, tool_results, forensic_data, force_finalize)
    except Exception as e:
        dfir_logger.error(
            f"Planner API call failed: {e}",
            agent="planner",
            iteration=iteration,
        )
        planner_output = _fallback_planner(critic_feedback, tool_results, forensic_data, force_finalize)

    # Enforce ceiling
    if force_finalize:
        planner_output["decision"] = "finalize"

    decision = planner_output.get("decision", "finalize")
    should_continue = (decision == "rerun")

    dfir_logger.decision(
        event="Planner decision",
        agent="planner",
        reasoning=planner_output.get("reasoning", ""),
        outcome=f"decision={decision}",
        iteration=iteration,
    )

    # Increment iteration counter if looping back
    next_iteration = (iteration + 1) if should_continue else iteration

    return {
        **state,
        "planner_decision":  planner_output,
        "should_continue":   should_continue,
        "tools_to_run":      planner_output.get("tools_to_run", []),
        "tool_parameters":   planner_output.get("tool_parameters", {}),
        "focus_areas":       planner_output.get("focus_areas", []),
        "iteration":         next_iteration,
        "current_step":      "planner_complete",
    }


# ------------------------------------------------------------------ #
#  Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _build_planner_message(
    forensic_data: dict,
    findings: list,
    critic_feedback: dict,
    tool_results: dict,
    iteration: int,
    max_iterations: int,
    force_finalize: bool,
    iteration_history: list,
) -> str:
    """Construct the planner's input message."""
    remaining = max_iterations - iteration
    tools_run_so_far = list(tool_results.keys())
    issues = critic_feedback.get("issues", [])
    critical_gaps = critic_feedback.get("critical_gaps", [])

    parts = [
        f"# DFIR Planner — Iteration {iteration}/{max_iterations}",
        f"Remaining iterations: {remaining}",
        "",
    ]

    if force_finalize:
        parts += [
            "⚠️  MAX ITERATIONS REACHED — you MUST set decision='finalize'.",
            "",
        ]

    parts += [
        "## Critic feedback:",
        json.dumps(critic_feedback, indent=2),
        "",
        "## Tools already run (do not repeat with identical parameters):",
        *[f"- {t}" for t in tools_run_so_far],
        "",
        "## Available data sources not yet fully analysed:",
    ]

    if forensic_data.get("logs") and "parse_logs" not in tools_run_so_far:
        parts.append("- logs (CRITICAL — parse_logs has NOT been run yet)")
    if forensic_data.get("network_connections"):
        parts.append("- network_connections (raw network data available)")

    parts += [
        "",
        "## Current findings summary:",
        json.dumps(
            [{"id": f["id"], "title": f["title"], "confidence": f["confidence"], "flag": f["flag"]}
             for f in findings],
            indent=2,
        ),
        "",
    ]

    if iteration_history:
        parts += [
            "## Iteration history (what improved each cycle):",
            json.dumps(
                [{"iteration": h["iteration"], "tools_run": h["tools_run"]}
                 for h in iteration_history],
                indent=2,
            ),
            "",
        ]

    parts.append(
        "Based on the critic's issues and gaps, decide: continue analysis or finalize. "
        "Return your action plan as JSON per your system prompt schema."
    )

    return "\n".join(parts)


def _fallback_planner(
    critic_feedback: dict,
    tool_results: dict,
    forensic_data: dict,
    force_finalize: bool,
) -> dict:
    """
    Rule-based fallback planner when the API is unavailable.
    Adds parse_logs if logs exist and haven't been analysed.
    """
    if force_finalize:
        return {
            "decision": "finalize",
            "reasoning": "Max iterations reached — finalizing regardless of remaining gaps.",
            "tools_to_run": [],
            "tool_parameters": {},
            "focus_areas": [],
            "updated_hypothesis": "Finalizing based on current evidence.",
            "risk_level": "high",
        }

    tools_to_run = []
    tool_parameters = {}
    focus_areas = []

    # If parse_logs not run and logs exist, add it
    if forensic_data.get("logs") and "parse_logs" not in tool_results:
        tools_to_run.append("parse_logs")
        tool_parameters["parse_logs"] = {"filter_level": "all"}
        focus_areas.append("Analyse Windows Event Log for process creation and persistence events")

    # If critic flagged critical issues, do a deep timeline pass
    critical_issues = [i for i in critic_feedback.get("issues", []) if i.get("severity") == "critical"]
    if critical_issues and "get_timeline" in tool_results:
        tools_to_run.append("get_timeline")
        tool_parameters["get_timeline"] = {"depth": "deep"}
        focus_areas.append("Deep timeline analysis to find additional artefacts")

    decision = "rerun" if tools_to_run else "finalize"

    return {
        "decision": decision,
        "reasoning": "Fallback planner: adding missing tools based on rule-based checks.",
        "tools_to_run": tools_to_run,
        "tool_parameters": tool_parameters,
        "focus_areas": focus_areas,
        "updated_hypothesis": "Continuing analysis to fill identified gaps.",
        "risk_level": "high",
    }
