"""
graph/workflow.py
LangGraph workflow definition for the Self-Correcting DFIR Agent.

Graph topology:
    START → triage → critic → planner → (rerun → triage | finalize → report) → END

State is a plain dict that flows through every node.  Each node
receives the full state and returns an updated version.
"""

from typing import TypedDict, Optional, Any
import json
from datetime import datetime, timezone

from langgraph.graph import StateGraph, END

from agents.triage  import run_triage
from agents.critic  import run_critic
from agents.planner import run_planner
from utils.logger   import dfir_logger
from utils.scoring  import score_overall_analysis


# ------------------------------------------------------------------ #
#  Shared state schema                                                 #
# ------------------------------------------------------------------ #

class DFIRState(TypedDict, total=False):
    # ── Input ─────────────────────────────────────────────────────── #
    forensic_data:    dict          # Raw forensic evidence package
    api_key:          str           # Anthropic API key
    case_id:          str           # Human-readable case identifier

    # ── Iteration control ─────────────────────────────────────────── #
    iteration:        int           # Current loop counter (starts at 1)
    max_iterations:   int           # Hard ceiling
    should_continue:  bool          # Planner sets this

    # ── Tool orchestration ────────────────────────────────────────── #
    tools_to_run:     list          # Which tools triage should call
    tool_parameters:  dict          # Parameters per tool name
    tool_results:     dict          # Accumulated results from all iterations
    focus_areas:      list          # Planner-guided focus for next triage

    # ── Agent outputs ─────────────────────────────────────────────── #
    triage_findings:  list          # Current iteration's findings
    critic_feedback:  dict          # Latest critic review
    planner_decision: dict          # Latest planner action plan
    missing_analysis: list          # Triage analyst's own gap notes
    analyst_summary:  str           # Triage narrative

    # ── History ───────────────────────────────────────────────────── #
    iteration_history: list         # Snapshot of every iteration

    # ── Final output ──────────────────────────────────────────────── #
    final_report:     Optional[dict]

    # ── UI / debugging ────────────────────────────────────────────── #
    current_step:     str           # For live UI display
    audit_trail:      list          # Structured log entries


# ------------------------------------------------------------------ #
#  Report generation node                                              #
# ------------------------------------------------------------------ #

def generate_final_report(state: dict) -> dict:
    """
    Final node: compile everything into a structured, explainable report.
    No LLM call — deterministic assembly from accumulated state.
    """
    findings  = state.get("triage_findings", [])
    history   = state.get("iteration_history", [])
    forensic  = state.get("forensic_data", {})
    planner   = state.get("planner_decision", {})
    critic    = state.get("critic_feedback", {})

    quality_stats = score_overall_analysis(findings)

    report = {
        "case_id":             forensic.get("case_id", "UNKNOWN"),
        "hostname":            forensic.get("hostname", "UNKNOWN"),
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "total_iterations":    len(history),
        "overall_quality":     quality_stats,
        "final_hypothesis":    planner.get("updated_hypothesis", ""),
        "risk_level":          planner.get("risk_level", "unknown"),
        "findings":            findings,
        "finding_summary": {
            "confirmed":    [f for f in findings if f.get("flag") == "confirmed"],
            "suspicious":   [f for f in findings if f.get("flag") == "suspicious"],
            "inconsistent": [f for f in findings if f.get("flag") == "inconsistent"],
        },
        "iteration_history":   history,
        "final_critic_score":  critic.get("quality_score", 0.0),
        "remaining_gaps":      critic.get("critical_gaps", []),
        "audit_trail":         dfir_logger.get_entries(),
        "tools_used_overall":  list(state.get("tool_results", {}).keys()),
    }

    dfir_logger.info(
        "Final report generated",
        agent="report",
        details={
            "finding_count":   len(findings),
            "quality":         quality_stats["overall_quality"],
            "total_iterations": len(history),
        },
    )

    return {**state, "final_report": report, "current_step": "complete"}


# ------------------------------------------------------------------ #
#  Routing function                                                    #
# ------------------------------------------------------------------ #

def route_after_planner(state: dict) -> str:
    """
    Conditional edge: decide whether to loop back to triage or finalize.
    """
    if state.get("should_continue", False):
        return "triage"
    return "report"


# ------------------------------------------------------------------ #
#  Graph factory                                                       #
# ------------------------------------------------------------------ #

def create_workflow() -> Any:
    """
    Build and compile the LangGraph StateGraph for the DFIR agent.

    Returns a compiled graph (Runnable) that can be invoked with
    `.invoke(initial_state)` or streamed with `.stream(initial_state)`.
    """
    graph = StateGraph(dict)   # Use plain dict; DFIRState is for documentation

    # Register nodes
    graph.add_node("triage",  run_triage)
    graph.add_node("critic",  run_critic)
    graph.add_node("planner", run_planner)
    graph.add_node("report",  generate_final_report)

    # Entry point
    graph.set_entry_point("triage")

    # Linear edges
    graph.add_edge("triage", "critic")
    graph.add_edge("critic", "planner")

    # Conditional edge: planner decides whether to loop or finalize
    graph.add_conditional_edges(
        "planner",
        route_after_planner,
        {
            "triage": "triage",   # loop back
            "report": "report",   # finalize
        },
    )

    # Report always ends
    graph.add_edge("report", END)

    return graph.compile()


# ------------------------------------------------------------------ #
#  Default initial state builder                                       #
# ------------------------------------------------------------------ #

def build_initial_state(
    forensic_data: dict,
    api_key: str,
    max_iterations: int = 3,
) -> dict:
    """
    Construct the initial state dict for a new DFIR analysis run.
    The triage agent will start by running the default tool set.
    """
    dfir_logger.clear()   # Reset log for fresh run

    return {
        "forensic_data":    forensic_data,
        "api_key":          api_key,
        "case_id":          forensic_data.get("case_id", "UNKNOWN"),
        "iteration":        1,
        "max_iterations":   max_iterations,
        "should_continue":  False,
        "tools_to_run":     ["get_timeline", "analyze_processes"],  # default first pass
        "tool_parameters":  {},
        "tool_results":     {},
        "focus_areas":      [],
        "triage_findings":  [],
        "critic_feedback":  None,
        "planner_decision": None,
        "missing_analysis": [],
        "analyst_summary":  "",
        "iteration_history": [],
        "final_report":     None,
        "current_step":     "initializing",
        "audit_trail":      [],
    }
