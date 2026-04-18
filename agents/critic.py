"""
agents/critic.py
Critic Agent — adversarially reviews the triage findings.

The critic's job is deliberately sceptical:
  - Looks for findings without sufficient evidence
  - Identifies analysis gaps (tools not run, data not examined)
  - Flags contradictions between findings or between findings and raw data
  - Scores the overall quality of the analysis

This is the self-correction engine: without a tough critic, the loop
would never improve.
"""

import json

import anthropic

from utils.logger import dfir_logger


# ------------------------------------------------------------------ #
#  System prompt for the critic persona                               #
# ------------------------------------------------------------------ #
CRITIC_SYSTEM_PROMPT = """
You are an adversarial DFIR review board member.
Your job is to challenge, poke holes in, and identify weaknesses
in a triage analyst's findings.

You ask:
  - "What evidence ACTUALLY supports this claim?"
  - "Were all relevant data sources examined?"
  - "Do any findings contradict each other or the raw data?"
  - "Are confidence scores justified, or inflated?"
  - "What MUST be investigated before this report can be trusted?"

RULES:
- Be specific: name the exact finding (by ID) and the exact problem.
- Do NOT soften your critique — the goal is improvement.
- If a data source was NOT analysed (e.g. no log analysis despite
  log data being available), flag it as a CRITICAL gap.
- Contradictions must be spelled out with the conflicting evidence.
- If the analysis is genuinely complete, say so and set needs_revision=false.

Return ONLY a valid JSON object — no markdown, no commentary.
Schema:
{
  "issues": [
    {
      "issue_id": "I001",
      "type": "missing_evidence|contradiction|weak_claim|analysis_gap|inflated_confidence",
      "severity": "critical|high|medium|low",
      "finding_refs": ["F001"],   // which findings are affected ([] if general)
      "description": "Specific description of the problem",
      "recommendation": "What the triage analyst must do to resolve this"
    }
  ],
  "quality_score": 0.55,       // 0.0 (terrible) to 1.0 (publication-ready)
  "needs_revision": true,
  "critical_gaps": [            // data sources / tools urgently needed
    "parse_logs — Windows Event Log data present but not analysed"
  ],
  "critique_summary": "One-paragraph verdict on the current analysis quality"
}
"""


# ------------------------------------------------------------------ #
#  Node function (called by LangGraph)                                #
# ------------------------------------------------------------------ #

def run_critic(state: dict) -> dict:
    """
    LangGraph node: Critic Agent.

    Reviews the current triage findings and tool results, calls Claude
    to identify weaknesses, and returns an updated state with critic feedback.
    """
    iteration       = state.get("iteration", 1)
    api_key         = state.get("api_key", "")
    findings        = state.get("triage_findings", [])
    tool_results    = state.get("tool_results", {})
    forensic_data   = state.get("forensic_data", {})
    missing_analysis = state.get("missing_analysis", [])

    dfir_logger.info(
        f"Critic reviewing {len(findings)} findings",
        agent="critic",
        iteration=iteration,
    )

    user_message = _build_critic_message(
        forensic_data=forensic_data,
        findings=findings,
        tool_results=tool_results,
        missing_analysis=missing_analysis,
        iteration=iteration,
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=CRITIC_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = response.content[0].text.strip()
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
        critic_output = json.loads(raw_text)
    except json.JSONDecodeError as e:
        dfir_logger.error(
            f"JSON parse error from critic Claude: {e}",
            agent="critic",
            iteration=iteration,
        )
        critic_output = _fallback_critic(findings, tool_results, forensic_data)
    except Exception as e:
        dfir_logger.error(
            f"Critic API call failed: {e}",
            agent="critic",
            iteration=iteration,
        )
        critic_output = _fallback_critic(findings, tool_results, forensic_data)

    issues         = critic_output.get("issues", [])
    quality_score  = critic_output.get("quality_score", 0.5)
    needs_revision = critic_output.get("needs_revision", True)
    critical_gaps  = critic_output.get("critical_gaps", [])

    dfir_logger.decision(
        event="Critic assessment complete",
        agent="critic",
        reasoning=critic_output.get("critique_summary", ""),
        outcome=(
            f"quality_score={quality_score:.2f}, "
            f"needs_revision={needs_revision}, "
            f"issues={len(issues)}"
        ),
        iteration=iteration,
    )

    return {
        **state,
        "critic_feedback": critic_output,
        "current_step":    "critic_complete",
    }


# ------------------------------------------------------------------ #
#  Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _build_critic_message(
    forensic_data: dict,
    findings: list,
    tool_results: dict,
    missing_analysis: list,
    iteration: int,
) -> str:
    """Build the critic's prompt with all available context."""
    available_data_sources = []
    if forensic_data.get("events"):
        available_data_sources.append("events (timeline data)")
    if forensic_data.get("processes"):
        available_data_sources.append("processes (process list)")
    if forensic_data.get("logs"):
        available_data_sources.append("logs (Windows Event Log / Sysmon)")
    if forensic_data.get("network_connections"):
        available_data_sources.append("network_connections")
    if forensic_data.get("file_hash_results"):
        available_data_sources.append("file_hash_results (VirusTotal data)")

    tools_actually_run = list(tool_results.keys())

    parts = [
        f"# DFIR Critic Review — Iteration {iteration}",
        "",
        "## Available data sources in the forensic evidence package:",
        *[f"- {d}" for d in available_data_sources],
        "",
        "## Tools actually run this analysis:",
        *[f"- {t}" for t in tools_actually_run],
        "",
    ]

    if missing_analysis:
        parts += [
            "## Triage analyst's own notes on missing analysis:",
            *[f"- {m}" for m in missing_analysis],
            "",
        ]

    parts += [
        "## Current findings to review:",
        json.dumps(findings, indent=2),
        "",
        "## Tool output summaries (for cross-reference):",
    ]

    for tool_name, result in tool_results.items():
        # Include key sub-sections, not the full raw event list (too long)
        summary = {
            "statistics": result.get("statistics", {}),
            "anomalies":  result.get("anomalies", [])[:5],
        }
        if "suspicious_processes" in result:
            summary["suspicious_processes"] = result["suspicious_processes"][:5]
        if "critical_events" in result:
            summary["critical_events"] = result["critical_events"][:5]
        if "anti_forensic_events" in result:
            summary["anti_forensic_events"] = result["anti_forensic_events"]
        if "persistence_events" in result:
            summary["persistence_events"] = result["persistence_events"]
        if "correlation_gaps" in result:
            summary["correlation_gaps"] = result["correlation_gaps"]

        parts += [f"### {tool_name}", json.dumps(summary, indent=2), ""]

    parts.append(
        "Identify every weakness, gap, and contradiction. "
        "Return your adversarial review as JSON per your system prompt schema."
    )

    return "\n".join(parts)


def _fallback_critic(
    findings: list,
    tool_results: dict,
    forensic_data: dict,
) -> dict:
    """
    Rule-based fallback critic when the API is unavailable.
    Checks for the most common structural gaps without LLM reasoning.
    """
    issues = []

    # Gap: logs available but not analysed
    if forensic_data.get("logs") and "parse_logs" not in tool_results:
        issues.append({
            "issue_id": "I001",
            "type": "analysis_gap",
            "severity": "critical",
            "finding_refs": [],
            "description": "Log data is present in the forensic package but parse_logs was not run.",
            "recommendation": "Run parse_logs immediately — Windows Event IDs 4688, 7045, 1102 may be critical.",
        })

    # Gap: single-tool findings with high confidence
    for finding in findings:
        if (
            len(finding.get("supporting_tools", [])) == 1
            and finding.get("confidence", 0) > 0.70
        ):
            issues.append({
                "issue_id": f"I{len(issues)+2:03d}",
                "type": "inflated_confidence",
                "severity": "medium",
                "finding_refs": [finding.get("id", "?")],
                "description": (
                    f"Finding {finding.get('id')} has confidence "
                    f"{finding.get('confidence')} but is supported by only one tool."
                ),
                "recommendation": "Corroborate with additional data sources before raising confidence.",
            })

    needs_revision = len(issues) > 0
    quality = 0.4 if issues else 0.8

    return {
        "issues": issues,
        "quality_score": quality,
        "needs_revision": needs_revision,
        "critical_gaps": [i["description"] for i in issues if i["severity"] == "critical"],
        "critique_summary": (
            f"Rule-based fallback critique (API unavailable). "
            f"Found {len(issues)} structural issues."
        ),
    }
