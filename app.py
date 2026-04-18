"""
app.py
Streamlit UI for the Self-Correcting DFIR Agent.

Run with:
    streamlit run app.py

Features:
  - JSON / text forensic data file upload (or use built-in sample)
  - Configurable max iterations + API key input
  - Live step-by-step display as the LangGraph workflow streams events
  - Final dashboard: findings table, confidence visualisation,
    iteration-over-iteration improvement, full audit log
"""

import json
import os
import time

import streamlit as st
import pandas as pd

from graph.workflow import create_workflow, build_initial_state
from utils.logger   import dfir_logger


# ──────────────────────────────────────────────────────────────────── #
#  Page config (must be first Streamlit call)                          #
# ──────────────────────────────────────────────────────────────────── #
st.set_page_config(
    page_title="Self-Correcting DFIR Agent",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────────── #
#  Custom CSS                                                          #
# ──────────────────────────────────────────────────────────────────── #
st.markdown("""
<style>
    .main-header {
        font-size: 2rem;
        font-weight: 700;
        color: #FF4B4B;
        margin-bottom: 0.25rem;
    }
    .sub-header {
        color: #888;
        font-size: 0.9rem;
        margin-bottom: 1.5rem;
    }
    .step-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 6px;
    }
    .badge-triage  { background: #1a3a5c; color: #5bc0eb; }
    .badge-critic  { background: #3a1a1a; color: #eb5b5b; }
    .badge-planner { background: #1a3a1a; color: #5beb6e; }
    .badge-report  { background: #2e2a3a; color: #b05beb; }
    .confirmed    { color: #2ecc71; font-weight: 600; }
    .suspicious   { color: #f39c12; font-weight: 600; }
    .inconsistent { color: #e74c3c; font-weight: 600; }
    .metric-box {
        background: #1a1a2e;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 12px;
        text-align: center;
    }
    div[data-testid="stExpander"] {
        border: 1px solid #333;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────── #
#  Sidebar — configuration                                             #
# ──────────────────────────────────────────────────────────────────── #

with st.sidebar:
    st.markdown("## ⚙️ Configuration")

    # API key
    api_key_env = os.environ.get("GROK_API_KEY", "")
    api_key = st.text_input(
        "Grok API Key",
        value=api_key_env,
        type="password",
        help="Set GROK_API_KEY env var or paste here",
    )

    st.divider()

    # Max iterations
    max_iterations = st.slider(
        "Max Iterations",
        min_value=1,
        max_value=5,
        value=3,
        help=(
            "Maximum number of triage→critic→planner loops. "
            "The agent self-corrects within this budget."
        ),
    )

    st.divider()
    st.markdown("### 📂 Forensic Data")
    use_sample = st.checkbox("Use built-in sample (LockBit scenario)", value=True)

    uploaded_file = None
    if not use_sample:
        uploaded_file = st.file_uploader(
            "Upload forensic data JSON",
            type=["json"],
            help="JSON file matching the expected schema (see sample_data.json)",
        )

    st.divider()
    st.markdown("### 📖 About")
    st.caption(
        "This agent uses a Triage → Critic → Planner loop to iteratively "
        "improve its forensic analysis. The critic challenges every finding; "
        "the planner decides what additional evidence to gather."
    )


# ──────────────────────────────────────────────────────────────────── #
#  Main header                                                         #
# ──────────────────────────────────────────────────────────────────── #

st.markdown('<div class="main-header">🔍 Self-Correcting DFIR Agent</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Autonomous Digital Forensics & Incident Response '
    '| Powered by LangGraph + Grok</div>',
    unsafe_allow_html=True,
)

# ──────────────────────────────────────────────────────────────────── #
#  Session state initialisation                                        #
# ──────────────────────────────────────────────────────────────────── #

if "analysis_complete" not in st.session_state:
    st.session_state.analysis_complete = False
if "final_report" not in st.session_state:
    st.session_state.final_report = None
if "stream_log" not in st.session_state:
    st.session_state.stream_log = []


# ──────────────────────────────────────────────────────────────────── #
#  Load forensic data                                                  #
# ──────────────────────────────────────────────────────────────────── #

@st.cache_data
def load_sample_data() -> dict:
    """Load the bundled ransomware scenario."""
    sample_path = os.path.join(os.path.dirname(__file__), "sample_data.json")
    with open(sample_path) as f:
        return json.load(f)


def load_forensic_data() -> dict | None:
    if use_sample:
        return load_sample_data()
    if uploaded_file:
        try:
            return json.load(uploaded_file)
        except Exception as e:
            st.error(f"Failed to parse uploaded file: {e}")
            return None
    return None


forensic_data = load_forensic_data()

if forensic_data:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Case ID",   forensic_data.get("case_id", "N/A"))
    col2.metric("Host",      forensic_data.get("hostname", "N/A"))
    col3.metric("Events",    len(forensic_data.get("events", [])))
    col4.metric("Processes", len(forensic_data.get("processes", [])))
else:
    st.info("⬆️  Upload a forensic data file or enable the built-in sample in the sidebar.")


# ──────────────────────────────────────────────────────────────────── #
#  Run button + live analysis display                                  #
# ──────────────────────────────────────────────────────────────────── #

st.markdown("---")

run_col, _ = st.columns([1, 3])
run_clicked = run_col.button(
    "🚀 Run Analysis",
    type="primary",
    disabled=(not forensic_data or not api_key),
    use_container_width=True,
)

if not api_key:
    st.warning("⚠️  Please enter your Grok API key in the sidebar.")

if run_clicked and forensic_data and api_key:
    # Reset previous run
    st.session_state.analysis_complete = False
    st.session_state.final_report      = None
    st.session_state.stream_log        = []

    workflow = create_workflow()
    initial_state = build_initial_state(
        forensic_data=forensic_data,
        api_key=api_key,
        max_iterations=max_iterations,
    )

    # ── Live display containers ──────────────────────────────────── #
    progress_bar    = st.progress(0, text="Initialising…")
    status_box      = st.empty()
    live_log_header = st.empty()
    live_log_box    = st.empty()

    STEP_LABELS = {
        "triage":  ("🔬 Triage Agent",  "Collecting and analysing forensic artefacts…"),
        "critic":  ("🧐 Critic Agent",   "Reviewing findings for gaps and contradictions…"),
        "planner": ("🧠 Planner Agent",  "Deciding next investigation steps…"),
        "report":  ("📋 Report Builder", "Compiling final structured report…"),
    }

    step_index    = 0
    total_steps   = max_iterations * 3 + 1   # (triage+critic+planner) × n + report

    stream_log: list[dict] = []

    try:
        for event in workflow.stream(initial_state):
            node_name = list(event.keys())[0]
            node_state = event[node_name]

            step_index += 1
            progress = min(step_index / total_steps, 0.99)

            label, description = STEP_LABELS.get(
                node_name, (f"⚙️ {node_name}", "Processing…")
            )
            iteration = node_state.get("iteration", 1)

            progress_bar.progress(
                progress,
                text=f"Iteration {iteration}/{max_iterations} — {label}",
            )

            # Collate log entries from this step
            new_log_entries = dfir_logger.get_entries()[len(stream_log):]
            stream_log.extend(new_log_entries)
            st.session_state.stream_log = stream_log

            # Status box
            badge_class = {
                "triage": "badge-triage",
                "critic": "badge-critic",
                "planner": "badge-planner",
                "report": "badge-report",
            }.get(node_name, "badge-triage")

            status_box.markdown(
                f'<span class="step-badge {badge_class}">{label}</span> '
                f'<b>Iteration {iteration}</b> — {description}',
                unsafe_allow_html=True,
            )

            # Live log preview (last 8 entries)
            if stream_log:
                live_log_header.markdown("**📡 Live Agent Log** (last 8 entries)")
                recent = stream_log[-8:]
                log_md = "\n".join(
                    f"- `[{e['level']}]` **{e['agent']}** — {e['event']}"
                    + (f" *(tool: {e['tool']})*" if e.get("tool") else "")
                    for e in recent
                )
                live_log_box.markdown(log_md)

            # Capture final state when report node completes
            if node_name == "report" and node_state.get("final_report"):
                st.session_state.final_report      = node_state["final_report"]
                st.session_state.analysis_complete = True

    except Exception as e:
        st.error(f"❌ Analysis failed: {e}")
        st.exception(e)
        progress_bar.empty()
    else:
        progress_bar.progress(1.0, text="✅ Analysis complete!")
        status_box.success("Analysis complete — see report below.")
        live_log_header.empty()
        live_log_box.empty()
        time.sleep(0.5)
        progress_bar.empty()
        status_box.empty()


# ──────────────────────────────────────────────────────────────────── #
#  Final dashboard                                                     #
# ──────────────────────────────────────────────────────────────────── #

if st.session_state.analysis_complete and st.session_state.final_report:
    report = st.session_state.final_report

    st.markdown("---")
    st.markdown("## 📊 Investigation Report")

    # ── Summary metrics ─────────────────────────────────────────── #
    quality   = report.get("overall_quality", {})
    findings  = report.get("findings", [])
    confirmed = report["finding_summary"]["confirmed"]
    suspicious = report["finding_summary"]["suspicious"]
    inconsistent = report["finding_summary"]["inconsistent"]

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("🔁 Iterations",      report.get("total_iterations", 0))
    m2.metric("⚠️  Risk Level",     report.get("risk_level", "N/A").upper())
    m3.metric("📋 Findings",        len(findings))
    m4.metric("✅ Confirmed",        len(confirmed),   delta=None)
    m5.metric("🔶 Suspicious",      len(suspicious),  delta=None)
    m6.metric("❌ Inconsistent",    len(inconsistent), delta=None)

    avg_conf = quality.get("average_confidence", 0)
    qual_label = quality.get("overall_quality", "unknown")

    col_conf, col_hyp = st.columns([1, 2])
    with col_conf:
        st.metric(
            "📈 Average Confidence",
            f"{avg_conf:.0%}",
            delta=f"Quality: {qual_label}",
        )
    with col_hyp:
        st.info(f"**Final Hypothesis:** {report.get('final_hypothesis', 'N/A')}")

    st.markdown("---")

    # ── Findings table ──────────────────────────────────────────── #
    st.markdown("### 🔎 Findings")

    if findings:
        rows = []
        for f in findings:
            flag = f.get("flag", "unknown")
            conf = f.get("confidence", 0)
            bar  = "█" * int(conf * 10) + "░" * (10 - int(conf * 10))
            rows.append({
                "ID":          f.get("id", ""),
                "Title":       f.get("title", ""),
                "Confidence":  f"{conf:.0%}  {bar}",
                "Flag":        flag.upper(),
                "Tools":       ", ".join(f.get("supporting_tools", [])),
                "MITRE":       f.get("mitre_technique") or "—",
            })

        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Confidence": st.column_config.TextColumn("Confidence (0–100%)"),
                "Flag": st.column_config.TextColumn("Status"),
            },
        )

        # Detail cards for each finding
        st.markdown("#### Finding Details")
        for f in findings:
            flag  = f.get("flag", "unknown")
            conf  = f.get("confidence", 0)
            color = {"confirmed": "🟢", "suspicious": "🟡", "inconsistent": "🔴"}.get(flag, "⚪")

            with st.expander(f"{color} [{f.get('id')}] {f.get('title', '')} — {conf:.0%}"):
                st.markdown(f"**Description:** {f.get('description', '')}")
                st.markdown("**Evidence:**")
                for ev in f.get("evidence", []):
                    st.markdown(f"  - {ev}")
                st.markdown(
                    f"**Flag:** `{flag}` | "
                    f"**Confidence:** `{conf:.3f}` | "
                    f"**MITRE:** `{f.get('mitre_technique') or 'unknown'}`"
                )
                st.markdown(f"**Supporting tools:** {', '.join(f.get('supporting_tools', []))}")
    else:
        st.warning("No findings generated.")

    st.markdown("---")

    # ── Iteration-over-iteration improvement ────────────────────── #
    st.markdown("### 🔁 Self-Correction History")

    history = report.get("iteration_history", [])
    if history:
        for snap in history:
            it = snap.get("iteration", "?")
            with st.expander(
                f"Iteration {it} — tools: {', '.join(snap.get('tools_run', []))}",
                expanded=(it == 1),
            ):
                st.markdown(f"**Analyst summary:** {snap.get('analyst_summary', '—')}")
                st.markdown(f"**Findings generated this pass:** {len(snap.get('findings', []))}")

                if snap.get("missing_analysis"):
                    st.markdown("**Analyst noted these gaps:**")
                    for gap in snap["missing_analysis"]:
                        st.markdown(f"  - {gap}")

                tools_summary = snap.get("tool_results_summary", {})
                if tools_summary:
                    st.markdown("**Tool statistics:**")
                    st.json(tools_summary)

    st.markdown("---")

    # ── Remaining gaps ──────────────────────────────────────────── #
    remaining_gaps = report.get("remaining_gaps", [])
    if remaining_gaps:
        st.warning("⚠️  **Unresolved gaps at time of report:**")
        for gap in remaining_gaps:
            st.markdown(f"  - {gap}")

    # ── Full audit log ──────────────────────────────────────────── #
    st.markdown("---")
    with st.expander("📜 Full Structured Audit Trail", expanded=False):
        audit = report.get("audit_trail", [])
        st.caption(f"{len(audit)} log entries captured")

        # Filter controls
        col_a, col_b = st.columns(2)
        filter_agent = col_a.selectbox(
            "Filter by agent",
            ["all"] + list({e.get("agent", "") for e in audit}),
        )
        filter_level = col_b.selectbox(
            "Filter by level",
            ["all"] + list({e.get("level", "") for e in audit}),
        )

        filtered = audit
        if filter_agent != "all":
            filtered = [e for e in filtered if e.get("agent") == filter_agent]
        if filter_level != "all":
            filtered = [e for e in filtered if e.get("level") == filter_level]

        for entry in filtered:
            ts      = entry.get("timestamp", "")[:19].replace("T", " ")
            level   = entry.get("level", "INFO")
            agent   = entry.get("agent", "?")
            event   = entry.get("event", "")
            tool    = entry.get("tool")
            details = entry.get("details", {})
            it      = entry.get("iteration")

            icon = {
                "INFO":      "ℹ️",
                "WARNING":   "⚠️",
                "ERROR":     "❌",
                "TOOL_CALL": "🔧",
                "DECISION":  "🧠",
            }.get(level, "📝")

            iter_str = f" [iter {it}]" if it else ""
            tool_str = f" `tool={tool}`" if tool else ""
            st.markdown(
                f"{icon} `{ts}`{iter_str} **[{agent}]** {event}{tool_str}"
            )
            if details and level in ("TOOL_CALL", "DECISION", "ERROR"):
                st.json(details)

    # ── Download button ─────────────────────────────────────────── #
    st.markdown("---")
    report_json = json.dumps(report, indent=2, default=str)
    st.download_button(
        label="⬇️  Download Full Report (JSON)",
        data=report_json,
        file_name=f"dfir_report_{report.get('case_id', 'unknown')}.json",
        mime="application/json",
    )

elif not st.session_state.analysis_complete:
    # Pre-run: show data preview
    if forensic_data:
        st.markdown("### 📄 Data Preview")
        tab1, tab2, tab3 = st.tabs(["Events", "Processes", "Logs"])

        with tab1:
            events = forensic_data.get("events", [])
            if events:
                st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
            else:
                st.caption("No events in this dataset.")

        with tab2:
            procs = forensic_data.get("processes", [])
            if procs:
                st.dataframe(pd.DataFrame(procs), use_container_width=True, hide_index=True)
            else:
                st.caption("No processes in this dataset.")

        with tab3:
            logs = forensic_data.get("logs", [])
            if logs:
                flat = []
                for l in logs:
                    flat.append({
                        "timestamp": l.get("timestamp"),
                        "event_id":  l.get("event_id"),
                        "source":    l.get("source"),
                        "description": l.get("description"),
                        "flag":      l.get("flag", ""),
                    })
                st.dataframe(pd.DataFrame(flat), use_container_width=True, hide_index=True)
            else:
                st.caption("No logs in this dataset.")

        st.info(
            "👆 Click **Run Analysis** to start the self-correcting DFIR investigation. "
            "The agent will iteratively triage, critique, and refine its findings."
        )
