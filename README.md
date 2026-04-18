# Self-Correcting DFIR Agent

A LangGraph-based Digital Forensics & Incident Response (DFIR) agent that performs autonomous, iterative digital forensic analysis with built-in self-correction capability. Powered by Grok.

## Overview

This system implements a multi-agent framework using LangGraph that automates DFIR analysis through a sophisticated workflow:

1. **Triage Agent** — Runs forensic tools (timeline analysis, process examination, log parsing) and synthesizes findings using Grok
2. **Critic Agent** — Adversarially reviews findings for gaps, weaknesses, and contradictions
3. **Planner Agent** — Decides whether to continue analysis or finalize, directing focus for next iteration
4. **Report Generator** — Compiles final analysis into a structured, auditable report

## Features

- **Self-Correcting Loop**: Automatically improves analysis quality across iterations by detecting and addressing gaps
- **Multi-Source Evidence**: Confidence scoring rewards corroboration across independent data sources
- **Structured Logging**: Full audit trail of every decision, tool call, and reasoning step
- **Forensic Tools**: Built-in simulators for timeline analysis, process examination, and log parsing
- **Streamlit UI**: Interactive interface for case management and real-time progress visualization

## Project Structure

```
├── app.py                 # Streamlit web interface
├── requirements.txt       # Python dependencies
├── sample_data.json       # Example forensic data for testing
├── graph/
│   └── workflow.py       # LangGraph workflow definition
├── agents/
│   ├── triage.py         # Triage Agent implementation
│   ├── critic.py         # Critic Agent implementation
│   └── planner.py        # Planner Agent implementation
├── tools/
│   ├── timeline.py       # Timeline analysis tool
│   ├── processes.py      # Process analysis tool
│   └── logs.py           # Log parsing tool
└── utils/
    ├── logger.py         # Structured JSON logging
    └── scoring.py        # Confidence scoring helpers
```

## Setup

### Prerequisites

- Python 3.9+
- Grok API key (from https://console.x.ai)

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd self-correcting-dfir-agent
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up your API key:
   ```bash
   export GROK_API_KEY="your-api-key-here"  # Or set via environment
   ```

## Usage

### Running the Streamlit App

```bash
streamlit run app.py
```

The app will open at `http://localhost:8501` and provide:
- Case file upload or built-in sample data
- Configurable max iterations and Grok API settings
- Live step-by-step execution display
- Final dashboard with findings, confidence metrics, and audit log

### Example Workflow

1. **Upload forensic data** (JSON format with events, processes, logs)
2. **Configure analysis parameters**:
   - Maximum iterations (1-5 recommended)
   - API key validation
3. **Start analysis** — Watch real-time progress
4. **Review results**:
   - Findings table with severity and confidence
   - Quality visualization
   - Iteration-by-iteration improvements
   - Full audit trail

## Architecture

### State Flow

```
START
  ↓
[Triage] → Runs tools, extracts findings from Grok
  ↓
[Critic] → Reviews for gaps and contradictions
  ↓
[Planner] → Decides: continue or finalize?
  ↓
? ────→ [Triage] (if max_iterations not reached & quality < 0.80)
  ↓
[Report] → Compiles final structured output
  ↓
END
```

### Evidence Scoring

Confidence scores are computed based on:
- **Corroboration**: Multiple independent tools supporting the same finding (+15% per source)
- **Contradictions**: Evidence conflicts detected (-25%)
- **Single sourcing**: Weak single-tool findings (-15% penalty)
- **Completeness**: Missing expected artifacts (-10% per gap)

Final flag assignment:
- **Confirmed**: confidence ≥ 0.75
- **Suspicious**: 0.40 ≤ confidence < 0.75
- **Inconsistent**: confidence < 0.40

## Configuration

### Environment Variables

```bash
GROK_API_KEY    # Required: Grok API key from https://console.x.ai
```

### Parameters

- `max_iterations`: Maximum analysis loops (default: 3)
- `filter_level`: Log filter intensity ('all', 'critical', 'high')
- `depth`: Analysis depth for tools ('standard', 'deep')

## Logging

All events are logged to the structured audit trail with:
- Timestamp (UTC)
- Agent name
- Event type (INFO, WARNING, ERROR, DECISION, TOOL_CALL)
- Iteration number
- Full details payload

Export log as JSON from the final report for downstream analysis.

## Dependencies

- **langgraph** ≥ 0.2.0 — Graph-based agent orchestration
- **openai** ≥ 1.0.0 — Grok API access (OpenAI-compatible)
- **streamlit** ≥ 1.40.0 — Web interface
- **pandas** ≥ 2.0.0 — Data visualization
- **python-dotenv** ≥ 1.0.0 — Environment configuration

See `requirements.txt` for full list and versions.

## Example Data Format

```json
{
  "case_id": "CASE-2024-001",
  "hostname": "workstation-42",
  "analyst_notes": "Suspected credential theft",
  "events": [
    {
      "timestamp": "2024-01-15T08:15:32Z",
      "type": "process_create",
      "path": "C:\\Windows\\System32\\cmd.exe"
    }
  ],
  "processes": [
    {
      "pid": 1234,
      "name": "svchost.exe",
      "path": "C:\\Windows\\System32\\svchost.exe",
      "parent_name": "services.exe"
    }
  ],
  "logs": [
    {
      "event_id": 4688,
      "timestamp": "2024-01-15T08:15:32Z",
      "details": {"new_process": "cmd.exe"}
    }
  ]
}
```

## Future Enhancements

- [ ] Integration with real forensic tools (log2timeline, Volatility, etc.)
- [ ] Support for multiple disk images / memory captures
- [ ] VirusTotal/YARA hash intelligence integration
- [ ] Timeline correlation and persistence chain detection
- [ ] Multi-host analysis coordination
- [ ] Automated MITRE ATT&CK tactic mapping

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with description

## License

MIT

## Support

For issues or questions:
- Check the [Issues](issues) tab
- Review logs in the Streamlit UI audit trail
- Enable debug logging by setting `log_level=DEBUG`

---

**Built with LangGraph for autonomous, iterative digital forensics.**
