"""
utils/logger.py
Structured JSON logger for the DFIR agent workflow.
Every step, decision, and tool call is recorded with full context.
"""

import json
from datetime import datetime, timezone
from typing import Optional


class StructuredLogger:
    """
    Provides structured JSON logging for the DFIR workflow.
    All entries include timestamp, level, agent, iteration,
    tool used, and a details payload — making the audit trail
    machine-readable and human-understandable.
    """

    def __init__(self, name: str = "dfir_agent"):
        self.name = name
        self.entries: list[dict] = []

    # ------------------------------------------------------------------ #
    #  Core logging method                                                 #
    # ------------------------------------------------------------------ #
    def log(
        self,
        level: str,
        event: str,
        agent: str,
        details: Optional[dict] = None,
        tool: Optional[str] = None,
        iteration: Optional[int] = None,
    ) -> dict:
        """Create a structured log entry and append it to the in-memory log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "agent": agent,
            "event": event,
            "iteration": iteration,
            "tool": tool,
            "details": details or {},
        }
        self.entries.append(entry)
        return entry

    # ------------------------------------------------------------------ #
    #  Convenience wrappers                                                #
    # ------------------------------------------------------------------ #
    def info(self, event: str, agent: str, **kwargs) -> dict:
        return self.log("INFO", event, agent, **kwargs)

    def warning(self, event: str, agent: str, **kwargs) -> dict:
        return self.log("WARNING", event, agent, **kwargs)

    def error(self, event: str, agent: str, **kwargs) -> dict:
        return self.log("ERROR", event, agent, **kwargs)

    def tool_call(
        self,
        tool: str,
        agent: str,
        parameters: dict,
        result_summary: str,
        iteration: int,
    ) -> dict:
        """Log a tool invocation with its parameters and a short result summary."""
        return self.log(
            "TOOL_CALL",
            f"Tool '{tool}' invoked",
            agent,
            details={"parameters": parameters, "result_summary": result_summary},
            tool=tool,
            iteration=iteration,
        )

    def decision(
        self,
        event: str,
        agent: str,
        reasoning: str,
        outcome: str,
        iteration: int,
    ) -> dict:
        """Log an agent decision with its reasoning and outcome."""
        return self.log(
            "DECISION",
            event,
            agent,
            details={"reasoning": reasoning, "outcome": outcome},
            iteration=iteration,
        )

    # ------------------------------------------------------------------ #
    #  Retrieval helpers                                                   #
    # ------------------------------------------------------------------ #
    def get_entries(self) -> list[dict]:
        return self.entries

    def get_entries_by_agent(self, agent: str) -> list[dict]:
        return [e for e in self.entries if e["agent"] == agent]

    def get_entries_by_iteration(self, iteration: int) -> list[dict]:
        return [e for e in self.entries if e.get("iteration") == iteration]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.entries, indent=indent)

    def clear(self) -> None:
        """Reset the logger — useful between Streamlit reruns."""
        self.entries = []


# Single shared logger instance imported across the project
dfir_logger = StructuredLogger()
