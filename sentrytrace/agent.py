"""
sentrytrace/agent.py
Core forensic incident analysis orchestrator.
Bridges deterministic log pre-filtering with local inference.
"""

from __future__ import annotations
import json
import re
from typing import List, Optional
from pydantic import BaseModel, Field

from sentrytrace.log_engine import IncidentLogEngine, LogEvent
from sentrytrace.inference_engine import LocalInferenceClient


class IncidentReport(BaseModel):
    incident_type: str = Field(description="Classification of incident (e.g. Deadlock, Connection Pool Exhaustion, OOM)")
    culprit_trace_id: Optional[str] = Field(None, description="Primary trace ID or correlation ID involved")
    culprit_line_numbers: List[int] = Field(default_factory=list, description="Exact log line numbers where failure triggers occurred")
    timeline: List[str] = Field(default_factory=list, description="Chronological sequence leading to failure")
    root_cause_analysis: str = Field(description="In-depth technical breakdown of the crash mechanism")
    remediation_steps: List[str] = Field(default_factory=list, description="Actionable architectural or code fixes")


SYSTEM_PROMPT = """You are SentryTrace, an air-gapped on-device incident forensics engineer.
Your task is to analyze the provided pre-filtered log slice from a crashed production server.

RULES:
1. Base your findings ONLY on the provided log events. Do NOT invent line numbers, timestamps, or service names.
2. Identify the root trigger (why the system failed, not just the symptom).
3. Always respond with strict, valid JSON matching the schema below. No markdown backticks, no conversational fluff.

JSON Output Schema:
{
  "incident_type": "string",
  "culprit_trace_id": "string or null",
  "culprit_line_numbers": [123, 124],
  "timeline": ["09:15:00 - Worker spawned", "09:15:02 - Pool exhausted"],
  "root_cause_analysis": "string explanation",
  "remediation_steps": ["Step 1", "Step 2"]
}
"""


def extract_json_payload(raw_text: str) -> dict:
    """
    Cleans markdown backticks, conversational preamble, and trailing characters
    to reliably parse JSON returned by smaller local models.
    """
    clean_text = raw_text.strip()

    # 1. Strip markdown fences (```json ... ``` or ``` ... ```)
    if "```" in clean_text:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", clean_text, re.DOTALL)
        if match:
            clean_text = match.group(1).strip()

    # 2. Extract outermost JSON object if preamble text exists before {
    if not clean_text.startswith("{"):
        match = re.search(r"(\{.*\})", clean_text, re.DOTALL)
        if match:
            clean_text = match.group(1).strip()

    return json.loads(clean_text)


class ForensicsAgent:
    """
    Coordinates anomaly detection, context window extraction,
    prompt assembly, and LLM-driven post-mortem generation.
    """

    def __init__(self, log_file_path: str, inference_client: Optional[LocalInferenceClient] = None):
        self.engine = IncidentLogEngine(log_file_path)
        self.client = inference_client or LocalInferenceClient()

    def assemble_culprit_context(self, max_context_lines: int = 50) -> tuple[List[LogEvent], Optional[str]]:
        """
        Extracts anomalous events and builds a compact incident bundle.
        """
        anomalies = self.engine.scan_anomalies(max_anomalies=10)
        if not anomalies:
            return [], None

        primary_anomaly = anomalies[0]
        target_trace = primary_anomaly.trace_id

        # Strategy A: Correlate entire trace lifecycle if trace_id exists
        if target_trace:
            trace_events = self.engine.isolate_trace(target_trace)
            if trace_events:
                return trace_events[:max_context_lines], target_trace

        # Strategy B: Context window around first anomaly
        context_window = self.engine.extract_context_window(
            target_line_number=primary_anomaly.line_number,
            window_size=max_context_lines // 2
        )
        return context_window, target_trace

    def generate_post_mortem(self) -> IncidentReport:
        """
        Runs the end-to-end deterministic investigation pipeline and builds
        the structured incident post-mortem report.
        """
        culprit_events, trace_id = self.assemble_culprit_context()
        if not culprit_events:
            return IncidentReport(
                incident_type="No Anomaly Detected",
                culprit_trace_id=None,
                culprit_line_numbers=[],
                timeline=["Scan completed cleanly. No critical errors found."],
                root_cause_analysis="The log file contains no known fatal signatures or HTTP 5xx errors.",
                remediation_steps=[]
            )

        # Format events into compact prompt lines
        formatted_logs = "\n".join(
            f"Line {e.line_number}: [{e.timestamp or 'NO_TS'}] [{e.level or 'LOG'}] {e.message}"
            for e in culprit_events
        )

        user_content = f"INCIDENT LOG CONTEXT:\n{formatted_logs}\n\nAnalyze this incident and output the post-mortem JSON."

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

        raw_response = self.client.chat_completion(messages=messages, temperature=0.1)

        # Robust parsing into IncidentReport Pydantic schema
        try:
            parsed = extract_json_payload(raw_response)
            return IncidentReport(
                incident_type=parsed.get("incident_type", "Unknown Incident"),
                culprit_trace_id=parsed.get("culprit_trace_id") or trace_id,
                culprit_line_numbers=parsed.get("culprit_line_numbers") or [e.line_number for e in culprit_events if e.is_anomaly],
                timeline=parsed.get("timeline", []),
                root_cause_analysis=parsed.get("root_cause_analysis", "No detailed mechanism provided."),
                remediation_steps=parsed.get("remediation_steps", [])
            )
        except Exception:
            # Fallback if the output still cannot be parsed
            return IncidentReport(
                incident_type="Forensic Parsing Failure",
                culprit_trace_id=trace_id,
                culprit_line_numbers=[e.line_number for e in culprit_events if e.is_anomaly],
                timeline=[f"{e.timestamp}: {e.message}" for e in culprit_events[:5]],
                root_cause_analysis=raw_response,
                remediation_steps=["Review raw LLM response in root_cause_analysis."]
            )