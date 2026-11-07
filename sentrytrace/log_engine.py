from __future__ import annotations
import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Generator, Optional, Pattern


# --- Core Data Models ---

@dataclass(slots=True)
class LogEvent:
    line_number: int
    raw: str
    timestamp: Optional[str] = None
    level: Optional[str] = None
    trace_id: Optional[str] = None
    message: Optional[str] = None
    is_anomaly: bool = False

    def to_dict(self) -> dict:
        return asdict(self)



TIMESTAMP_PATTERN: Pattern[str] = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)

TRACE_ID_PATTERNS: list[Pattern[str]] = [
    re.compile(r"traceparent[=:\s]+00-([a-f0-9]{32})-[a-f0-9]{16}-[a-f0-9]{2}", re.I),
    re.compile(r"(?:trace_?id|correlation_?id|request_?id|x-request-id)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9\-_]{16,64})[\"']?", re.I),
    re.compile(r"\b([a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\b", re.I),
]

ANOMALY_SIGNATURES: Pattern[str] = re.compile(
    r"(?:"
    r"FATAL|CRITICAL|PANIC|EMERGENCY|"
    r"Exception|Error|Traceback|"
    r"Connection\s*refused|Connection\s*reset|"
    r"PoolAcquireTimeoutException|connection\s*pool\s*exhausted|"
    r"deadlock\s*detected|deadlock\s*victim|"
    r"OOMKilled|OutOfMemoryError|"
    r"status_code[=:\s]+5\d{2}|HTTP\s*5\d{2}"
    r")",
    re.IGNORECASE,
)

LEVEL_PATTERN: Pattern[str] = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL|PANIC)\b",
    re.IGNORECASE,
)


class StreamingLogReader:
    def __init__(self, file_path: str, buffer_size: int = 64 * 1024):
        self.file_path = file_path
        self.buffer_size = buffer_size
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

    def stream_lines(self) -> Generator[tuple[int, str], None, None]:
        with open(self.file_path, "r", encoding="utf-8", errors="replace", buffering=self.buffer_size) as f:
            for line_number, line in enumerate(f, start=1):
                yield line_number, line.rstrip("\r\n")


class ForensicsLogParser:
    @staticmethod
    def extract_trace_id(line: str) -> Optional[str]:
        for pattern in TRACE_ID_PATTERNS:
            match = pattern.search(line)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def parse_line(line_number: int, line: str) -> LogEvent:
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                data = json.loads(stripped)
                trace_id = (
                    data.get("trace_id")
                    or data.get("traceId")
                    or data.get("correlation_id")
                    or data.get("requestId")
                    or ForensicsLogParser.extract_trace_id(line)
                )
                level = str(data.get("level") or data.get("severity") or "INFO").upper()
                msg = str(data.get("message") or data.get("msg") or line)
                ts = str(data.get("timestamp") or data.get("time") or "")
                
                is_anomaly = bool(
                    level in {"ERROR", "CRITICAL", "FATAL", "PANIC"}
                    or ANOMALY_SIGNATURES.search(msg)
                )
                return LogEvent(
                    line_number=line_number,
                    raw=line,
                    timestamp=ts or None,
                    level=level,
                    trace_id=str(trace_id) if trace_id else None,
                    message=msg,
                    is_anomaly=is_anomaly,
                )
            except Exception:
                pass

        ts_match = TIMESTAMP_PATTERN.search(line)
        lvl_match = LEVEL_PATTERN.search(line)
        trace_id = ForensicsLogParser.extract_trace_id(line)
        is_anomaly = bool(ANOMALY_SIGNATURES.search(line))

        return LogEvent(
            line_number=line_number,
            raw=line,
            timestamp=ts_match.group(0) if ts_match else None,
            level=lvl_match.group(1).upper() if lvl_match else None,
            trace_id=trace_id,
            message=line,
            is_anomaly=is_anomaly,
        )


class IncidentLogEngine:
    def __init__(self, file_path: str):
        self.reader = StreamingLogReader(file_path)
        self.parser = ForensicsLogParser()

    def scan_anomalies(self, max_anomalies: int = 500) -> list[LogEvent]:
        anomalies: list[LogEvent] = []
        for line_num, line in self.reader.stream_lines():
            event = self.parser.parse_line(line_num, line)
            if event.is_anomaly:
                anomalies.append(event)
                if len(anomalies) >= max_anomalies:
                    break
        return anomalies

    def isolate_trace(self, target_trace_id: str) -> list[LogEvent]:
        trace_events: list[LogEvent] = []
        for line_num, line in self.reader.stream_lines():
            if target_trace_id in line:
                event = self.parser.parse_line(line_num, line)
                if event.trace_id == target_trace_id or target_trace_id in event.raw:
                    trace_events.append(event)
        return trace_events

    def extract_context_window(
        self, target_line_number: int, window_size: int = 25
    ) -> list[LogEvent]:
        start_line = max(1, target_line_number - window_size)
        end_line = target_line_number + window_size
        window: list[LogEvent] = []

        for line_num, line in self.reader.stream_lines():
            if line_num < start_line:
                continue
            if line_num > end_line:
                break
            window.append(self.parser.parse_line(line_num, line))

        return window