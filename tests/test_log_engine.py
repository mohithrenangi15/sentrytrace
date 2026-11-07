import tempfile
from sentrytrace.log_engine import IncidentLogEngine

sample_logs = """2026-10-15T09:15:00.123Z INFO [trace_id=a1b2c3d4-e5f6-7890-abcd-1234567890ef] Worker spawned successfully.
2026-10-15T09:15:01.450Z INFO [trace_id=a1b2c3d4-e5f6-7890-abcd-1234567890ef] Fetching order details for user_id=4091.
2026-10-15T09:15:02.890Z ERROR [trace_id=a1b2c3d4-e5f6-7890-abcd-1234567890ef] PoolAcquireTimeoutException: connection pool exhausted after 30000ms
{"timestamp": "2026-10-15T09:15:03Z", "level": "FATAL", "trace_id": "bbbbbbbb-1111-2222-3333-444444444444", "message": "deadlock detected on relation 'orders'"}
2026-10-15T09:15:04.000Z INFO Server health check OK.
"""

with tempfile.NamedTemporaryFile("w+", delete=False) as f:
    f.write(sample_logs)
    temp_path = f.name

engine = IncidentLogEngine(temp_path)

# Test Anomaly Scanner
anomalies = engine.scan_anomalies()
assert len(anomalies) == 2, f"Expected 2 anomalies, found {len(anomalies)}"
print(f"Detected {len(anomalies)} anomalies successfully.")

# Test Trace Extraction
trace_events = engine.isolate_trace("a1b2c3d4-e5f6-7890-abcd-1234567890ef")
assert len(trace_events) == 3, f"Expected 3 trace events, found {len(trace_events)}"
print(f"Stitched trace with {len(trace_events)} lifecycle steps.")

# Test Context Window
window = engine.extract_context_window(target_line_number=3, window_size=1)
assert len(window) == 3
print(f"Context window captured {len(window)} lines around incident.")