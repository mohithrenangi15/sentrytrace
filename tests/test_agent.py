"""
tests/test_agent.py
"""

import json
import tempfile
import httpx
from sentrytrace.agent import ForensicsAgent
from sentrytrace.inference_engine import LocalInferenceClient

sample_incident_log = """2026-10-15T09:15:00.100Z INFO [trace_id=tx-deadlock-99] Checkout request received for user 8821.
2026-10-15T09:15:01.200Z INFO [trace_id=tx-deadlock-99] Acquiring row lock on accounts table.
2026-10-15T09:15:03.400Z FATAL [trace_id=tx-deadlock-99] deadlock detected: Process 1420 waits for ShareLock on transaction 88102
2026-10-15T09:15:04.000Z INFO System monitoring alive.
"""

def test_agent_orchestrator():
    # 1. Create temporary incident log
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(sample_incident_log)
        log_path = f.name

    # 2. Mock inference client
    mock_client = LocalInferenceClient(base_url="[http://127.0.0.1:8080](http://127.0.0.1:8080)")

    mock_llm_json = {
        "incident_type": "Database Deadlock",
        "culprit_trace_id": "tx-deadlock-99",
        "culprit_line_numbers": [3],
        "timeline": [
            "09:15:00 - Checkout request initiated",
            "09:15:01 - Lock acquired on accounts",
            "09:15:03 - Deadlock detected on transaction 88102"
        ],
        "root_cause_analysis": "Two concurrent transactions attempted to lock mutual account rows in opposing orders, resulting in a Postgres ShareLock circular wait condition.",
        "remediation_steps": [
            "Enforce a uniform row-locking order across all transactional pathways.",
            "Implement exponential backoff retry logic on deadlock error codes (40P01)."
        ]
    }

    def mock_post(url, json=None, **kwargs):
        return httpx.Response(
            status_code=200,
            json={"choices": [{"message": {"content": json_module.dumps(mock_llm_json)}}]},
            request=httpx.Request("POST", "[http://127.0.0.1:8080/v1/chat/completions](http://127.0.0.1:8080/v1/chat/completions)")
        )

    import json as json_module
    mock_client.client.post = mock_post

    # 3. Run Agent
    agent = ForensicsAgent(log_file_path=log_path, inference_client=mock_client)
    report = agent.generate_post_mortem()

    assert report.incident_type == "Database Deadlock"
    assert report.culprit_trace_id == "tx-deadlock-99"
    assert 3 in report.culprit_line_numbers
    assert len(report.remediation_steps) == 2
    print("Forensics Agent successfully orchestrated parsing and RCA generation.")

if __name__ == "__main__":
    test_agent_orchestrator()