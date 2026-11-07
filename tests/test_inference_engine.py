"""
tests/test_inference_engine.py
"""

import httpx
from sentrytrace.inference_engine import LocalInferenceClient

def test_inference_client_mock():
    test_client = LocalInferenceClient(base_url="http://127.0.0.1:8080")

    def mock_post(url, json=None, **kwargs):
        assert "chat/completions" in str(url)
        assert json["temperature"] == 0.1
        return httpx.Response(
            status_code=200,
            json={
                "choices": [{
                    "message": {"content": "ROOT CAUSE: Database connection pool exhaustion detected."}
                }]
            },
            request=httpx.Request("POST", "http://127.0.0.1:8080/v1/chat/completions")
        )

    # Directly assign the mock method
    test_client.client.post = mock_post

    messages = [{"role": "user", "content": "Analyze log bundle."}]
    response = test_client.chat_completion(messages)
    assert "Database connection pool exhaustion" in response
    print("Inference client successfully verified.")

if __name__ == "__main__":
    test_inference_client_mock()