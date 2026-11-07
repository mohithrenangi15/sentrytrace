"""
sentrytrace/inference_engine.py
Subprocess lifecycle manager and client for local llama-server sidecar.
"""

from __future__ import annotations
import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, Generator, List, Optional
import httpx


@dataclass(slots=True)
class ModelConfig:
    model_path: str
    host: str = "127.0.0.1"
    port: int = 8080
    n_ctx: int = 4096
    n_threads: int = 6
    n_gpu_layers: int = 99  # Offload all layers to Metal GPU on Apple Silicon
    binary_path: str = "llama-server"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class SidecarProcessManager:
    """
    Manages the lifecycle of the local llama-server child process.
    Guarantees clean startup, health verification, and SIGTERM shutdown.
    """

    def __init__(self, config: ModelConfig):
        self.config = config
        self.process: Optional[subprocess.Popen] = None

    def start(self, timeout_seconds: int = 30) -> None:
        """
        Launches llama-server and blocks until the HTTP /health endpoint is ready.
        """
        if self.is_healthy():
            return

        if not os.path.exists(self.config.model_path):
            raise FileNotFoundError(
                f"GGUF model file not found at: {self.config.model_path}\n"
                "Please verify the file path to your quantized GGUF model."
            )

        cmd = [
            self.config.binary_path,
            "-m", self.config.model_path,
            "--host", self.config.host,
            "--port", str(self.config.port),
            "-c", str(self.config.n_ctx),
            "-t", str(self.config.n_threads),
            "-ngl", str(self.config.n_gpu_layers),
        ]

        # Spawn child process in a separate process group to avoid pipe lockups and zombie processes
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if self.is_healthy():
                return
            time.sleep(0.5)

        self.stop()
        raise TimeoutError(f"llama-server failed to bind to {self.config.base_url} within {timeout_seconds}s.")

    def is_healthy(self) -> bool:
        """
        Polls health endpoint to check if model weights are loaded and server is serving.
        """
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.get(f"{self.config.base_url}/health")
                return res.status_code == 200
        except Exception:
            return False

    def stop(self) -> None:
        """
        Terminates the inference subprocess group cleanly.
        """
        if self.process:
            try:
                if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                else:
                    self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                else:
                    self.process.kill()
            finally:
                self.process = None


class LocalInferenceClient:
    """
    OpenAI-compatible client communicating with the local inference server (Ollama, llama-server, vLLM).
    """

    def __init__(self, base_url: str = "http://127.0.0.1:11434/v1"):
        clean_url = base_url.rstrip("/")
        # Automatically append /v1 if missing for Ollama / standard OpenAI endpoints
        if not clean_url.endswith("/v1"):
            clean_url = f"{clean_url}/v1"
        self.base_url = clean_url
        self.client = httpx.Client(base_url=self.base_url, timeout=120.0)

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str = "qwen2.5:3b",
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ) -> str:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        res = self.client.post("/chat/completions", json=payload)
        res.raise_for_status()
        data = res.json()
        return data["choices"][0]["message"]["content"]

    def stream_chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str = "qwen2.5:3b",
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ) -> Generator[str, None, None]:
        """
        Streams response tokens in real-time for live terminal UI rendering.
        """
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        with self.client.stream("POST", "/chat/completions", json=payload) as res:
            res.raise_for_status()
            for line in res.iter_lines():
                if not line or not line.startswith("data: "):
                    continue
                raw_chunk = line[6:].strip()
                if raw_chunk == "[DONE]":
                    break
                chunk_data = json.loads(raw_chunk)
                delta = chunk_data["choices"][0].get("delta", {}).get("content", "")
                if delta:
                    yield delta