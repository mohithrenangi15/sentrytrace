"""
tests/benchmark_engine.py
Profiles throughput, latency, and peak RAM consumption of SentryTrace.
"""

from __future__ import annotations
import os
import sys
import time
import tracemalloc

from sentrytrace.agent import ForensicsAgent
from sentrytrace.inference_engine import LocalInferenceClient
from sentrytrace.log_engine import IncidentLogEngine


def run_benchmark(file_path: str, model_url: str = "http://127.0.0.1:11434"):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return

    file_size_bytes = os.path.getsize(file_path)
    file_size_mb = file_size_bytes / (1024 * 1024)

    print("\n" + "=" * 60)
    print(f"  SentryTrace Performance Profile: {os.path.basename(file_path)}")
    print(f"  File Size: {file_size_mb:.2f} MB ({file_size_bytes:,} bytes)")
    print("=" * 60)

    # 1. Track Heap Memory and Low-Level Engine Throughput
    tracemalloc.start()
    t_start = time.perf_counter()

    engine = IncidentLogEngine(file_path)
    anomalies = engine.scan_anomalies(max_anomalies=50)
    total_lines = sum(1 for _ in engine.reader.stream_lines())

    engine_duration = time.perf_counter() - t_start
    _, peak_ram = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_ram_mb = peak_ram / (1024 * 1024)
    throughput_mb_s = file_size_mb / engine_duration if engine_duration > 0 else 0
    lines_per_sec = total_lines / engine_duration if engine_duration > 0 else 0

    print(f"Total Lines Processed : {total_lines:,} lines")
    print(f"Engine Scan Time      : {engine_duration:.4f} s")
    print(f"I/O Throughput        : {throughput_mb_s:.2f} MB/s")
    print(f"Line Processing Speed : {lines_per_sec:,.0f} lines/sec")
    print(f"Peak Heap Memory (RAM): {peak_ram_mb:.3f} MB  (O(1) Memory Verification)")
    print(f"Anomalies Isolated    : {len(anomalies)} events")

    # 2. Track Full Agent + LLM Latency
    print("\nRunning End-to-End Forensics Agent (LLM Inference)...")
    client = LocalInferenceClient(base_url=model_url)
    agent = ForensicsAgent(log_file_path=file_path, inference_client=client)

    t_llm = time.perf_counter()
    report = agent.generate_post_mortem()
    agent_duration = time.perf_counter() - t_llm

    print(f"Total End-to-End Time : {agent_duration:.2f} s")
    print(f"Diagnosed Incident    : {report.incident_type}")
    print(f"Culprit Trace ID      : {report.culprit_trace_id or 'None'}")
    print(f"Trigger Line Numbers  : {report.culprit_line_numbers}")
    print(f"Remediation Steps     : {len(report.remediation_steps)} items")
    print("=" * 60)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "logs/real_hadoop.log"
    run_benchmark(target)