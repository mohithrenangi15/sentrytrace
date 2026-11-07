"""
sentrytrace/cli.py
Terminal CLI for SentryTrace incident forensics.
Supports human-readable Rich formatting and raw machine JSON output.
"""

from __future__ import annotations
import json
import os
import sys
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from sentrytrace.agent import ForensicsAgent
from sentrytrace.inference_engine import LocalInferenceClient

app = typer.Typer(
    name="sentrytrace",
    help="SentryTrace: Air-gapped on-device incident forensics AI agent.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


@app.command("version")
def version():
    """Print the SentryTrace CLI version."""
    console.print("[bold cyan]SentryTrace[/bold cyan] [white]v0.1.0[/white] (Air-Gapped Edition)")


@app.command("scan")
def scan(
    log_file: str = typer.Argument(..., help="Path to production log file to scan"),
    model_url: str = typer.Option("http://127.0.0.1:11434", "--url", "-u", help="URL of local Ollama/OpenAI endpoint"),
    json_out: bool = typer.Option(False, "--json", help="Output raw structured JSON for CI/CD pipelines"),
):
    """
    Scans a log file and produces a deterministic forensic post-mortem report.
    """
    if not os.path.exists(log_file):
        if json_out:
            print(json.dumps({"status": "error", "message": f"Log file '{log_file}' not found."}))
        else:
            err_console.print(f"[bold red]Error:[/bold red] Log file '{log_file}' not found.")
        raise typer.Exit(code=1)

    client = LocalInferenceClient(base_url=model_url)
    agent = ForensicsAgent(log_file_path=log_file, inference_client=client)

    if json_out:
        # Machine-readable output mode: bypass spinners and terminal formatting
        report = agent.generate_post_mortem()
        print(report.model_dump_json(indent=2))
        return

    # Standard human-readable CLI output with Rich panels
    console.print(Panel.fit(
        "[bold cyan]SentryTrace | Air-Gapped Incident Forensics[/bold cyan]\n"
        "[dim]Zero-copy streaming • O(1) Memory • 100% Local Inference[/dim]",
        border_style="cyan"
    ))

    with console.status("[bold green]Streaming logs & reconstructing culprit context...[/bold green]"):
        culprit_events, trace_id = agent.assemble_culprit_context()

    if not culprit_events:
        console.print("[yellow]Scan completed cleanly. No anomalies detected.[/yellow]")
        return

    # Render Telemetry Table
    table = Table(title="Isolated Culprit Telemetry", border_style="red")
    table.add_column("Line", style="cyan", no_wrap=True)
    table.add_column("Timestamp", style="magenta")
    table.add_column("Level", style="bold red")
    table.add_column("Message Preview", style="white")

    for ev in culprit_events[:15]:
        lvl_style = "bold red" if ev.is_anomaly else "dim"
        table.add_row(
            str(ev.line_number),
            ev.timestamp or "N/A",
            f"[{lvl_style}]{ev.level or 'LOG'}[/{lvl_style}]",
            ev.message[:80] if ev.message else ""
        )

    console.print(table)
    if trace_id:
        console.print(f"[bold green]Correlated Distributed Trace ID:[/bold green] [yellow]{trace_id}[/yellow]\n")

    with console.status("[bold green]Synthesizing deterministic post-mortem with local model...[/bold green]"):
        report = agent.generate_post_mortem()

    report_md = f"""
# Incident Post-Mortem: {report.incident_type}

**Culprit Trace ID:** `{report.culprit_trace_id or 'None'}`  
**Trigger Line Numbers:** `{', '.join(map(str, report.culprit_line_numbers)) or 'N/A'}`

---

### Incident Timeline
{chr(10).join(f"- {step}" for step in report.timeline)}

---

### Root Cause Analysis
{report.root_cause_analysis}

---

### Recommended Remediation Steps
{chr(10).join(f"1. {step}" for step in report.remediation_steps)}
"""
    console.print(Panel(Markdown(report_md), title="Deterministic Forensics Report", border_style="green"))

    
    if not json_output:
        table = Table(title="Isolated Culprit Telemetry", border_style="red")
        table.add_column("Line", style="cyan", justify="right")
        table.add_column("Timestamp", style="yellow")
        table.add_column("Level", style="magenta")
        table.add_column("Message Preview", style="white")

        for event in culprit_events[:10]:
            msg_snippet = event.message or ""
            if len(msg_snippet) > 65:
                msg_snippet = msg_snippet[:62] + "..."
            table.add_row(
                str(event.line_number),
                event.timestamp or "N/A",
                event.level or "INFO",
                msg_snippet
            )

        console.print(table)
        if trace_id:
            console.print(f"[bold yellow]Correlated Distributed Trace ID:[/bold yellow] [bold white]{trace_id}[/bold white]\n")

    # Stage 3: LLM Root Cause Analysis
    if not json_output:
        with console.status("[bold yellow]Synthesizing Root Cause Analysis with local LLM...[/bold yellow]"):
            try:
                report = agent.generate_post_mortem()
            except Exception as e:
                err_console.print(f"[bold red]Inference failed:[/bold red] Could not reach endpoint at {model_url}. {e}")
                err_console.print("[dim]Ensure llama-server or Ollama is running locally.[/dim]")
                raise typer.Exit(code=1)
    else:
        report = agent.generate_post_mortem()

    # Stage 4: Output Rendering
    if json_output:
        print(json.dumps(report.model_dump(), indent=2))
        return

    # Render Clean Markdown Panel
    report_md = f"""
# Incident Post-Mortem: {report.incident_type}

**Culprit Trace ID:** `{report.culprit_trace_id or 'Isolated via Context Window'}`  
**Trigger Line Numbers:** `{', '.join(map(str, report.culprit_line_numbers)) or 'N/A'}`

---

### Incident Timeline
{chr(10).join(f"- {step}" for step in report.timeline)}

---

### Root Cause Analysis
{report.root_cause_analysis}

---

### Recommended Remediation Steps
{chr(10).join(f"1. {step}" for step in report.remediation_steps)}
"""
    console.print(Panel(
        Markdown(report_md),
        title="[bold green]Deterministic Forensics Report[/bold green]",
        border_style="green"
    ))


if __name__ == "__main__":
    app()