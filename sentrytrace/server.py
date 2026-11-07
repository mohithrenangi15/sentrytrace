"""
sentrytrace/server.py
Local lightweight FastAPI backend serving the 100% offline incident forensics dashboard.
"""

from __future__ import annotations
import os
import tempfile
from typing import Optional
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from sentrytrace.agent import ForensicsAgent
from sentrytrace.inference_engine import LocalInferenceClient

app = FastAPI(title="SentryTrace Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/scan")
async def scan_log(
    file: UploadFile = File(...),
    model_url: Optional[str] = Form("http://127.0.0.1:8080"),
):
    """
    Receives an uploaded log file, streams it into a temporary buffer on disk,
    and returns structured post-mortem telemetry.
    """
    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
        while chunk := await file.read(1024 * 64):
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        client = LocalInferenceClient(base_url=model_url or "http://127.0.0.1:8080")
        agent = ForensicsAgent(log_file_path=tmp_path, inference_client=client)

        culprit_events, trace_id = agent.assemble_culprit_context()
        report = agent.generate_post_mortem()

        return JSONResponse(
            content={
                "status": "success",
                "trace_id": trace_id,
                "culprit_events": [e.to_dict() for e in culprit_events[:25]],
                "report": report.model_dump(),
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)},
        )
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return HTMLResponse(content=OFFLINE_DASHBOARD_HTML)


OFFLINE_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentryTrace | Air-Gapped Incident Forensics</title>
    <style>
        :root {
            --bg-dark: #0a0e17;
            --card-bg: #111726;
            --border-color: #1e293b;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-red: #f43f5e;
            --font-stack: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --mono-stack: "SF Mono", Monaco, Consolas, "Liberation Mono", Menlo, Courier, monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background-color: var(--bg-dark); color: var(--text-main); font-family: var(--font-stack); min-height: 100vh; display: flex; flex-direction: column; }
        .mono { font-family: var(--mono-stack); }

        /* Header */
        header { background: rgba(17, 23, 38, 0.8); border-bottom: 1px solid var(--border-color); padding: 14px 28px; display: flex; justify-content: space-between; align-items: center; }
        .logo-wrap { display: flex; align-items: center; gap: 10px; }
        .logo-dot { width: 12px; height: 12px; background: var(--accent-cyan); border-radius: 50%; box-shadow: 0 0 10px var(--accent-cyan); }
        .badge { font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #164e63; background: #083344; color: #38bdf8; font-weight: 600; }
        .badge-green { border-color: #064e3b; background: #022c22; color: #34d399; }
        .status-indicators { font-size: 12px; color: var(--text-muted); display: flex; gap: 16px; align-items: center; }
        .dot-green { width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green); display: inline-block; margin-right: 6px; }

        /* Main Workspace */
        main { max-width: 1150px; width: 100%; margin: 24px auto; padding: 0 20px; display: flex; flex-direction: column; gap: 20px; flex: 1; }
        .grid-config { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        .card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; }

        /* Upload Dropzone */
        .dropzone { border: 2px dashed var(--border-color); display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; cursor: pointer; transition: 0.2s border; min-height: 140px; }
        .dropzone:hover { border-color: var(--accent-cyan); }
        .dropzone-icon { font-size: 32px; margin-bottom: 8px; }
        .dropzone-title { font-weight: 600; font-size: 14px; margin-bottom: 4px; }
        .dropzone-desc { font-size: 12px; color: var(--text-muted); }

        /* Controls */
        label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 6px; }
        input[type="text"] { width: 100%; background: #060911; border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 12px; color: #fff; font-size: 12px; outline: none; margin-bottom: 14px; }
        input[type="text"]:focus { border-color: var(--accent-cyan); }
        button.btn-primary { width: 100%; background: #0891b2; color: #fff; border: none; border-radius: 6px; padding: 10px; font-weight: 600; font-size: 13px; cursor: pointer; transition: 0.2s background; }
        button.btn-primary:hover { background: var(--accent-cyan); }
        button.btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

        /* Status Bar */
        .progress-bar { display: none; align-items: center; justify-content: space-between; padding: 12px 18px; font-size: 12px; }
        .spinner { width: 14px; height: 14px; border: 2px solid var(--accent-cyan); border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; display: inline-block; margin-right: 10px; }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* Results & Tables */
        .hidden { display: none !important; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; text-align: left; margin-top: 10px; }
        th { border-bottom: 1px solid var(--border-color); color: var(--text-muted); font-size: 10px; text-transform: uppercase; padding: 8px 6px; }
        td { padding: 8px 6px; border-bottom: 1px solid #161f30; }
        tr.anomaly-row td { color: #fecdd3; }
        .tag-pill { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 600; }
        .tag-error { background: #4c0519; color: #f43f5e; }
        .tag-info { background: #082f49; color: #38bdf8; }

        /* Report Section */
        .report-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 14px; margin-bottom: 16px; }
        .report-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .report-col h4 { font-size: 11px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: 8px; }
        .timeline-item { font-size: 12px; margin-bottom: 6px; display: flex; gap: 8px; color: #cbd5e1; }
        .mechanism-box { background: #060911; border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-size: 12px; line-height: 1.5; color: #cbd5e1; }
        .remedy-item { font-size: 12px; color: #a7f3d0; margin-bottom: 6px; display: flex; gap: 6px; }
    </style>
</head>
<body>

    <header>
        <div class="logo-wrap">
            <div class="logo-dot"></div>
            <strong>SentryTrace</strong>
            <span class="badge">AIR-GAPPED AGENT</span>
        </div>
        <div class="status-indicators mono">
            <span><span class="dot-green"></span>Memory: O(1) Constant</span>
            <span>Target: Apple Silicon Metal / 127.0.0.1</span>
        </div>
    </header>

    <main>
        <section class="grid-config">
            <div class="card dropzone" id="dropzone">
                <input type="file" id="fileInput" style="display:none;" accept=".log,.txt,.json">
                <div class="dropzone-icon">📄</div>
                <div class="dropzone-title">Select or drag & drop server log file</div>
                <div class="dropzone-desc mono" id="fileLabel">Chunked streaming parser • Zero cloud leakage</div>
            </div>

            <div class="card">
                <label class="mono">Local Endpoint</label>
                <input type="text" id="modelUrl" value="http://127.0.0.1:8080" class="mono">
                <button class="btn-primary" id="scanBtn">Run Incident Forensics</button>
            </div>
        </section>

        <!-- Progress Spinner -->
        <div class="card progress-bar mono" id="progressBar">
            <div>
                <span class="spinner"></span>
                <span id="statusText">Streaming gigabyte logs & isolating culprit trace...</span>
            </div>
            <div style="color: var(--accent-cyan); font-weight:600;" id="timer">0.0s</div>
        </div>

        <!-- Investigation Results -->
        <div id="resultsContainer" class="hidden" style="display:flex; flex-direction:column; gap:20px;">
            
            <!-- Culprit Logs Table -->
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <strong style="font-size:13px; text-transform:uppercase; letter-spacing:0.05em;">Isolated Culprit Logs</strong>
                    <span class="badge mono" id="traceBadge">Trace: N/A</span>
                </div>
                <table class="mono">
                    <thead>
                        <tr>
                            <th>Line</th>
                            <th>Timestamp</th>
                            <th>Level</th>
                            <th>Message Preview</th>
                        </tr>
                    </thead>
                    <tbody id="telemetryTbody"></tbody>
                </table>
            </div>

            <!-- Root Cause Analysis Card -->
            <div class="card" style="border-color: #064e3b;">
                <div class="report-header">
                    <div>
                        <span class="badge badge-green mono">ROOT CAUSE POST-MORTEM</span>
                        <h2 id="reportTitle" style="font-size:18px; margin-top:6px;"></h2>
                    </div>
                </div>

                <div class="report-grid">
                    <div class="report-col">
                        <h4>Failure Progression</h4>
                        <div id="timelineContainer" class="mono"></div>
                    </div>
                    <div class="report-col">
                        <h4>Root Cause Mechanism</h4>
                        <div class="mechanism-box" id="mechanismText"></div>
                    </div>
                </div>

                <div style="margin-top:16px; border-top:1px solid var(--border-color); padding-top:14px;">
                    <h4 style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:8px;">Actionable Fixes</h4>
                    <div id="remediationContainer"></div>
                </div>
            </div>

        </div>
    </main>

    <script>
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('fileInput');
        const fileLabel = document.getElementById('fileLabel');
        const scanBtn = document.getElementById('scanBtn');
        const progressBar = document.getElementById('progressBar');
        const timer = document.getElementById('timer');
        const resultsContainer = document.getElementById('resultsContainer');

        let selectedFile = null;
        let timerId = null;

        dropzone.onclick = () => fileInput.click();

        fileInput.onchange = (e) => {
            if (e.target.files.length > 0) {
                selectedFile = e.target.files[0];
                fileLabel.textContent = `${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
                fileLabel.style.color = 'var(--accent-cyan)';
            }
        };

        scanBtn.onclick = async () => {
            if (!selectedFile) {
                alert('Select a log file first.');
                return;
            }

            const formData = new FormData();
            formData.append('file', selectedFile);
            formData.append('model_url', document.getElementById('modelUrl').value);

            progressBar.style.display = 'flex';
            resultsContainer.classList.add('hidden');
            scanBtn.disabled = true;

            let elapsed = 0;
            timer.textContent = '0.0s';
            timerId = setInterval(() => {
                elapsed += 0.1;
                timer.textContent = elapsed.toFixed(1) + 's';
            }, 100);

            try {
                const res = await fetch('/api/scan', { method: 'POST', body: formData });
                const data = await res.json();

                if (data.status !== 'success') {
                    alert('Scan failed: ' + (data.message || 'Check terminal logs'));
                    return;
                }

                renderDashboard(data);
            } catch (err) {
                alert('Connection error: ' + err.message);
            } finally {
                clearInterval(timerId);
                progressBar.style.display = 'none';
                scanBtn.disabled = false;
            }
        };

        function renderDashboard(data) {
            resultsContainer.classList.remove('hidden');
            document.getElementById('traceBadge').textContent = data.trace_id ? `Trace: ${data.trace_id}` : 'Context Window Bound';

            // Populate Table
            const tbody = document.getElementById('telemetryTbody');
            tbody.innerHTML = '';
            data.culprit_events.forEach(e => {
                const row = document.createElement('tr');
                if (e.is_anomaly) row.className = 'anomaly-row';
                const tagClass = e.is_anomaly ? 'tag-error' : 'tag-info';
                row.innerHTML = `
                    <td style="color:var(--accent-cyan);">${e.line_number}</td>
                    <td style="color:var(--text-muted);">${e.timestamp || 'N/A'}</td>
                    <td><span class="tag-pill ${tagClass}">${e.level || 'INFO'}</span></td>
                    <td style="max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${e.message}</td>
                `;
                tbody.appendChild(row);
            });

            // Populate Report
            const r = data.report;
            document.getElementById('reportTitle').textContent = r.incident_type;
            document.getElementById('mechanismText').textContent = r.root_cause_analysis;

            const tl = document.getElementById('timelineContainer');
            tl.innerHTML = '';
            r.timeline.forEach(step => {
                const item = document.createElement('div');
                item.className = 'timeline-item';
                item.innerHTML = `<span style="color:var(--accent-cyan);">▸</span><span>${step}</span>`;
                tl.appendChild(item);
            });

            const rm = document.getElementById('remediationContainer');
            rm.innerHTML = '';
            r.remediation_steps.forEach(step => {
                const item = document.createElement('div');
                item.className = 'remedy-item';
                item.innerHTML = `<span>✓</span><span>${step}</span>`;
                rm.appendChild(item);
            });
        }
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sentrytrace.server:app", host="127.0.0.1", port=8000, reload=True)