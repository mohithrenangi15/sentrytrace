"""
sentrytrace/desktop.py
Native desktop window launcher for SentryTrace using pywebview.
"""
import threading
import time
import uvicorn
import webview
from sentrytrace.server import app

def start_server():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

def main():
    # Run backend in background daemon thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    # Launch native Cocoa desktop window
    webview.create_window(
        title="SentryTrace | Air-Gapped Forensics",
        url="http://127.0.0.1:8000",
        width=1150,
        height=800,
        min_size=(900, 600),
        text_select=True,
    )
    webview.start()

if __name__ == "__main__":
    main()