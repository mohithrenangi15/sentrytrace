"""
scripts/build_binary.py
Bundles SentryTrace into a standalone binary using PyInstaller.
"""

import subprocess
import sys

def build():
    cmd = [
        "pyinstaller",
        "--noconfirm",
        "--onedir",
        "--name=sentrytrace-desktop",
        "--add-data=sentrytrace:sentrytrace",
        "--hidden-import=uvicorn.logging",
        "--hidden-import=uvicorn.loops",
        "--hidden-import=uvicorn.loops.auto",
        "--hidden-import=uvicorn.protocols",
        "--hidden-import=uvicorn.protocols.http",
        "--hidden-import=uvicorn.protocols.http.auto",
        "--hidden-import=uvicorn.lifespan",
        "--hidden-import=uvicorn.lifespan.on",
        "sentrytrace/desktop.py"
    ]
    print("Building standalone binary for SentryTrace...")
    result = subprocess.run(cmd)
    if result.returncode == 0:
        print("\nBuild successful! Standalone app located at: dist/sentrytrace-desktop/")
    else:
        print("\nBuild failed. Check the error output above.")

if __name__ == "__main__":
    build()