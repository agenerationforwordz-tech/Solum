#!/usr/bin/env python3
"""
Solum demo launcher. One command to try Solum with sample data, no setup:

    python start_demo.py

It installs the dependencies (first run only), loads the sample memory into a
throwaway SQLite database, starts the server, and opens your browser at
http://localhost:4320. Everything is local. Nothing leaves your machine.

This is the DEMO. To run your own Solum, see the README "Getting started".
"""
import os
import sys
import time
import shutil
import threading
import subprocess
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = os.environ.get("SOLUM_PORT", "4320")
URL = f"http://localhost:{PORT}"


def ensure_deps():
    """Install requirements the first time (idempotent)."""
    try:
        import mcp, fastembed, numpy, uvicorn, starlette  # noqa: F401
        return
    except ImportError:
        pass
    print("[demo] Installing dependencies (first run only, ~1 minute)...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-r",
         os.path.join(HERE, "requirements.txt")]
    )


def prep_db():
    """Copy the sample database into place. Fresh each run, so the demo resets."""
    data = os.path.join(HERE, "data")
    os.makedirs(data, exist_ok=True)
    dst = os.path.join(data, "brain.db")
    for ext in ("", "-wal", "-shm"):
        p = dst + ext
        if os.path.exists(p):
            os.remove(p)
    shutil.copy(os.path.join(HERE, "solum_demo.db"), dst)


def open_when_ready():
    """Wait for the server to answer, then open the browser."""
    for _ in range(60):
        time.sleep(1)
        try:
            urllib.request.urlopen(URL + "/health", timeout=1)
            break
        except Exception:
            continue
    print(f"\n[demo] Solum demo is live -> {URL}\n")
    try:
        import webbrowser
        webbrowser.open(URL)
    except Exception:
        pass


def main():
    ensure_deps()
    prep_db()
    env = dict(os.environ)
    env["SOLUM_DB_BACKEND"] = "sqlite"
    env["SOLUM_DEMO_MODE"] = "true"
    env.setdefault("SOLUM_PORT", PORT)
    print(f"[demo] Starting the Solum demo. Open {URL} when it says it is ready.")
    threading.Thread(target=open_when_ready, daemon=True).start()
    subprocess.run([sys.executable, os.path.join(HERE, "server.py")], env=env)


if __name__ == "__main__":
    main()
