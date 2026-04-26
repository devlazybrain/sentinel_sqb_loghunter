"""Streamlit dashboard'ni ishga tushirish."""
from __future__ import annotations
import os
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if __name__ == "__main__":
    target = ROOT / "src" / "soc_analyzer" / "web" / "dashboard.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(target),
           "--server.port", "8501", "--server.headless", "true"]
    print(f"Launching: {' '.join(cmd)}")
    subprocess.run(cmd, check=False)
