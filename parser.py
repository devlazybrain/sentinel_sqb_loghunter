"""
parser.py — Nginx/backend log parser for SQB LogHunter.

Supports two formats automatically:

1. Custom SQB format (space-delimited, 7 fields):
   TIMESTAMP IP METHOD URL STATUS BYTES USER_AGENT
   Example:
     2026-04-01T10:02:04Z 91.199.12.77 GET /api/accounts?id=1 500 2048 sqlmap/1.7.2

2. Standard Nginx combined log format:
   IP - - [DD/Mon/YYYY:HH:MM:SS +TZ] "METHOD URL PROTO" STATUS BYTES "-" "USER_AGENT"
   Example:
     10.64.65.169 - - [15/Nov/2024:09:00:08 +0500] "POST /api/v1/login HTTP/1.1" 200 3305 "-" "Mozilla/5.0"
"""

from __future__ import annotations

import io
import re
from datetime import datetime, timezone
from typing import Union

import pandas as pd

# Nginx combined log format regex
_NGINX_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+'          # IP - -
    r'\[([^\]]+)\]\s+'                  # [timestamp]
    r'"(\S+)\s+(.*?)\s+HTTP/\S+"\s+'    # "METHOD URL PROTO" — URL may contain spaces (SQLi payloads)
    r'(\d+)\s+(\d+)\s+'                # STATUS BYTES
    r'"[^"]*"\s+"([^"]*)"'             # "-" "USER_AGENT"
)


def _parse_nginx_line(line: str) -> dict | None:
    m = _NGINX_RE.match(line)
    if not m:
        return None
    ip, ts_raw, method, url, status_raw, bytes_raw, user_agent = m.groups()
    try:
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        status = int(status_raw)
        size = int(bytes_raw)
    except ValueError:
        return None
    return {
        "timestamp": ts,
        "ip": ip,
        "method": method.upper(),
        "url": url,
        "status": status,
        "bytes": size,
        "user_agent": user_agent,
    }


def _parse_sqb_line(line: str) -> dict | None:
    parts = line.split(" ", 6)
    if len(parts) != 7:
        return None
    ts_raw, ip, method, url, status_raw, bytes_raw, user_agent = parts
    try:
        ts = datetime.fromisoformat(ts_raw.rstrip("Z")).replace(tzinfo=timezone.utc)
        status = int(status_raw)
        size = int(bytes_raw)
    except ValueError:
        return None
    return {
        "timestamp": ts,
        "ip": ip,
        "method": method.upper(),
        "url": url,
        "status": status,
        "bytes": size,
        "user_agent": user_agent,
    }


def parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Detect format: Nginx combined starts with IP followed by " - - ["
    if re.match(r'^\S+\s+\S+\s+\S+\s+\[', line):
        return _parse_nginx_line(line)
    return _parse_sqb_line(line)


def parse_file(source: Union[str, io.IOBase]) -> pd.DataFrame:
    """Parse a log file (path string or file-like object) into a DataFrame."""
    rows = []
    if isinstance(source, str):
        with open(source, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    else:
        raw = source.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        lines = raw.splitlines()

    for line in lines:
        record = parse_line(line)
        if record:
            rows.append(record)

    if not rows:
        return pd.DataFrame(columns=["timestamp", "ip", "method", "url",
                                     "status", "bytes", "user_agent"])

    df = pd.DataFrame(rows)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "web_attack_logs.txt"
    df = parse_file(path)
    print(f"Parsed {len(df):,} log entries")
    print(f"Time range : {df['timestamp'].min()}  ->  {df['timestamp'].max()}")
    print(f"Unique IPs : {df['ip'].nunique()}")
    print(df.head())
