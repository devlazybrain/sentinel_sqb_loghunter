"""
Log Parser — Nginx + backend log faylini boyitilgan DataFrame'ga aylantiradi.

Qo'llab-quvvatlanadigan formatlar (avtomatik aniqlanadi):

1. Custom SQB formati (7 bo'sh joy bilan ajratilgan maydon):
   TIMESTAMP IP METHOD URL STATUS BYTES USER_AGENT
   Misol: 2026-04-01T09:00:01Z 185.23.44.12 GET /accounts 200 1019 PostmanRuntime/7.39.0

2. Standart Nginx combined log formati:
   IP - - [DD/Mon/YYYY:HH:MM:SS +TZ] "METHOD URL PROTO" STATUS BYTES "-" "USER_AGENT"
   Misol: 10.64.65.169 - - [15/Nov/2024:09:00:08 +0500] "POST /api/v1/login HTTP/1.1" 200 3305 "-" "Mozilla/5.0"
"""
from __future__ import annotations
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

from soc_analyzer.config import patterns as P_PATTERNS
from soc_analyzer.config import endpoints as P_ENDPOINTS
from soc_analyzer.config import thresholds as P_THR
from soc_analyzer.config.endpoint_store import get_merged

# SQB custom format
LOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+"
    r"(?P<ip>\S+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<url>\S+)\s+"
    r"(?P<status>\d+)\s+"
    r"(?P<bytes>\d+)\s+"
    r"(?P<ua>.+)$"
)

# Nginx combined log format
_NGINX_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+'           # IP - -
    r'\[([^\]]+)\]\s+'                   # [timestamp]
    r'"(\S+)\s+(.*?)\s+HTTP/\S+"\s+'    # "METHOD URL PROTO"
    r'(\d+)\s+(\d+)\s+'                 # STATUS BYTES
    r'"[^"]*"\s+"([^"]*)"'              # "-" "USER_AGENT"
)

_NGINX_DETECT_RE = re.compile(r'^\S+\s+\S+\s+\S+\s+\[')


def _parse_nginx_line(lineno: int, line: str) -> dict | None:
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
        "lineno":     lineno,
        "timestamp":  ts.isoformat(),
        "ip":         ip,
        "method":     method.upper(),
        "url_full":   url,
        "status":     status,
        "bytes":      size,
        "user_agent": user_agent,
    }


def _parse_sqb_line(lineno: int, line: str) -> dict | None:
    m = LOG_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    try:
        status = int(d["status"])
        size = int(d["bytes"])
    except ValueError:
        return None
    return {
        "lineno":     lineno,
        "timestamp":  d["ts"],
        "ip":         d["ip"],
        "method":     d["method"],
        "url_full":   d["url"],
        "status":     status,
        "bytes":      size,
        "user_agent": d["ua"].strip(),
    }


def parse_log(path: str | Path, errors_path: str | Path | None = None) -> pd.DataFrame:
    """
    Log faylni o'qib, boyitilgan DataFrame qaytaradi.
    SQB custom va Nginx combined formatlarini avtomatik aniqlaydi.

    Qo'shimcha ustunlar:
      - url_path, url_query, url_decoded
      - is_sensitive, is_admin, is_transaction, is_exfil_target, is_deep_admin
      - is_login, is_failed_login, is_success_login
      - is_bot_ua, is_tor_ua
      - hour_local, is_off_hours
      - sqli_match
    """
    rows = []
    bad_rows: list[tuple[int, str]] = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip() or line.startswith("#"):
                continue
            if _NGINX_DETECT_RE.match(line):
                record = _parse_nginx_line(lineno, line)
            else:
                record = _parse_sqb_line(lineno, line)
            if record is None:
                bad_rows.append((lineno, line))
                continue
            rows.append(record)

    df = pd.DataFrame(rows)
    if df.empty:
        return _empty_df()

    df = _enrich(df)

    if errors_path and bad_rows:
        with open(errors_path, "w", encoding="utf-8") as f:
            for ln, raw in bad_rows:
                f.write(f"{ln}\t{raw}\n")

    return df


def _enrich(df: pd.DataFrame) -> pd.DataFrame:
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp"]).copy()
    df["timestamp_local"] = df["timestamp"] + pd.Timedelta(hours=P_THR.LOCAL_TZ_OFFSET_HOURS)

    parts = df["url_full"].apply(_split_url)
    df["url_path"]    = parts.str[0]
    df["url_query"]   = parts.str[1]
    df["url_decoded"] = df["url_full"].apply(_safe_unquote)

    df["is_sensitive"]    = df["url_path"].apply(_match_prefix(get_merged("sensitive_prefixes")))
    df["is_admin"]        = df["url_path"].apply(_match_prefix(get_merged("admin_endpoints")))
    df["is_deep_admin"]   = df["url_path"].apply(
        lambda p: any(p == d or p.startswith(d + "/") for d in P_THR.ADMIN_RECON_DEEP_PATHS)
        if isinstance(p, str) else False
    )
    df["is_transaction"]  = df["url_path"].apply(_match_prefix(get_merged("transaction")))
    df["is_exfil_target"] = df["url_path"].apply(_match_prefix(get_merged("exfil_targets")))

    df["is_login"]         = (df["method"] == "POST") & df["url_path"].isin(set(get_merged("login_paths")))
    df["is_failed_login"]  = df["is_login"] & df["status"].isin([401, 403, 400])
    df["is_success_login"] = df["is_login"] & (df["status"] == 200)

    df["is_bot_ua"] = df["user_agent"].apply(_is_bot_ua)
    df["is_tor_ua"] = df["user_agent"].str.match(P_PATTERNS.TOR_UA_PATTERN, na=False)

    df["hour_local"]   = df["timestamp_local"].dt.hour
    df["is_off_hours"] = (df["hour_local"] >= P_THR.OFF_HOURS_START) | (df["hour_local"] < P_THR.OFF_HOURS_END)

    sqli_combined = "|".join(f"(?:{p})" for p in P_PATTERNS.SQLI_PATTERNS)
    sqli_re = re.compile(sqli_combined, re.IGNORECASE)
    decoded_lower = df["url_decoded"].str.lower()
    raw_lower     = df["url_full"].str.lower()
    df["sqli_match"] = decoded_lower.str.contains(sqli_re, na=False) | \
                       raw_lower.str.contains(sqli_re, na=False)

    return df.sort_values("timestamp").reset_index(drop=True)


def _split_url(url: str) -> tuple[str, str]:
    if "?" in url:
        path, q = url.split("?", 1)
        return (path, q)
    return (url, "")


def _safe_unquote(url: str) -> str:
    try:
        return urllib.parse.unquote(urllib.parse.unquote(url)).lower()
    except Exception:
        return url.lower()


def _match_prefix(prefixes):
    def fn(path: str) -> bool:
        if not isinstance(path, str):
            return False
        return any(path == p or path.startswith(p + "/") or path.startswith(p + "?")
                   for p in prefixes)
    return fn


def _is_bot_ua(ua: str) -> bool:
    if not isinstance(ua, str):
        return False
    return any(re.search(pat, ua, re.IGNORECASE) for pat in P_PATTERNS.BOT_USER_AGENTS)


def _empty_df() -> pd.DataFrame:
    cols = [
        "lineno", "timestamp", "timestamp_local", "ip", "method",
        "url_full", "url_path", "url_query", "url_decoded",
        "status", "bytes", "user_agent",
        "is_sensitive", "is_admin", "is_deep_admin", "is_transaction", "is_exfil_target",
        "is_login", "is_failed_login", "is_success_login",
        "is_bot_ua", "is_tor_ua", "hour_local", "is_off_hours", "sqli_match",
    ]
    return pd.DataFrame(columns=cols)
