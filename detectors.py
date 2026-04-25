"""
detectors.py — Attack detection logic for SQB LogHunter.

Four detectors:
  1. detect_credential_stuffing      — per-IP login burst (401/403)
  2. detect_distributed_cs           — multi-IP coordinated login burst
  3. detect_sql_injection            — SQLi patterns in URL + sqlmap UA
  4. detect_data_exfiltration        — large-response export/download requests
"""

from __future__ import annotations

import re
from urllib.parse import unquote
from datetime import timedelta

import pandas as pd

# ── Tunable thresholds (exposed for SOC review) ─────────────────────────────
CS_FAIL_STATUSES        = {401, 403}
CS_PER_IP_WINDOW_SEC    = 60
CS_PER_IP_THRESHOLD     = 10       # failed logins per IP per 60 s
CS_DIST_WINDOW_SEC      = 300      # 5-min window for distributed check
CS_DIST_TOTAL_THRESHOLD = 15       # total failed logins across all IPs in window
CS_DIST_UNIQUE_IP_MIN   = 4        # OR flag if this many distinct IPs hit /login in window
CS_DIST_UA_MIN_IPS      = 2        # min IPs sharing same UA to flag coordinated

SQLI_MIN_REQUESTS       = 3        # min SQLi-pattern hits per IP to flag
SQLI_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s*'",
    r"--(?:\s|$)",
    r"drop\s+table",
    r"insert\s+into",
    r"exec\s*\(",
    r"cast\s*\(",
    r"benchmark\s*\(",
    r"sleep\s*\(",
    r"select\s+.+\s+from",
    r"load_file\s*\(",
    r"outfile\s+",
]

EXFIL_MIN_BYTES         = 50_000      # 50 KB response to qualify (paginated exports are ~50–250 KB per page)
EXFIL_WINDOW_SEC        = 300         # 5-min rolling window
EXFIL_MIN_REQUESTS      = 3           # hits in window to flag
EXFIL_ENDPOINTS         = r"/(?:export|download|backup|dump|extract|report|list)"

INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.", "127.")


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)


def _sqli_match(url: str, user_agent: str) -> bool:
    if "sqlmap" in user_agent.lower():
        return True
    decoded = unquote(unquote(url)).lower()  # double-decode for %2527 etc.
    for pat in SQLI_PATTERNS:
        if re.search(pat, decoded, re.IGNORECASE):
            return True
    return False


# ── 1. Per-IP Credential Stuffing ────────────────────────────────────────────

def detect_credential_stuffing(df: pd.DataFrame) -> list[dict]:
    mask = (
        (df["method"] == "POST") &
        (df["url"].str.contains("/login", case=False, na=False)) &
        (df["status"].isin(CS_FAIL_STATUSES))
    )
    login_fails = df[mask].copy()
    if login_fails.empty:
        return []

    # Tumbling 60-second buckets
    login_fails["bucket"] = login_fails["timestamp"].dt.floor(
        f"{CS_PER_IP_WINDOW_SEC}s"
    )
    bucket_counts = (
        login_fails.groupby(["ip", "bucket"])
        .size()
        .reset_index(name="count")
    )
    flagged_ips = set(
        bucket_counts.loc[
            bucket_counts["count"] >= CS_PER_IP_THRESHOLD, "ip"
        ]
    )

    # All POST /login requests (includes 200 successes during the attack window)
    all_login_mask = (
        (df["method"] == "POST") &
        (df["url"].str.contains("/login", case=False, na=False))
    )
    all_login = df[all_login_mask]

    results = []
    for ip in flagged_ips:
        if _is_internal(ip):
            continue
        fail_rows = login_fails[login_fails["ip"] == ip]
        all_rows  = all_login[all_login["ip"] == ip]
        results.append({
            "attack_type":   "Credential Stuffing",
            "attacker_ip":   ip,
            "start_time":    all_rows["timestamp"].min(),
            "end_time":      all_rows["timestamp"].max(),
            "num_requests":  len(all_rows),
            "total_bytes":   int(all_rows["bytes"].sum()),
            "coordinated":   False,
            "shared_user_agent": None,
            "ip_rotation_detected": False,
            "involved_ips":  [ip],
            "sample_payloads": [
                f"{r['url']} -> {r['status']}"
                for _, r in all_rows.head(5).iterrows()
            ],
        })
    return results


# ── 2. Distributed / Multi-IP Credential Stuffing ────────────────────────────

def detect_distributed_cs(df: pd.DataFrame) -> list[dict]:
    """Detect coordinated login bursts spread across multiple IPs (VPN rotation)."""
    mask = (
        (df["method"] == "POST") &
        (df["url"].str.contains("/login", case=False, na=False)) &
        (df["status"].isin(CS_FAIL_STATUSES))
    )
    login_fails = df[mask].copy()
    if login_fails.empty:
        return []

    login_fails["bucket"] = login_fails["timestamp"].dt.floor(
        f"{CS_DIST_WINDOW_SEC}s"
    )
    bucket_stats = (
        login_fails[~login_fails["ip"].apply(_is_internal)]
        .groupby("bucket")
        .agg(
            total=("ip", "count"),
            unique_ips=("ip", "nunique"),
            ips=("ip", lambda x: list(x.unique())),
        )
        .reset_index()
    )
    flagged_buckets = bucket_stats[
        (bucket_stats["unique_ips"] >= 2) &  # must involve multiple IPs to be "distributed"
        (
            (bucket_stats["total"] >= CS_DIST_TOTAL_THRESHOLD) |
            (bucket_stats["unique_ips"] >= CS_DIST_UNIQUE_IP_MIN)
        )
    ]
    if flagged_buckets.empty:
        return []

    # UA clustering: find shared user-agent across those IPs
    results = []
    for _, row in flagged_buckets.iterrows():
        window_start = row["bucket"]
        window_end   = window_start + timedelta(seconds=CS_DIST_WINDOW_SEC)
        window_rows  = login_fails[
            (login_fails["timestamp"] >= window_start) &
            (login_fails["timestamp"] < window_end) &
            (~login_fails["ip"].apply(_is_internal))
        ]
        # Check shared user-agent fingerprint
        ua_ip_counts = (
            window_rows.groupby("user_agent")["ip"]
            .nunique()
        )
        shared_ua = None
        coordinated = False
        if (ua_ip_counts >= CS_DIST_UA_MIN_IPS).any():
            shared_ua   = ua_ip_counts.idxmax()
            coordinated = True

        results.append({
            "attack_type":   "Distributed Credential Stuffing",
            "attacker_ip":   ", ".join(sorted(set(row["ips"]))),
            "start_time":    window_start,
            "end_time":      window_end,
            "num_requests":  int(row["total"]),
            "total_bytes":   int(window_rows["bytes"].sum()),
            "coordinated":   coordinated,
            "shared_user_agent": shared_ua,
            "ip_rotation_detected": True,
            "involved_ips":  row["ips"],
        })
    return results


# ── 3. SQL Injection ──────────────────────────────────────────────────────────

def detect_sql_injection(df: pd.DataFrame) -> list[dict]:
    sqli_mask = df.apply(
        lambda r: _sqli_match(r["url"], r["user_agent"]), axis=1
    )
    sqli_rows = df[sqli_mask].copy()
    if sqli_rows.empty:
        return []

    results = []
    for ip, group in sqli_rows.groupby("ip"):
        if _is_internal(ip):
            continue
        if len(group) < SQLI_MIN_REQUESTS:
            continue
        sample_urls = group["url"].head(5).tolist()
        results.append({
            "attack_type":   "SQL Injection",
            "attacker_ip":   ip,
            "start_time":    group["timestamp"].min(),
            "end_time":      group["timestamp"].max(),
            "num_requests":  len(group),
            "total_bytes":   int(group["bytes"].sum()),
            "coordinated":   False,
            "shared_user_agent": None,
            "ip_rotation_detected": False,
            "involved_ips":  [ip],
            "sample_payloads": sample_urls,
        })
    return results


# ── 4. Data Exfiltration ──────────────────────────────────────────────────────

def detect_data_exfiltration(df: pd.DataFrame) -> list[dict]:
    mask = (
        (df["status"] == 200) &
        (df["bytes"] >= EXFIL_MIN_BYTES) &
        (df["url"].str.contains(EXFIL_ENDPOINTS, na=False))
    )
    exfil_rows = df[mask].copy()
    if exfil_rows.empty:
        return []

    results = []
    for ip, group in exfil_rows.groupby("ip"):
        if _is_internal(ip):
            continue
        group = group.sort_values("timestamp").reset_index(drop=True)

        # Rolling 5-minute window: find any sub-window with >= threshold requests
        flagged = False
        for i in range(len(group)):
            t0 = group.loc[i, "timestamp"]
            window = group[
                group["timestamp"] <= t0 + timedelta(seconds=EXFIL_WINDOW_SEC)
            ]
            if len(window) >= EXFIL_MIN_REQUESTS:
                flagged = True
                break

        if not flagged:
            continue

        results.append({
            "attack_type":   "Data Exfiltration",
            "attacker_ip":   ip,
            "start_time":    group["timestamp"].min(),
            "end_time":      group["timestamp"].max(),
            "num_requests":  len(group),
            "total_bytes":   int(group["bytes"].sum()),
            "coordinated":   False,
            "shared_user_agent": None,
            "ip_rotation_detected": False,
            "involved_ips":  [ip],
        })
    return results


# ── Run all detectors ─────────────────────────────────────────────────────────

def run_all(df: pd.DataFrame) -> list[dict]:
    results = []
    results += detect_credential_stuffing(df)
    results += detect_distributed_cs(df)
    results += detect_sql_injection(df)
    results += detect_data_exfiltration(df)
    return results
