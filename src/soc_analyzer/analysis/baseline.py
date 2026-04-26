"""
Baseline Analyzer — oddiy foydalanuvchi xulq profili.

"Normal user" = HIGH/CRITICAL severity'ga tushmagan IP'lar.
"Attacker"    = HIGH yoki CRITICAL severity bilan IP'lar.

Statistika tab'i shu profilni hujumchi bilan taqqoslab ko'rsatadi.
"""
from __future__ import annotations
import pandas as pd

from soc_analyzer.core.models import IpReputation
from soc_analyzer.utils.stats import request_rate_per_minute


def compute_baseline(df: pd.DataFrame, reputation: dict[str, IpReputation]) -> dict:
    """Oddiy foydalanuvchi vs hujumchi profili."""
    if df.empty:
        return _empty()

    attacker_ips = {ip for ip, r in reputation.items() if r.severity in ("CRITICAL", "HIGH")}
    normal_ips = set(df["ip"].unique()) - attacker_ips

    normal_df   = df[df["ip"].isin(normal_ips)] if normal_ips else df.iloc[0:0]
    attacker_df = df[df["ip"].isin(attacker_ips)] if attacker_ips else df.iloc[0:0]

    return {
        "normal":   _profile(normal_df),
        "attacker": _profile(attacker_df),
        "normal_ip_count":   len(normal_ips),
        "attacker_ip_count": len(attacker_ips),
        "normal_ips":   sorted(normal_ips),
        "attacker_ips": sorted(attacker_ips),
    }


def _profile(df: pd.DataFrame) -> dict:
    if df.empty:
        return _empty_profile()

    # Sessiya davomiyligi: bitta IP'ning birinchi va oxirgi so'rovi
    durations = df.groupby("ip")["timestamp"].agg(lambda s: (s.max() - s.min()).total_seconds())
    avg_session = float(durations.mean()) if len(durations) else 0

    # Soatlik tarqatma
    hourly = df.groupby("hour_local").size().to_dict()

    # Top endpoint
    top_endpoints = df["url_path"].value_counts().head(10).to_dict()

    # O'rtacha so'rov tezligi (daqiqasiga, har IP)
    rates = []
    for _, g in df.groupby("ip"):
        r = request_rate_per_minute(g["timestamp"])
        if r > 0:
            rates.append(r)
    avg_rate = float(sum(rates) / len(rates)) if rates else 0

    # O'rtacha yuklash hajmi (har IP)
    bytes_per_ip = df.groupby("ip")["bytes"].sum()
    avg_bytes = float(bytes_per_ip.mean()) if len(bytes_per_ip) else 0

    # Top User-Agent
    top_ua = df["user_agent"].value_counts().head(5).to_dict()

    # Faol soatlar — eng yuqori yuklamali 3 ta soat
    if hourly:
        sorted_hours = sorted(hourly.items(), key=lambda x: -x[1])[:3]
        peak_hours = [h for h, _ in sorted_hours]
    else:
        peak_hours = []

    return {
        "avg_session_duration":  avg_session,
        "hourly_distribution":   hourly,
        "peak_hours":            peak_hours,
        "top_endpoints":         top_endpoints,
        "avg_request_rate":      avg_rate,
        "avg_bytes_per_ip":      avg_bytes,
        "top_user_agents":       top_ua,
        "total_requests":        len(df),
        "unique_ips":            int(df["ip"].nunique()),
    }


def _empty_profile() -> dict:
    return {
        "avg_session_duration": 0,
        "hourly_distribution": {},
        "peak_hours": [],
        "top_endpoints": {},
        "avg_request_rate": 0,
        "avg_bytes_per_ip": 0,
        "top_user_agents": {},
        "total_requests": 0,
        "unique_ips": 0,
    }


def _empty() -> dict:
    return {
        "normal":            _empty_profile(),
        "attacker":          _empty_profile(),
        "normal_ip_count":   0,
        "attacker_ip_count": 0,
        "normal_ips":        [],
        "attacker_ips":      [],
    }
