"""IP Reputation — kumulyativ shubha balli har bir IP uchun."""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config import thresholds as T
from soc_analyzer.config.scoring import SCORE_WEIGHTS, classify_severity
from soc_analyzer.core.models import IpReputation
from soc_analyzer.utils.ip_utils import is_internal_ip
from soc_analyzer.utils.stats import interval_cv, request_rate_per_minute


def compute_ip_reputation(df: pd.DataFrame) -> dict[str, IpReputation]:
    if df.empty:
        return {}

    out: dict[str, IpReputation] = {}
    for ip, g in df.groupby("ip"):
        score = 0
        breakdown: dict[str, int] = {}

        # Failed login
        failed = int(g["is_failed_login"].sum())
        if failed:
            v = failed * SCORE_WEIGHTS["failed_login"]
            score += v; breakdown["failed_login"] = v

        # SQLi payload
        sqli_n = int(g["sqli_match"].sum())
        if sqli_n:
            v = sqli_n * SCORE_WEIGHTS["sqli_payload"]
            score += v; breakdown["sqli_payload"] = v

        # Sezgir API'ga muvaffaqiyatli kirish
        sens200 = int(((g["is_sensitive"]) & (g["status"] == 200)).sum())
        if sens200:
            v = sens200 * SCORE_WEIGHTS["sensitive_api_200"]
            score += v; breakdown["sensitive_api_200"] = v

        # Admin endpoint hits (oddiy)
        admin_n = int(g["is_admin"].sum())
        if admin_n:
            v = admin_n * SCORE_WEIGHTS["admin_endpoint_hit"]
            score += v; breakdown["admin_endpoint_hit"] = v

        # Chuqur admin (eng yomon)
        deep_n = int(g["is_deep_admin"].sum())
        if deep_n:
            v = deep_n * SCORE_WEIGHTS["deep_admin_hit"]
            score += v; breakdown["deep_admin_hit"] = v

        # Bot UA — bir martalik bonus
        if bool(g["is_bot_ua"].any()):
            v = SCORE_WEIGHTS["bot_user_agent"]
            score += v; breakdown["bot_user_agent"] = v

        # API trafik (per MB)
        api_bytes = int(g[g["is_sensitive"]]["bytes"].sum())
        if api_bytes >= 1_000_000:
            v = (api_bytes // 1_000_000) * SCORE_WEIGHTS["per_mb_api_traffic"]
            score += v; breakdown["per_mb_api_traffic"] = v

        # Off-hours
        off_n = int(g["is_off_hours"].sum())
        if off_n:
            v = off_n * SCORE_WEIGHTS["off_hours_activity"]
            score += v; breakdown["off_hours_activity"] = v

        # Bot ritmi
        cv = interval_cv(g["timestamp"])
        if cv is not None and cv < T.FINGERPRINT_IAT_CV and len(g) >= 20:
            v = SCORE_WEIGHTS["regular_interval"]
            score += v; breakdown["regular_interval"] = v

        # UA rotation
        if g["user_agent"].nunique() >= T.ANONYMIZER_UA_ROTATION_MIN:
            v = SCORE_WEIGHTS["ua_rotation"]
            score += v; breakdown["ua_rotation"] = v

        # Yuqori tezlik
        rate = request_rate_per_minute(g["timestamp"])
        if rate > 5:
            v = SCORE_WEIGHTS["high_request_rate"]
            score += v; breakdown["high_request_rate"] = v

        out[ip] = IpReputation(
            ip=ip,
            score=score,
            severity=classify_severity(score),
            is_internal=is_internal_ip(ip),
            total_requests=len(g),
            breakdown=breakdown,
        )
    return out
