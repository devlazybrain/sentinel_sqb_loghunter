"""
Severity Reason — IP'ning balli QAYSI signallar tufayli to'plangani.

Foydalanuvchi "nega bu IP KRITIK?" tushunish uchun tushuntirish ro'yxati.
"""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config.scoring import SCORE_WEIGHTS
from soc_analyzer.core.models import IpReputation
from soc_analyzer.utils.stats import interval_cv, request_rate_per_minute


REASON_TEMPLATES = {
    "failed_login": {
        "uz": "{count} ta muvaffaqiyatsiz login (har biri +{w} ball)",
        "ru": "{count} неуспешных попыток входа (по +{w} баллов)",
        "en": "{count} failed logins (+{w} each)",
    },
    "sqli_payload": {
        "uz": "{count} ta SQL injection payload (har biri +{w} ball)",
        "ru": "{count} SQL-инъекций (по +{w} баллов)",
        "en": "{count} SQL injection payloads (+{w} each)",
    },
    "sensitive_api_200": {
        "uz": "{count} ta sezgir API'ga muvaffaqiyatli kirish (har biri +{w})",
        "ru": "{count} успешных запросов к чувствительным API (по +{w})",
        "en": "{count} successful sensitive API requests (+{w} each)",
    },
    "admin_endpoint_hit": {
        "uz": "{count} ta /admin manzilini ziyorat (har biri +{w})",
        "ru": "{count} обращений к /admin (по +{w})",
        "en": "{count} hits to /admin (+{w} each)",
    },
    "deep_admin_hit": {
        "uz": "{count} ta CHUQUR admin manzili (/admin/users, /admin/export, /internal/...) +{w} har biri",
        "ru": "{count} обращений к глубоким admin путям (/admin/users, /admin/export...) по +{w}",
        "en": "{count} deep admin paths (/admin/users, /admin/export...) +{w} each",
    },
    "bot_user_agent": {
        "uz": "Bot/avtomat User-Agent ishlatadi (curl, sqlmap, Postman, python-requests) +{w}",
        "ru": "Использует бот-User-Agent (curl, sqlmap, Postman, python-requests) +{w}",
        "en": "Uses bot User-Agent (curl, sqlmap, Postman, python-requests) +{w}",
    },
    "per_mb_api_traffic": {
        "uz": "{mb} MB sezgir API'dan trafik (har MB uchun +{w})",
        "ru": "{mb} МБ трафика чувствительных API (за каждый МБ +{w})",
        "en": "{mb} MB sensitive API traffic (+{w} per MB)",
    },
    "off_hours_activity": {
        "uz": "{count} ta tunda yoki ish vaqtidan tashqari so'rov (22:00-07:00) +{w} har biri",
        "ru": "{count} запросов в нерабочее время (22:00-07:00) +{w} каждый",
        "en": "{count} off-hours requests (22:00-07:00) +{w} each",
    },
    "high_request_rate": {
        "uz": "Yuqori so'rov tezligi (daqiqasiga >5 ta) +{w}",
        "ru": "Высокая частота запросов (>5/мин) +{w}",
        "en": "High request rate (>5/min) +{w}",
    },
    "regular_interval": {
        "uz": "Bot ritmi — so'rovlar mukammal bir tekis (CV<0.3) +{w}",
        "ru": "Ритм бота — идеально равномерные интервалы (CV<0.3) +{w}",
        "en": "Bot rhythm — perfectly regular intervals (CV<0.3) +{w}",
    },
    "ua_rotation": {
        "uz": "User-Agent tez-tez almashinadi ({count} xil) +{w}",
        "ru": "Часто меняет User-Agent ({count} разных) +{w}",
        "en": "Frequently rotates User-Agent ({count} variants) +{w}",
    },
}


def explain_score(ip: str, df: pd.DataFrame, reputation: IpReputation, lang: str = "uz") -> list[dict]:
    """Berilgan IP'ning balli qayerdan kelganini tushuntiruvchi qatorlar."""
    g = df[df["ip"] == ip]
    if g.empty:
        return []

    reasons = []
    bd = reputation.breakdown

    def add(key: str, count: int = 0, mb: int = 0):
        if key not in bd:
            return
        w = SCORE_WEIGHTS.get(key, 0)
        tmpl = REASON_TEMPLATES.get(key, {}).get(lang, key)
        text = tmpl.format(count=count, w=w, mb=mb)
        reasons.append({"text": text, "points": bd[key]})

    add("failed_login",      count=int(g["is_failed_login"].sum()))
    add("sqli_payload",      count=int(g["sqli_match"].sum()))
    add("sensitive_api_200", count=int(((g["is_sensitive"]) & (g["status"] == 200)).sum()))
    add("admin_endpoint_hit", count=int(g["is_admin"].sum()))
    add("deep_admin_hit",    count=int(g["is_deep_admin"].sum()))

    if "bot_user_agent" in bd:
        reasons.append({
            "text": REASON_TEMPLATES["bot_user_agent"][lang].format(w=SCORE_WEIGHTS["bot_user_agent"]),
            "points": bd["bot_user_agent"]
        })

    api_bytes = int(g[g["is_sensitive"]]["bytes"].sum())
    if "per_mb_api_traffic" in bd:
        mb = api_bytes // 1_000_000
        reasons.append({
            "text": REASON_TEMPLATES["per_mb_api_traffic"][lang].format(
                mb=mb, w=SCORE_WEIGHTS["per_mb_api_traffic"]),
            "points": bd["per_mb_api_traffic"]
        })

    add("off_hours_activity", count=int(g["is_off_hours"].sum()))

    if "high_request_rate" in bd:
        reasons.append({
            "text": REASON_TEMPLATES["high_request_rate"][lang].format(w=SCORE_WEIGHTS["high_request_rate"]),
            "points": bd["high_request_rate"]
        })

    if "regular_interval" in bd:
        cv = interval_cv(g["timestamp"])
        reasons.append({
            "text": REASON_TEMPLATES["regular_interval"][lang].format(w=SCORE_WEIGHTS["regular_interval"]),
            "points": bd["regular_interval"]
        })

    if "ua_rotation" in bd:
        reasons.append({
            "text": REASON_TEMPLATES["ua_rotation"][lang].format(
                count=g["user_agent"].nunique(), w=SCORE_WEIGHTS["ua_rotation"]),
            "points": bd["ua_rotation"]
        })

    return sorted(reasons, key=lambda r: -r["points"])
