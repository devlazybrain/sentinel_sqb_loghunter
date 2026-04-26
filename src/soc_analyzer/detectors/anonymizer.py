"""
Anonymizer / Proxy Detector — bot UA + xulq asosida.

Faqat log fayl maydonlaridan foydalanadi (tashqi DB yo'q).
"""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config import thresholds as T
from soc_analyzer.config.scoring import MITRE_MAPPING
from soc_analyzer.core.models import AttackSession
from soc_analyzer.utils.ip_utils import is_internal_ip
from soc_analyzer.utils.stats import interval_cv
from .base import Detector


class AnonymizerDetector(Detector):
    name = "anonymizer"
    attack_type = "anonymizer"

    def detect(self, df: pd.DataFrame) -> list[AttackSession]:
        sessions: list[AttackSession] = []
        if df.empty:
            return sessions

        for ip, g in df.groupby("ip"):
            total = len(g)
            if total < T.ANONYMIZER_MIN_REQUESTS:
                continue

            bot_count = int(g["is_bot_ua"].sum())
            tor_count = int(g["is_tor_ua"].sum())
            unique_uas = int(g["user_agent"].nunique())
            bot_ratio = bot_count / total if total else 0

            cv = interval_cv(g["timestamp"])
            bot_rhythm = (cv is not None) and (cv < T.FINGERPRINT_IAT_CV) and (total >= 20)

            high_bot       = bot_ratio >= T.ANONYMIZER_MIN_BOT_RATIO
            tor            = tor_count > 0
            ua_rotation    = unique_uas >= T.ANONYMIZER_UA_ROTATION_MIN

            if not (high_bot or tor or ua_rotation or bot_rhythm):
                continue

            signals = []
            if high_bot:    signals.append(f"bot_ua_ratio={bot_ratio:.0%}({bot_count})")
            if tor:         signals.append(f"tor_ua({tor_count})")
            if ua_rotation: signals.append(f"ua_rotation({unique_uas})")
            if bot_rhythm:  signals.append(f"regular_interval(CV={cv:.2f})")

            sessions.append(AttackSession(
                attack_type=self.attack_type,
                ip=ip,
                start_time=g["timestamp"].min(),
                end_time=g["timestamp"].max(),
                duration_seconds=(g["timestamp"].max() - g["timestamp"].min()).total_seconds(),
                request_count=total,
                total_bytes=int(g["bytes"].sum()),
                layer="L4_fingerprint",
                is_internal=is_internal_ip(ip),
                mitre_id=MITRE_MAPPING[self.attack_type][0],
                evidence={
                    "signals":            signals,
                    "bot_ua_count":       bot_count,
                    "bot_ratio":          round(bot_ratio, 3),
                    "tor_ua_count":       tor_count,
                    "unique_user_agents": unique_uas,
                    "interval_cv":        round(cv, 3) if cv else None,
                    "user_agents":        g["user_agent"].value_counts().head(3).to_dict(),
                    "endpoints_targeted": g["url_path"].value_counts().head(5).to_dict(),
                },
            ))
        return sessions
