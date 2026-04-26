"""
Credential Stuffing Detector — 4 qatlamli aniqlash.

L1 (3h burst) — ko'p login qisqa vaqtda
L2 (1d session) — bir kunlik anomal xulq
L3 (long-term) — sekin "low-and-slow" hujum
"""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config import thresholds as T
from soc_analyzer.config.scoring import MITRE_MAPPING
from soc_analyzer.core.models import AttackSession
from soc_analyzer.utils.ip_utils import is_internal_ip
from .base import Detector


class CredentialStuffingDetector(Detector):
    name = "credential_stuffing"
    attack_type = "credential_stuffing"

    def detect(self, df: pd.DataFrame) -> list[AttackSession]:
        sessions: list[AttackSession] = []
        if df.empty:
            return sessions

        login_df = df[df["is_login"]]
        if login_df.empty:
            return sessions

        for ip, g in login_df.groupby("ip"):
            total = len(g)
            failed = int(g["is_failed_login"].sum())
            ratio = failed / total if total else 0.0
            start = g["timestamp"].min()
            end = g["timestamp"].max()
            duration = (end - start).total_seconds()

            burst   = self._burst_hit(g)
            session = total >= T.SESSION_LOGIN_COUNT and ratio >= T.SESSION_FAILURE_RATIO
            slow    = total >= T.WEEKLY_LOGIN_COUNT and ratio >= T.LONGTERM_FAILURE_RATIO
            high_ratio = failed >= 10 and ratio >= 0.6   # qo'shimcha — yuqori failure

            if not (burst or session or slow or high_ratio):
                continue

            layer = ("L1_burst" if burst else
                     "L2_session" if session else
                     "L3_long_term")

            sessions.append(AttackSession(
                attack_type=self.attack_type,
                ip=ip,
                start_time=start,
                end_time=end,
                duration_seconds=duration,
                request_count=total,
                total_bytes=int(g["bytes"].sum()),
                layer=layer,
                is_internal=is_internal_ip(ip),
                mitre_id=MITRE_MAPPING[self.attack_type][0],
                evidence={
                    "failed_logins":      failed,
                    "successful_logins":  int(g["is_success_login"].sum()),
                    "failure_ratio":      round(ratio, 3),
                    "unique_user_agents": int(g["user_agent"].nunique()),
                    "bot_ua_used":        bool(g["is_bot_ua"].any()),
                    "endpoints_targeted": g["url_path"].value_counts().head(5).to_dict(),
                    "sample_payloads":    g["user_agent"].dropna().unique()[:5].tolist(),
                },
            ))
        return sessions

    @staticmethod
    def _burst_hit(g: pd.DataFrame) -> bool:
        if len(g) < T.BURST_LOGIN_COUNT:
            return False
        s = g.set_index("timestamp").sort_index()
        rolling_total  = s["is_login"].astype(int).rolling(T.BURST_WINDOW).sum()
        rolling_failed = s["is_failed_login"].astype(int).rolling(T.BURST_WINDOW).sum()
        if rolling_total.empty:
            return False
        idx = rolling_total.idxmax()
        cnt = rolling_total.loc[idx]
        fail = rolling_failed.loc[idx]
        if cnt < T.BURST_LOGIN_COUNT:
            return False
        return (fail / cnt) >= T.BURST_FAILURE_RATIO
