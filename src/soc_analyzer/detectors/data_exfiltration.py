"""Data Exfiltration Detector — bayt-stavka va so'rov soni."""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config import thresholds as T
from soc_analyzer.config.economics import AVG_RECORD_SIZE_BYTES
from soc_analyzer.config.scoring import MITRE_MAPPING
from soc_analyzer.core.models import AttackSession
from soc_analyzer.utils.ip_utils import is_internal_ip
from .base import Detector


class DataExfiltrationDetector(Detector):
    name = "data_exfiltration"
    attack_type = "data_exfiltration"

    def detect(self, df: pd.DataFrame) -> list[AttackSession]:
        sessions: list[AttackSession] = []
        if df.empty:
            return sessions

        exfil_df = df[df["is_exfil_target"] & (df["status"] == 200)]
        if exfil_df.empty:
            return sessions

        for ip, g in exfil_df.groupby("ip"):
            total_bytes = int(g["bytes"].sum())
            count = len(g)
            start = g["timestamp"].min()
            end = g["timestamp"].max()
            duration = (end - start).total_seconds()

            burst   = self._burst_hit(g)
            session = total_bytes >= T.SESSION_EXFIL_BYTES and count >= T.SESSION_EXFIL_COUNT
            weekly  = total_bytes >= T.WEEKLY_EXFIL_BYTES

            if not (burst or session or weekly):
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
                request_count=count,
                total_bytes=total_bytes,
                layer=layer,
                is_internal=is_internal_ip(ip),
                mitre_id=MITRE_MAPPING[self.attack_type][0],
                evidence={
                    "endpoints_targeted":         g["url_path"].value_counts().to_dict(),
                    "max_single_response_bytes":  int(g["bytes"].max()),
                    "avg_response_bytes":         int(g["bytes"].mean()),
                    "estimated_records":          total_bytes // AVG_RECORD_SIZE_BYTES,
                    "sample_payloads":            g["url_full"].head(5).tolist(),
                },
            ))
        return sessions

    @staticmethod
    def _burst_hit(g: pd.DataFrame) -> bool:
        if len(g) < T.BURST_EXFIL_COUNT:
            return False
        s = g.set_index("timestamp").sort_index()
        rolling_bytes = s["bytes"].rolling(T.BURST_WINDOW).sum()
        rolling_count = s["bytes"].rolling(T.BURST_WINDOW).count()
        return bool(((rolling_bytes >= T.BURST_EXFIL_BYTES) &
                     (rolling_count >= T.BURST_EXFIL_COUNT)).any())
