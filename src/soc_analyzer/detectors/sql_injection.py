"""SQL Injection Detector — payload-asosli sessionlash."""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config import thresholds as T
from soc_analyzer.config.scoring import MITRE_MAPPING
from soc_analyzer.core.models import AttackSession
from soc_analyzer.utils.ip_utils import is_internal_ip
from .base import Detector


class SqlInjectionDetector(Detector):
    name = "sql_injection"
    attack_type = "sql_injection"

    def detect(self, df: pd.DataFrame) -> list[AttackSession]:
        sessions: list[AttackSession] = []
        if df.empty:
            return sessions

        sqli_df = df[df["sqli_match"]]
        if sqli_df.empty:
            return sessions

        for ip, g in sqli_df.groupby("ip"):
            if len(g) < T.SQLI_MIN_PAYLOADS:
                continue
            start = g["timestamp"].min()
            end = g["timestamp"].max()
            duration = (end - start).total_seconds()

            sample_payloads = g["url_query"].dropna().head(5).tolist()
            targeted = g["url_path"].value_counts().to_dict()
            successful = int((g["status"] == 200).sum())

            sessions.append(AttackSession(
                attack_type=self.attack_type,
                ip=ip,
                start_time=start,
                end_time=end,
                duration_seconds=duration,
                request_count=len(g),
                total_bytes=int(g["bytes"].sum()),
                layer="L1_burst" if duration < 600 else "L3_long_term",
                is_internal=is_internal_ip(ip),
                mitre_id=MITRE_MAPPING[self.attack_type][0],
                evidence={
                    "payload_count":         len(g),
                    "successful_responses":  successful,
                    "endpoints_targeted":    targeted,
                    "sample_payloads":       sample_payloads,
                    "user_agents":           g["user_agent"].unique().tolist()[:5],
                    "uses_sqlmap":           bool(g["user_agent"].str.contains("sqlmap", case=False, na=False).any()),
                },
            ))
        return sessions
