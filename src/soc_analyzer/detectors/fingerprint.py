"""
Fingerprint Detector — distributed attacker (bir xil xulq, har xil IP).

Hujumchi IP almashtirsa ham, xulq imzosi (UA + endpoint to'plami + ritm)
o'zgarmaydi. Shuni topadi.
"""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config import thresholds as T
from soc_analyzer.config.scoring import MITRE_MAPPING
from soc_analyzer.core.models import AttackSession
from soc_analyzer.utils.ip_utils import is_internal_ip
from soc_analyzer.utils.stats import interval_cv
from .base import Detector


class FingerprintDetector(Detector):
    name = "distributed_fingerprint"
    attack_type = "distributed_fingerprint"

    def detect(self, df: pd.DataFrame) -> list[AttackSession]:
        if df.empty:
            return []

        fp_to_ips: dict[tuple, set] = {}
        fp_to_rows: dict[tuple, list] = {}
        for ip, g in df.groupby("ip"):
            if len(g) < T.FINGERPRINT_MIN_REQUESTS:
                continue
            dom_ua = g["user_agent"].mode().iat[0] if not g["user_agent"].mode().empty else ""
            endpoints = tuple(sorted(g["url_path"].value_counts().head(5).index.tolist()))
            cv = interval_cv(g["timestamp"])
            rate_class = "fast" if (cv is not None and cv < T.FINGERPRINT_IAT_CV) else "normal"
            fp = (dom_ua, endpoints, rate_class)
            fp_to_ips.setdefault(fp, set()).add(ip)
            fp_to_rows.setdefault(fp, []).append(g)

        sessions: list[AttackSession] = []
        for fp, ips in fp_to_ips.items():
            if len(ips) < T.FINGERPRINT_DUPLICATE_IPS:
                continue
            all_rows = pd.concat(fp_to_rows[fp])
            sessions.append(AttackSession(
                attack_type=self.attack_type,
                ip=", ".join(sorted(ips)),
                start_time=all_rows["timestamp"].min(),
                end_time=all_rows["timestamp"].max(),
                duration_seconds=(all_rows["timestamp"].max() - all_rows["timestamp"].min()).total_seconds(),
                request_count=len(all_rows),
                total_bytes=int(all_rows["bytes"].sum()),
                layer="L4_fingerprint",
                is_internal=all(is_internal_ip(ip) for ip in ips),
                mitre_id=MITRE_MAPPING[self.attack_type][0],
                evidence={
                    "shared_ips":        sorted(ips),
                    "ip_count":          len(ips),
                    "dominant_ua":       fp[0],
                    "common_endpoints":  list(fp[1]),
                    "rhythm_class":      fp[2],
                },
            ))
        return sessions
