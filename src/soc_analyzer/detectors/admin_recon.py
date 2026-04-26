"""
Admin Recon Detector — oddiy foydalanuvchi kirmaydigan endpoint'lar.

Talab kuchaytirilgan: faqat /admin landing emas, chuqurroq path
(/admin/users, /admin/export, /internal/audit) yoki ko'p hit.
"""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config import thresholds as T
from soc_analyzer.config.scoring import MITRE_MAPPING
from soc_analyzer.core.models import AttackSession
from soc_analyzer.utils.ip_utils import is_internal_ip
from .base import Detector


class AdminReconDetector(Detector):
    name = "admin_recon"
    attack_type = "admin_recon"

    def detect(self, df: pd.DataFrame) -> list[AttackSession]:
        sessions: list[AttackSession] = []
        if df.empty:
            return sessions

        admin_df = df[df["is_admin"]]
        if admin_df.empty:
            return sessions

        for ip, g in admin_df.groupby("ip"):
            deep_hits = int(g["is_deep_admin"].sum())
            total = len(g)
            success = int(g["status"].isin([200, 302, 304]).sum())

            # Faqat /admin'ga 1-2 marta tegish — flag emas. Talablar:
            # 1) ≥5 ta hit, YOKI
            # 2) ≥1 chuqur admin path (/admin/users, /admin/export, /internal/...)
            if not (total >= T.ADMIN_RECON_MIN_HITS or deep_hits >= 1):
                continue

            sessions.append(AttackSession(
                attack_type=self.attack_type,
                ip=ip,
                start_time=g["timestamp"].min(),
                end_time=g["timestamp"].max(),
                duration_seconds=(g["timestamp"].max() - g["timestamp"].min()).total_seconds(),
                request_count=total,
                total_bytes=int(g["bytes"].sum()),
                layer="L2_session",
                is_internal=is_internal_ip(ip),
                mitre_id=MITRE_MAPPING[self.attack_type][0],
                evidence={
                    "admin_endpoints_hit":      g["url_path"].value_counts().to_dict(),
                    "deep_admin_hits":          deep_hits,
                    "successful_admin_access":  success,
                    "user_agents":              g["user_agent"].unique().tolist()[:3],
                },
            ))
        return sessions
