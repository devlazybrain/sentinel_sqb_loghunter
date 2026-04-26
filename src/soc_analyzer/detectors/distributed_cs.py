"""
Distributed Credential Stuffing Detector — ko'p IP koordinatsiyali login burst.

VPN/proxy rotatsiya orqali bir necha IP bir xil User-Agent bilan login qiladi.
LogHunter (sentinel_sqb_loghunter) loyihasidan olingan va asosiy arxitekturaga moslashtirilgan.
"""
from __future__ import annotations
from datetime import timedelta

import pandas as pd

from soc_analyzer.config.scoring import MITRE_MAPPING
from soc_analyzer.core.models import AttackSession
from soc_analyzer.utils.ip_utils import is_internal_ip
from .base import Detector

# Sozlanuvchi praglar
_DIST_WINDOW_SEC      = 300   # 5 daqiqalik oyna
_DIST_TOTAL_THRESHOLD = 15    # oynada jami muvaffaqiyatsiz loginlar soni
_DIST_UNIQUE_IP_MIN   = 4     # yoki shu qadар turli IP'lar
_DIST_UA_MIN_IPS      = 2     # bitta UA'ni ulashadigan minimal IP soni
_FAIL_STATUSES        = {401, 403}


class DistributedCSDetector(Detector):
    name = "distributed_credential_stuffing"
    attack_type = "distributed_credential_stuffing"

    def detect(self, df: pd.DataFrame) -> list[AttackSession]:
        if df.empty:
            return []

        mask = (
            (df["method"] == "POST") &
            df["url_path"].str.contains("/login", case=False, na=False) &
            df["status"].isin(_FAIL_STATUSES)
        )
        login_fails = df[mask].copy()
        if login_fails.empty:
            return []

        # Tashqi IP'lar bilan cheklash
        login_fails = login_fails[~login_fails["ip"].apply(is_internal_ip)]
        if login_fails.empty:
            return []

        # 5 daqiqalik chelaklar bo'yicha guruhlash
        login_fails = login_fails.copy()
        login_fails["bucket"] = login_fails["timestamp"].dt.floor(f"{_DIST_WINDOW_SEC}s")

        bucket_stats = (
            login_fails.groupby("bucket")
            .agg(
                total=("ip", "count"),
                unique_ips=("ip", "nunique"),
                ips=("ip", lambda x: list(x.unique())),
            )
            .reset_index()
        )

        flagged = bucket_stats[
            (bucket_stats["unique_ips"] >= 2) &
            (
                (bucket_stats["total"] >= _DIST_TOTAL_THRESHOLD) |
                (bucket_stats["unique_ips"] >= _DIST_UNIQUE_IP_MIN)
            )
        ]
        if flagged.empty:
            return []

        sessions: list[AttackSession] = []
        for _, row in flagged.iterrows():
            win_start = row["bucket"]
            win_end   = win_start + timedelta(seconds=_DIST_WINDOW_SEC)
            win_rows  = login_fails[
                (login_fails["timestamp"] >= win_start) &
                (login_fails["timestamp"] < win_end)
            ]

            # Ortak User-Agent aniqlash
            ua_ip_counts = win_rows.groupby("user_agent")["ip"].nunique()
            shared_ua: str | None = None
            coordinated = False
            if (ua_ip_counts >= _DIST_UA_MIN_IPS).any():
                shared_ua   = str(ua_ip_counts.idxmax())
                coordinated = True

            involved_ips = list(row["ips"])
            all_ip_str   = ", ".join(sorted(set(involved_ips)))

            # Barcha IP'lar uchun login qatorlarini (muvaffaqiyatli ham) olish
            all_login_mask = (
                (df["method"] == "POST") &
                df["url_path"].str.contains("/login", case=False, na=False) &
                df["ip"].isin(involved_ips) &
                (df["timestamp"] >= win_start) &
                (df["timestamp"] < win_end)
            )
            all_rows = df[all_login_mask]

            duration = (win_end - win_start).total_seconds()
            sessions.append(AttackSession(
                attack_type=self.attack_type,
                ip=all_ip_str,
                start_time=win_start,
                end_time=win_end,
                duration_seconds=duration,
                request_count=int(row["total"]),
                total_bytes=int(win_rows["bytes"].sum()),
                layer="L1_burst",
                is_internal=False,
                mitre_id=MITRE_MAPPING.get("credential_stuffing", ["T1110.004"])[0],
                evidence={
                    "involved_ips":    involved_ips,
                    "unique_ip_count": int(row["unique_ips"]),
                    "coordinated":     coordinated,
                    "shared_user_agent": shared_ua,
                },
                ip_rotation_detected=True,
                coordinated=coordinated,
                shared_user_agent=shared_ua,
            ))

        return sessions
