"""
Attack Session va IP Reputation ma'lumot modellari.

Barcha detector'lar AttackSession qaytaradi — bu CSV/JSON/dashboard'ga
oson aylantiriladigan birlashtirilgan format.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


@dataclass
class AttackSession:
    """Bitta hujum sessiyasi — TZ talablari bo'yicha 5 ta majburiy ko'rsatkich."""
    attack_type: str                       # credential_stuffing, sql_injection, etc.
    ip: str
    start_time: datetime                   # TZ: hujum boshlanish vaqti
    end_time: datetime                     # TZ: hujum tugash vaqti
    duration_seconds: float                # TZ: hujum davomiyligi
    request_count: int                     # TZ: hujumchi so'rovlari soni
    total_bytes: int                       # TZ: ko'chirilgan ma'lumot hajmi
    layer: str                             # L1_burst | L2_session | L3_long_term | L4_fingerprint
    is_internal: bool                      # ichki tarmoq IP'simi (variant B paranoid)
    mitre_id: str                          # MITRE ATT&CK Technique ID
    evidence: dict[str, Any] = field(default_factory=dict)
    score: int = 0                         # IP reputation balli
    severity: str = "LOW"                  # LOW/MEDIUM/HIGH/CRITICAL
    # Enrichment maydonlari (GeoIP + Tor + distributed flags)
    country: str = "Unknown"
    via_tor: bool = False
    ip_rotation_detected: bool = False
    coordinated: bool = False
    shared_user_agent: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["start_time"] = self.start_time.isoformat() if hasattr(self.start_time, 'isoformat') else str(self.start_time)
        d["end_time"]   = self.end_time.isoformat() if hasattr(self.end_time, 'isoformat') else str(self.end_time)
        return d

    @property
    def duration_human(self) -> str:
        """1h 23m 45s ko'rinishida o'qiladigan davomiylik."""
        s = int(self.duration_seconds)
        h, rem = divmod(s, 3600)
        m, sec = divmod(rem, 60)
        if h:
            return f"{h}h {m}m {sec}s"
        if m:
            return f"{m}m {sec}s"
        return f"{sec}s"


@dataclass
class IpReputation:
    """IP uchun kumulyativ shubha balli."""
    ip: str
    score: int
    severity: str
    is_internal: bool
    total_requests: int
    breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
