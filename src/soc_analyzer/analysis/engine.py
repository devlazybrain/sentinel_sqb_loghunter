"""
Analysis Engine — barcha detector va tahlil bosqichlarini birga ishga tushiradi.

Pipeline:
    DataFrame -> Detectors -> IP Reputation -> Enrichment (GeoIP+Tor) -> Attack Chain -> Economics
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import pandas as pd

from soc_analyzer.core.models import AttackSession, IpReputation
from soc_analyzer.core.parser import parse_log
from soc_analyzer.detectors import ALL_DETECTORS
from soc_analyzer.enrichment import enrich_all
from .reputation import compute_ip_reputation
from .attack_chain import detect_attack_chains
from .economics import estimate_damage
from .baseline import compute_baseline


@dataclass
class AnalysisResult:
    df: pd.DataFrame
    sessions: list[AttackSession] = field(default_factory=list)
    reputation: dict[str, IpReputation] = field(default_factory=dict)
    chains: list[dict] = field(default_factory=list)
    damage: dict = field(default_factory=dict)
    baseline: dict = field(default_factory=dict)


class AnalysisEngine:
    """Yagona giriş nuqtasi — barcha detektorlarni boshqaradi."""

    def __init__(self, detectors=None):
        self.detectors = detectors if detectors is not None else ALL_DETECTORS

    def analyze(self, df: pd.DataFrame) -> AnalysisResult:
        sessions: list[AttackSession] = []
        for det in self.detectors:
            sessions.extend(det.detect(df))

        reputation = compute_ip_reputation(df)

        # Severity'ni IP reputation orqali boyitamiz
        for s in sessions:
            first_ip = s.ip.split(",")[0].strip()
            rep = reputation.get(first_ip)
            if rep:
                s.score = rep.score
                s.severity = rep.severity

        # GeoIP mamlakat + Tor exit node boyitish
        enrich_all(sessions)

        chains = detect_attack_chains(sessions)
        damage = estimate_damage(sessions, df)
        baseline = compute_baseline(df, reputation)

        return AnalysisResult(
            df=df,
            sessions=sessions,
            reputation=reputation,
            chains=chains,
            damage=damage,
            baseline=baseline,
        )


def run_full_analysis(log_path: str | Path) -> AnalysisResult:
    """Convenience funksiya — log fayldan to'g'ridan-to'g'ri natijaga."""
    df = parse_log(log_path)
    return AnalysisEngine().analyze(df)
