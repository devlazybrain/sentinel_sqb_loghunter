"""
Attack Chain Detector — ikki xil zanjir turi:

1. Single-IP chain: bitta IP bir necha bosqichli hujum (Recon -> SQLi -> Exfil)
2. Multi-IP campaign: vaqt bo'yicha ketma-ket turli IP'lardan koordinatsiyali hujum
   (CS -> SQLi -> Exfil, har biri boshqa IP, lekin vaqt oralig'i < MAX_CAMPAIGN_GAP_SEC)

TZ baholash mezoni: 20 ball.
"""
from __future__ import annotations
from collections import defaultdict

from soc_analyzer.core.models import AttackSession

# Kampaniyada ikki bosqich orasidagi maksimal vaqt oralig'i (3 soat)
MAX_CAMPAIGN_GAP_SEC = 3 * 3600

# Ketma-ket hujum turlari — bu tartibda kelsalar kampaniya hisoblanadi
CAMPAIGN_SEQUENCES = [
    ["credential_stuffing", "sql_injection", "data_exfiltration"],
    ["credential_stuffing", "data_exfiltration"],
    ["sql_injection", "data_exfiltration"],
    ["admin_recon", "credential_stuffing", "data_exfiltration"],
    ["admin_recon", "sql_injection", "data_exfiltration"],
    ["credential_stuffing", "sql_injection"],
]


def detect_attack_chains(sessions: list[AttackSession]) -> list[dict]:
    chains = []
    chains.extend(_detect_single_ip_chains(sessions))
    chains.extend(_detect_multi_ip_campaigns(sessions))
    return sorted(chains, key=lambda c: (-_severity_rank(c["max_severity"]), -c["stages_count"]))


def _detect_single_ip_chains(sessions: list[AttackSession]) -> list[dict]:
    """Bitta IP'dan 2+ xil hujum turi — klassik chain."""
    by_ip: dict[str, list[AttackSession]] = defaultdict(list)
    for s in sessions:
        if "," in s.ip:
            continue
        by_ip[s.ip].append(s)

    chains = []
    for ip, evs in by_ip.items():
        types = sorted({e.attack_type for e in evs})
        if len(types) < 2:
            continue

        ordered = sorted(evs, key=lambda e: e.start_time)
        max_severity = max(evs, key=lambda e: _severity_rank(e.severity)).severity

        chains.append({
            "chain_type":     "single_ip",
            "ip":             ip,
            "stages_count":   len(types),
            "stage_types":    types,
            "is_internal":    ordered[0].is_internal,
            "first_seen":     ordered[0].start_time,
            "last_seen":      ordered[-1].end_time,
            "total_duration": (ordered[-1].end_time - ordered[0].start_time).total_seconds(),
            "total_requests": sum(e.request_count for e in evs),
            "total_bytes":    sum(e.total_bytes for e in evs),
            "max_severity":   max_severity,
            "critical_combo": _is_critical_combo(types),
            "steps":          _build_steps(ordered),
        })
    return chains


def _detect_multi_ip_campaigns(sessions: list[AttackSession]) -> list[dict]:
    """
    Turli IP'lardan ketma-ket kelgan hujumlar — kampaniya.
    Har bir bosqich boshqasidan MAX_CAMPAIGN_GAP_SEC ichida boshlanadi.
    """
    single_ip = [s for s in sessions if "," not in s.ip]
    if not single_ip:
        return []

    by_type: dict[str, list[AttackSession]] = defaultdict(list)
    for s in single_ip:
        by_type[s.attack_type].append(s)

    found_campaigns = []
    seen_keys: set[tuple] = set()

    for seq in CAMPAIGN_SEQUENCES:
        if not all(t in by_type for t in seq):
            continue

        stage_lists = [sorted(by_type[t], key=lambda s: s.start_time) for t in seq]

        for first_sess in stage_lists[0]:
            chain_sessions = [first_sess]
            prev_end = first_sess.end_time

            for stage_idx in range(1, len(seq)):
                found = None
                for cand in stage_lists[stage_idx]:
                    gap = (cand.start_time - prev_end).total_seconds()
                    if 0 <= gap <= MAX_CAMPAIGN_GAP_SEC:
                        found = cand
                        break
                if found is None:
                    break
                chain_sessions.append(found)
                prev_end = found.end_time

            if len(chain_sessions) < len(seq):
                continue

            key = tuple(id(s) for s in chain_sessions)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            ordered = sorted(chain_sessions, key=lambda s: s.start_time)
            ips = [s.ip for s in ordered]
            all_types = [s.attack_type for s in ordered]
            max_severity = max(ordered, key=lambda s: _severity_rank(s.severity)).severity

            found_campaigns.append({
                "chain_type":     "multi_ip_campaign",
                "ip":             " → ".join(ips),
                "stages_count":   len(ordered),
                "stage_types":    all_types,
                "is_internal":    False,
                "first_seen":     ordered[0].start_time,
                "last_seen":      ordered[-1].end_time,
                "total_duration": (ordered[-1].end_time - ordered[0].start_time).total_seconds(),
                "total_requests": sum(s.request_count for s in ordered),
                "total_bytes":    sum(s.total_bytes for s in ordered),
                "max_severity":   max_severity,
                "critical_combo": True,
                "steps":          _build_steps(ordered),
            })

    return found_campaigns


def _build_steps(ordered: list[AttackSession]) -> list[dict]:
    return [
        {
            "stage":    s.attack_type,
            "ip":       s.ip,
            "start":    s.start_time,
            "end":      s.end_time,
            "duration": s.duration_seconds,
            "requests": s.request_count,
            "bytes":    s.total_bytes,
            "mitre":    s.mitre_id,
        }
        for s in ordered
    ]


def _is_critical_combo(types: list[str]) -> bool:
    t = set(types)
    return (
        ("sql_injection" in t and "data_exfiltration" in t) or
        ("credential_stuffing" in t and "data_exfiltration" in t) or
        ("admin_recon" in t and "data_exfiltration" in t)
    )


def _severity_rank(s: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0)
