"""Hisobot eksport qiluvchilar — CSV, JSON, DataFrame."""
from __future__ import annotations
import json
from pathlib import Path
import pandas as pd

from soc_analyzer.core.models import AttackSession
from soc_analyzer.analysis.engine import AnalysisResult


def sessions_to_dataframe(sessions: list[AttackSession]) -> pd.DataFrame:
    """TZ talablariga mos jadval — 5 ta majburiy ko'rsatkich + qo'shimchalar."""
    rows = []
    for s in sessions:
        rows.append({
            "Hujum turi":        s.attack_type,
            "Severity":          s.severity,
            "Score":             s.score,
            "IP":                s.ip,
            "Mamlakat":          s.country,
            "Tor":               "✓" if s.via_tor else "",
            "IP Rotatsiya":      "✓" if s.ip_rotation_detected else "",
            "Koordinatsiya":     "✓" if s.coordinated else "",
            "Internal":          s.is_internal,
            "Boshlanishi":       s.start_time,
            "Tugashi":           s.end_time,
            "Davomiyligi (sek)": int(s.duration_seconds),
            "Davomiyligi":       s.duration_human,
            "So'rovlar":         s.request_count,
            "Bytes":             s.total_bytes,
            "Layer":             s.layer,
            "MITRE":             s.mitre_id,
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["Score", "Boshlanishi"], ascending=[False, True]).reset_index(drop=True)
    return df


def sessions_to_csv(sessions: list[AttackSession], path: str | Path) -> None:
    df = sessions_to_dataframe(sessions)
    df.to_csv(path, index=False, encoding="utf-8-sig")


def sessions_to_json(sessions: list[AttackSession], path: str | Path) -> None:
    data = [s.to_dict() for s in sessions]
    Path(path).write_text(json.dumps(data, indent=2, default=str, ensure_ascii=False), encoding="utf-8")


def build_chain_narrative(sessions: list[AttackSession]) -> str:
    """
    Barcha sessiyalar uchun o'qiladigan hujum zanjiri matn ko'rinishida.
    Incident report uchun nusxa olish yoki .txt fayl sifatida yuklab olish uchun.
    """
    if not sessions:
        return "Hujum aniqlanmadi."

    ordered = sorted(sessions, key=lambda s: s.start_time)
    lines = []
    for s in ordered:
        time_str  = s.start_time.strftime("%H:%M:%S")
        ip_label  = s.ip
        bytes_mb  = s.total_bytes / (1024 * 1024)
        bytes_str = f" | {bytes_mb:.1f} MB" if bytes_mb >= 1 else ""
        tor_flag  = " [TOR]"         if s.via_tor               else ""
        rot_flag  = " [IP ROTATION]" if s.ip_rotation_detected   else ""
        country   = f" [{s.country}]" if s.country not in ("Unknown", "") else ""
        lines.append(
            f"  [{time_str}] {s.attack_type:<40} | {ip_label:<32}"
            f" | {s.request_count} reqs{bytes_str}{tor_flag}{rot_flag}{country}"
        )

    header = (
        "=" * 70 + "\n"
        "  HUJUM ZANJIRI — SQB Mobile Internet-Banking\n"
        + "=" * 70
    )
    arrow_chain = " -> ".join(
        f"{s.attack_type} ({s.start_time.strftime('%H:%M')})"
        for s in ordered
    )
    return f"{header}\n" + "\n".join(lines) + f"\n\n  Zanjir: {arrow_chain}"


def full_report(result: AnalysisResult, output_dir: str | Path) -> dict:
    """To'liq hisobot to'plamini yozadi: CSV jadval, JSON sessionlar, chains, damage, reputation."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    sessions_to_csv(result.sessions, out / "attacks.csv")
    sessions_to_json(result.sessions, out / "attacks.json")

    # Reputation
    rep_rows = [r.to_dict() for r in sorted(result.reputation.values(), key=lambda x: -x.score)]
    pd.DataFrame(rep_rows).to_csv(out / "ip_reputation.csv", index=False, encoding="utf-8-sig")

    # Chains (JSON + matn zanjiri)
    (out / "attack_chains.json").write_text(
        json.dumps(result.chains, indent=2, default=str, ensure_ascii=False), encoding="utf-8"
    )
    (out / "attack_chain_narrative.txt").write_text(
        build_chain_narrative(result.sessions), encoding="utf-8"
    )

    # Damage
    (out / "economic_damage.json").write_text(
        json.dumps(result.damage, indent=2, default=str, ensure_ascii=False), encoding="utf-8"
    )

    return {
        "csv":       str(out / "attacks.csv"),
        "json":      str(out / "attacks.json"),
        "rep":       str(out / "ip_reputation.csv"),
        "chains":    str(out / "attack_chains.json"),
        "narrative": str(out / "attack_chain_narrative.txt"),
        "damage":    str(out / "economic_damage.json"),
    }
