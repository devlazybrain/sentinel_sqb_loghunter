"""
CLI giriş nuqtasi — log faylni tahlil qilib, hisobot yaratadi.

Foydalanish:
    python scripts/run_analysis.py [log_path] [output_dir]

Default:
    log:    data/input/web_attack_logs.txt
    output: data/output/
"""
from __future__ import annotations
import sys
from pathlib import Path

# src/ ni Python path'ga qo'shamiz
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from soc_analyzer.analysis.engine import run_full_analysis
from soc_analyzer.reporting.exporters import full_report


def main() -> int:
    log_path   = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "input" / "web_attack_logs.txt"
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "data" / "output"

    if not log_path.exists():
        print(f"[ERROR] Log fayl topilmadi: {log_path}")
        return 1

    print(f"[1/3] Tahlil: {log_path.name}")
    result = run_full_analysis(log_path)
    print(f"      Parsed: {len(result.df):,} qator | {result.df['ip'].nunique()} IP")

    print(f"[2/3] Aniqlandi: {len(result.sessions)} hujum sessiyasi, "
          f"{len(result.chains)} attack chain")

    print(f"[3/3] Hisobotlar yozilmoqda: {output_dir}")
    paths = full_report(result, output_dir)
    for label, p in paths.items():
        print(f"      {label:8} -> {p}")

    print()
    _print_summary(result)
    return 0


def _print_summary(result):
    sessions = sorted(result.sessions, key=lambda s: -s.score)
    print("=" * 80)
    print(f"TOP HUJUMLAR ({len(sessions)} jami)")
    print("=" * 80)
    print(f"{'Severity':9} {'Type':25} {'IP':18} {'Reqs':>6} {'Bytes':>15} {'Score':>6}")
    print("-" * 80)
    for s in sessions[:15]:
        flag = "[i]" if s.is_internal else "   "
        print(f"{s.severity:9} {s.attack_type:25} {s.ip[:18]:18} {s.request_count:>6} "
              f"{s.total_bytes:>15,} {s.score:>6} {flag}")

    if result.chains:
        print(f"\n{'='*80}\nATTACK CHAINS ({len(result.chains)})\n{'='*80}")
        for c in result.chains[:5]:
            combo = " -> ".join(c["stage_types"])
            crit = " [CRITICAL COMBO!]" if c["critical_combo"] else ""
            print(f"  [{c['max_severity']}] {c['ip']}  ({c['stages_count']} bosqich){crit}")
            print(f"      {combo}")
            print(f"      Davomiyligi: {int(c['total_duration'])}s | "
                  f"Reqs: {c['total_requests']} | Bytes: {c['total_bytes']:,}")

    d = result.damage
    print(f"\n{'='*80}\nIQTISODIY ZARAR (taxminiy)\n{'='*80}")
    print(f"  O'g'irlangan ma'lumot:     {d.get('exfil_mb',0)} MB ({d.get('estimated_records',0):,} yozuv)")
    print(f"  Dark market qiymati:       ${d.get('dark_market_loss_usd',0):,}")
    print(f"  Compliance jarima:         ${d.get('compliance_fine_usd',0):,}")
    print(f"  Reputatsiya zarari:        ${d.get('reputation_loss_usd',0):,}")
    print(f"  Fraud potensiali:          ${d.get('fraud_potential_usd',0):,} "
          f"({d.get('suspicious_transfers',0)} shubhali tranzaksiya)")
    print(f"  JAMI:                      ${d.get('total_loss_usd',0):,}  "
          f"({d.get('total_loss_uzs',0):,} so'm)")


if __name__ == "__main__":
    sys.exit(main())
