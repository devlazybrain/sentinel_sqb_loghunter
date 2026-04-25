"""
report.py — Converts attack sessions to DataFrame / CSV and prints CLI summary.

Usage:
  python report.py [log_file]
"""

from __future__ import annotations

import csv
import io
import sys

import pandas as pd


_DISPLAY_COLS = [
    "attack_type",
    "attacker_ip",
    "start_time",
    "end_time",
    "duration_seconds",
    "num_requests",
    "total_bytes",
    "country",
    "via_tor",
    "ip_rotation_detected",
]


def to_dataframe(sessions: list[dict]) -> pd.DataFrame:
    if not sessions:
        return pd.DataFrame(columns=_DISPLAY_COLS)
    rows = []
    for s in sessions:
        rows.append({
            "attack_type":          s["attack_type"],
            "attacker_ip":          s["attacker_ip"],
            "start_time":           s["start_time"].strftime("%Y-%m-%d %H:%M:%S UTC"),
            "end_time":             s["end_time"].strftime("%Y-%m-%d %H:%M:%S UTC"),
            "duration_seconds":     s["duration_seconds"],
            "num_requests":         s["num_requests"],
            "total_bytes":          s["total_bytes"],
            "country":              s.get("country", "Unknown"),
            "via_tor":              s.get("via_tor", False),
            "ip_rotation_detected": s.get("ip_rotation_detected", False),
        })
    return pd.DataFrame(rows, columns=_DISPLAY_COLS)


def to_csv_string(sessions: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_DISPLAY_COLS)
    writer.writeheader()
    for row in to_dataframe(sessions).to_dict("records"):
        writer.writerow(row)
    return buf.getvalue()


def print_summary(sessions: list[dict], chain: str = "") -> None:
    if chain:
        print(chain)
        print()

    if not sessions:
        print("No attacks detected.")
        return

    df = to_dataframe(sessions)
    print("+- DETECTED ATTACK SESSIONS " + "-" * 50)
    for _, row in df.iterrows():
        mb = row["total_bytes"] / (1024 * 1024)
        print(
            f"|  [{row['attack_type']:<35}]  IP: {row['attacker_ip']}\n"
            f"|    Start    : {row['start_time']}\n"
            f"|    End      : {row['end_time']}\n"
            f"|    Duration : {row['duration_seconds']} s\n"
            f"|    Requests : {row['num_requests']}\n"
            f"|    Bytes    : {row['total_bytes']:,}  ({mb:.2f} MB)\n"
            f"|    Country  : {row['country']}\n"
            f"|    Tor      : {row['via_tor']}\n"
            f"|    IPRotate : {row['ip_rotation_detected']}\n"
            f"|"
        )
    print("+" + "-" * 77)


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from parser import parse_file
    from detectors import run_all
    from analyzer import build_attack_sessions, build_attack_chain
    from enrichment import enrich_all

    log_path = sys.argv[1] if len(sys.argv) > 1 else "web_attack_logs.txt"
    print(f"Parsing {log_path} ...")
    df = parse_file(log_path)
    print(f"  {len(df):,} log entries loaded\n")

    raw        = run_all(df)
    sessions   = build_attack_sessions(raw)
    sessions   = enrich_all(sessions)
    chain      = build_attack_chain(sessions)

    print_summary(sessions, chain)

    csv_out = "attack_report.csv"
    with open(csv_out, "w", newline="", encoding="utf-8") as f:
        f.write(to_csv_string(sessions))
    print(f"\nCSV report saved -> {csv_out}")
