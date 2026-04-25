"""
analyzer.py — Groups raw detections into clean attack sessions and builds
the attack chain narrative.
"""

from __future__ import annotations

from datetime import timezone


def build_attack_sessions(raw: list[dict]) -> list[dict]:
    """
    Normalize and merge raw detector output into standard session dicts.

    Each session has:
      attack_type, attacker_ip, start_time, end_time,
      duration_seconds, num_requests, total_bytes,
      coordinated, shared_user_agent, ip_rotation_detected, involved_ips
    """
    if not raw:
        return []

    sessions = []
    for det in raw:
        start = det["start_time"]
        end   = det["end_time"]
        # Make datetimes timezone-aware if they aren't already
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        duration = max(int((end - start).total_seconds()), 0)
        sessions.append({
            "attack_type":          det["attack_type"],
            "attacker_ip":          det["attacker_ip"],
            "start_time":           start,
            "end_time":             end,
            "duration_seconds":     duration,
            "num_requests":         det["num_requests"],
            "total_bytes":          det["total_bytes"],
            "coordinated":          det.get("coordinated", False),
            "shared_user_agent":    det.get("shared_user_agent"),
            "ip_rotation_detected": det.get("ip_rotation_detected", False),
            "involved_ips":         det.get("involved_ips", [det["attacker_ip"]]),
            "sample_payloads":      det.get("sample_payloads", []),
        })

    # Merge duplicate sessions: same attack_type + same primary IP → keep one
    # (distributed CS may appear twice if per-IP and distributed both fire)
    merged: list[dict] = []
    seen_keys: set[tuple] = set()
    for s in sorted(sessions, key=lambda x: x["start_time"]):
        key = (s["attack_type"], s["attacker_ip"])
        if key in seen_keys:
            # Extend existing session instead of duplicating
            for m in merged:
                if (m["attack_type"], m["attacker_ip"]) == key:
                    m["start_time"]      = min(m["start_time"], s["start_time"])
                    m["end_time"]        = max(m["end_time"],   s["end_time"])
                    m["num_requests"]   += s["num_requests"]
                    m["total_bytes"]    += s["total_bytes"]
                    m["duration_seconds"] = max(
                        int((m["end_time"] - m["start_time"]).total_seconds()), 0
                    )
                    break
        else:
            seen_keys.add(key)
            merged.append(s)

    return merged


def build_attack_chain(sessions: list[dict]) -> str:
    """
    Return a human-readable attack chain timeline narrative, sorted by start_time.
    Example output:
      [09:00:48] Credential Stuffing        | 185.23.44.12 (+ 3 more IPs) | 120 reqs
      [10:02:00] SQL Injection              | 91.199.12.77                 | 45 reqs
      [10:02:35] Data Exfiltration          | 91.199.12.77                 | 7 reqs | 99 MB
    """
    if not sessions:
        return "No attacks detected."

    ordered = sorted(sessions, key=lambda s: s["start_time"])
    lines = []
    for s in ordered:
        time_str = s["start_time"].strftime("%H:%M:%S")
        ip_label = s["attacker_ip"]
        involved = s.get("involved_ips", [])
        if isinstance(involved, list) and len(involved) > 1:
            ip_label = f"{involved[0]} (+{len(involved)-1} more IPs)"

        bytes_mb = s["total_bytes"] / (1024 * 1024)
        bytes_str = f" | {bytes_mb:.1f} MB" if bytes_mb >= 1 else ""

        rot_flag = " [IP ROTATION]" if s.get("ip_rotation_detected") else ""
        tor_flag = " [TOR]"         if s.get("via_tor")              else ""
        country  = f" [{s['country']}]" if s.get("country") and s["country"] != "Unknown" else ""

        lines.append(
            f"  [{time_str}] {s['attack_type']:<35} | {ip_label:<30}"
            f" | {s['num_requests']} reqs{bytes_str}{rot_flag}{tor_flag}{country}"
        )

    header = (
        "=" * 66 + "\n"
        "  ATTACK CHAIN TIMELINE  --  SQB Mobile Internet-Banking\n"
        + "=" * 66
    )
    arrow_chain = " -> ".join(
        f"{s['attack_type']} ({s['start_time'].strftime('%H:%M')})"
        for s in ordered
    )
    return f"{header}\n" + "\n".join(lines) + f"\n\n  Chain: {arrow_chain}"
