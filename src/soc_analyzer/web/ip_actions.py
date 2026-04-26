"""
IP Actions — Watchlist / Ignore / Block boshqaruvi.

Lokal JSON faylda saqlanadi: data/state/ip_actions.json.
Streamlit qayta yuklanganda ham saqlanib qoladi.
"""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
STATE_DIR = ROOT / "data" / "state"
STATE_FILE = STATE_DIR / "ip_actions.json"

VALID_ACTIONS = {"watchlist", "ignore", "block"}


def _load() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(data: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def get_action(ip: str) -> str | None:
    """IP uchun joriy action ('watchlist', 'ignore', 'block') yoki None."""
    return _load().get(ip, {}).get("action")


def get_all() -> dict[str, dict]:
    """Barcha IP'larning actionlari."""
    return _load()


def set_action(ip: str, action: str, note: str = "") -> None:
    """IP'ga action belgilash."""
    if action not in VALID_ACTIONS:
        raise ValueError(f"Yaroqsiz action: {action}")
    data = _load()
    data[ip] = {
        "action": action,
        "note":   note,
        "set_at": datetime.now(timezone.utc).isoformat(),
    }
    _save(data)


def clear_action(ip: str) -> None:
    """IP'dan action olib tashlash."""
    data = _load()
    data.pop(ip, None)
    _save(data)


def filter_by_action(ips: list[str], action: str) -> list[str]:
    data = _load()
    return [ip for ip in ips if data.get(ip, {}).get("action") == action]
