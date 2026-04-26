"""
enrichment.py — IP boyitish: Tor exit-node aniqlash + GeoIP mamlakat qidirish.

Ikkala manba ham offline (mahalliy fayllar), internet kerak emas.
  - data/torbulkexitlist.txt  : har qatorda bitta IP
  - data/GeoLite2-Country.mmdb: MaxMind GeoLite2 offline baza
"""
from __future__ import annotations

from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_TOR_PATH  = _DATA_DIR / "torbulkexitlist.txt"
_MMDB_PATH = _DATA_DIR / "GeoLite2-Country.mmdb"

_tor_nodes: set[str] | None = None
_geoip_reader = None


def _load_tor_nodes() -> set[str]:
    global _tor_nodes
    if _tor_nodes is not None:
        return _tor_nodes
    nodes: set[str] = set()
    try:
        with open(_TOR_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    nodes.add(line)
    except FileNotFoundError:
        pass
    _tor_nodes = nodes
    return _tor_nodes


def _get_geoip_reader():
    global _geoip_reader
    if _geoip_reader is not None:
        return _geoip_reader
    try:
        import geoip2.database  # type: ignore
        _geoip_reader = geoip2.database.Reader(str(_MMDB_PATH))
    except Exception:
        _geoip_reader = None
    return _geoip_reader


def is_tor(ip: str) -> bool:
    return ip in _load_tor_nodes()


def geoip_country(ip: str) -> str:
    reader = _get_geoip_reader()
    if reader is None:
        return "Unknown"
    try:
        return reader.country(ip).country.name or "Unknown"
    except Exception:
        return "Unknown"


def enrich_session(session) -> None:
    """AttackSession obyektiga country va via_tor maydonlarini to'ldiradi (in-place)."""
    primary_ip = session.ip.split(",")[0].strip()
    session.country = geoip_country(primary_ip)
    session.via_tor = is_tor(primary_ip)


def enrich_all(sessions: list) -> None:
    """Barcha sessiyalarni boyitadi (in-place)."""
    for s in sessions:
        enrich_session(s)
