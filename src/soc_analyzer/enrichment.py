"""
enrichment.py — IP boyitish: Tor + Proxy aniqlash + GeoIP mamlakat qidirish.

Barcha manbalar offline (mahalliy fayllar), internet kerak emas.
  - data/torbulkexitlist.txt  : Tor exit node'lar (har qatorda bitta IP)
  - data/http_proxies.txt     : HTTP proxy ro'yxati (IP:PORT)
  - data/proxyList.txt        : Proxy ro'yxati (IP:PORT)
  - data/proxy-list-raw.txt   : Proxy ro'yxati (IP:PORT)
  - data/GeoLite2-Country.mmdb: MaxMind GeoLite2 offline baza
"""
from __future__ import annotations

from pathlib import Path

_DATA_DIR  = Path(__file__).resolve().parents[2] / "data"
_TOR_PATH  = _DATA_DIR / "torbulkexitlist.txt"
_MMDB_PATH = _DATA_DIR / "GeoLite2-Country.mmdb"
_PROXY_FILES = [
    _DATA_DIR / "http_proxies.txt",
    _DATA_DIR / "proxyList.txt",
    _DATA_DIR / "proxy-list-raw.txt",
]

_tor_nodes: set[str] | None = None
_proxy_ips: set[str] | None = None
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


def _load_proxy_ips() -> set[str]:
    """Barcha proxy fayllaridan IP manzillarni yuklaydi (IP:PORT → faqat IP)."""
    global _proxy_ips
    if _proxy_ips is not None:
        return _proxy_ips
    ips: set[str] = set()
    for path in _PROXY_FILES:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ip = line.split(":")[0].strip()
                    if ip:
                        ips.add(ip)
        except FileNotFoundError:
            pass
    _proxy_ips = ips
    return _proxy_ips


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


def is_proxy(ip: str) -> bool:
    return ip in _load_proxy_ips()


def geoip_country(ip: str) -> str:
    reader = _get_geoip_reader()
    if reader is None:
        return "Unknown"
    try:
        return reader.country(ip).country.name or "Unknown"
    except Exception:
        return "Unknown"


def enrich_session(session) -> None:
    """AttackSession obyektiga country, via_tor, via_proxy maydonlarini to'ldiradi (in-place)."""
    primary_ip = session.ip.split(",")[0].strip()
    session.country   = geoip_country(primary_ip)
    session.via_tor   = is_tor(primary_ip)
    # Tor ham proxy hisoblanadi, lekin via_proxy faqat tor bo'lmagan proxy uchun
    session.via_proxy = is_proxy(primary_ip) and not session.via_tor


def enrich_all(sessions: list) -> None:
    """Barcha sessiyalarni boyitadi (in-place)."""
    for s in sessions:
        enrich_session(s)
