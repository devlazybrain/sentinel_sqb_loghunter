"""
enrichment.py — IP enrichment: Tor exit-node detection + GeoIP country lookup.

Both data sources are offline (local files), so no internet is needed.
  - torbulkexitlist.txt  : one IP per line, from check.torproject.org
  - GeoLite2-Country.mmdb: MaxMind GeoLite2 offline database
"""

from __future__ import annotations

import os

_TOR_PATH  = os.path.join(os.path.dirname(__file__), "torbulkexitlist.txt")
_MMDB_PATH = os.path.join(os.path.dirname(__file__), "GeoLite2-Country.mmdb")

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
        _geoip_reader = geoip2.database.Reader(_MMDB_PATH)
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


def enrich_session(session: dict) -> dict:
    """Add country, via_tor fields to a session dict (in-place and returned)."""
    # For distributed CS the attacker_ip field is a comma-separated list;
    # use the first real IP for enrichment.
    primary_ip = session["attacker_ip"].split(",")[0].strip()
    session["country"] = geoip_country(primary_ip)
    session["via_tor"] = is_tor(primary_ip)
    return session


def enrich_all(sessions: list[dict]) -> list[dict]:
    return [enrich_session(s) for s in sessions]
