"""
Endpoint moslashtiruv — foydalanuvchi qo'shadigan endpoint'larni saqlaydi.

Saqlash joyi: data/custom_endpoints.json (loyiha ildizida)
Har safar parse_log() chaqirilganda default + custom birlashtiriladi.
"""
from __future__ import annotations
import json
from pathlib import Path

from soc_analyzer.config import endpoints as _defaults

_STORE_PATH = Path(__file__).resolve().parents[3] / "data" / "custom_endpoints.json"

_CATEGORIES = {
    "login_paths":        list,
    "exfil_targets":      list,
    "sensitive_prefixes": list,
    "transaction":        list,
    "admin_endpoints":    list,
}

_DEFAULTS: dict[str, list[str]] = {
    "login_paths":        ["/login", "/api/login", "/api/v1/login", "/api/v2/login", "/auth/login"],
    "exfil_targets":      list(_defaults.EXFIL_TARGET_ENDPOINTS),
    "sensitive_prefixes": list(_defaults.SENSITIVE_API_PREFIXES),
    "transaction":        list(_defaults.TRANSACTION_ENDPOINTS),
    "admin_endpoints":    list(_defaults.ADMIN_INTERNAL_ENDPOINTS),
}


def load_custom() -> dict[str, list[str]]:
    """custom_endpoints.json dan o'qiydi, yo'q bo'lsa bo'sh qaytaradi."""
    if not _STORE_PATH.exists():
        return {k: [] for k in _CATEGORIES}
    try:
        data = json.loads(_STORE_PATH.read_text(encoding="utf-8"))
        return {k: data.get(k, []) for k in _CATEGORIES}
    except Exception:
        return {k: [] for k in _CATEGORIES}


def save_custom(custom: dict[str, list[str]]) -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STORE_PATH.write_text(
        json.dumps(custom, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def get_merged(category: str) -> list[str]:
    """Default + custom ro'yxatlarini birlashtiradi (takrorsiz)."""
    base = list(_DEFAULTS.get(category, []))
    custom = load_custom().get(category, [])
    seen = set(base)
    for ep in custom:
        if ep not in seen:
            base.append(ep)
            seen.add(ep)
    return base


def add_endpoint(category: str, path: str) -> bool:
    """Yangi endpoint qo'shadi. True qaytaradi agar muvaffaqiyatli bo'lsa."""
    path = path.strip()
    if not path or not path.startswith("/"):
        return False
    custom = load_custom()
    if path in custom.get(category, []) or path in _DEFAULTS.get(category, []):
        return False
    custom.setdefault(category, []).append(path)
    save_custom(custom)
    return True


def remove_endpoint(category: str, path: str) -> None:
    """Custom ro'yxatdan o'chiradi (default'larni o'chirmaydi)."""
    custom = load_custom()
    lst = custom.get(category, [])
    if path in lst:
        lst.remove(path)
        custom[category] = lst
        save_custom(custom)


def get_defaults(category: str) -> list[str]:
    return list(_DEFAULTS.get(category, []))


CATEGORY_LABELS = {
    "login_paths":        ("🔑 Login endpoints",      "Login so'rovlari aniqlanadigan URL'lar"),
    "exfil_targets":      ("📤 Exfiltration targets", "Ma'lumot chiqishini nazorat qiluvchi URL'lar"),
    "sensitive_prefixes": ("🔒 Sensitive API",        "Himoyalangan API prefikslari"),
    "transaction":        ("💳 Transaction",           "Moliyaviy operatsiya URL'lari"),
    "admin_endpoints":    ("🛠 Admin endpoints",       "Admin/internal panellar"),
}
