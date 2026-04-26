"""Bayt va davomiylikni o'qiladigan formatga aylantiruvchilar (3 tilda)."""
from __future__ import annotations
from soc_analyzer.i18n import t


def format_bytes(b: int | float) -> str:
    """1234567 -> '1.18 MB'"""
    b = float(b or 0)
    if b < 1024:
        return f"{int(b)} B"
    if b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    if b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    if b < 1024 ** 4:
        return f"{b / 1024 ** 3:.2f} GB"
    return f"{b / 1024 ** 4:.2f} TB"


def format_duration(seconds: float | int, lang: str = "uz") -> str:
    """
    8039 sek -> "2 soat 13 daqiqa" (uz) / "2 ч 13 мин" (ru) / "2h 13m" (en)
    """
    s = int(seconds or 0)
    if s < 0:
        s = 0

    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)

    h_word = t("dur_hour", lang)
    m_word = t("dur_minute", lang)
    s_word = t("dur_second", lang)
    d_word = t("dur_day", lang)

    parts: list[str] = []
    if days:  parts.append(f"{days} {d_word}")
    if hours: parts.append(f"{hours} {h_word}")
    if mins:  parts.append(f"{mins} {m_word}")
    if secs and not (days or hours):
        parts.append(f"{secs} {s_word}")
    if not parts:
        parts.append(f"0 {s_word}")
    return " ".join(parts)
