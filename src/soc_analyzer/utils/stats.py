"""Statistik yordamchi funksiyalar."""
import pandas as pd


def interval_cv(timestamps: pd.Series) -> float | None:
    """
    Inter-arrival Time Coefficient of Variation = std/mean.
    CV past (< 0.3) bo'lsa → bot ritmi (juda barqaror interval).
    """
    ts = timestamps.sort_values()
    if len(ts) < 5:
        return None
    diffs = ts.diff().dt.total_seconds().dropna()
    if diffs.empty or diffs.mean() == 0:
        return None
    return float(diffs.std() / diffs.mean())


def request_rate_per_minute(timestamps: pd.Series) -> float:
    """Daqiqada o'rtacha so'rov soni."""
    if len(timestamps) < 2:
        return 0.0
    span = (timestamps.max() - timestamps.min()).total_seconds() / 60
    if span <= 0:
        return 0.0
    return len(timestamps) / span
