"""
Iqtisodiy zarar baholash — hay'at iqtisodchilari uchun pul tilida.

Hisoblash:
  - O'g'irlangan yozuvlar soni: bytes / record_size
  - Dark market qiymati:        records × $5
  - Compliance jarima:          records × $50
  - Reputatsiya zarari:         direct × 3
  - Fraud potensial:            successful_transfers × $250
"""
from __future__ import annotations
import pandas as pd

from soc_analyzer.config.economics import (
    AVG_RECORD_SIZE_BYTES,
    RECORD_DARK_MARKET_USD,
    USD_TO_UZS,
    AVG_TRANSFER_USD,
    AVG_PAYMENT_USD,
    GDPR_FINE_PER_RECORD_USD,
    REPUTATION_DAMAGE_MULTIPLIER,
)
from soc_analyzer.core.models import AttackSession


def estimate_damage(sessions: list[AttackSession], df: pd.DataFrame) -> dict:
    """Umumiy iqtisodiy zarar (USD va UZS)."""
    total_exfil_bytes = sum(
        s.total_bytes for s in sessions if s.attack_type == "data_exfiltration"
    )
    estimated_records = total_exfil_bytes // AVG_RECORD_SIZE_BYTES if total_exfil_bytes else 0

    dark_market_loss = estimated_records * RECORD_DARK_MARKET_USD
    compliance_fine  = estimated_records * GDPR_FINE_PER_RECORD_USD
    direct_loss      = dark_market_loss + compliance_fine
    reputation_loss  = int(direct_loss * (REPUTATION_DAMAGE_MULTIPLIER - 1))
    total_usd        = direct_loss + reputation_loss

    # Hujum davomida muvaffaqiyatli transfer/to'lov tahdidi
    suspicious_ips = {s.ip for s in sessions if s.severity in ("HIGH", "CRITICAL")
                      and "," not in s.ip}
    if df.empty or not suspicious_ips:
        fraud_potential = 0
        suspicious_transfers = 0
    else:
        sus_df = df[df["ip"].isin(suspicious_ips) & df["is_transaction"] & (df["status"] == 200)]
        suspicious_transfers = len(sus_df)
        fraud_potential = (
            int((sus_df["url_path"] == "/api/transfer").sum()) * AVG_TRANSFER_USD +
            int((sus_df["url_path"] == "/api/payment").sum())  * AVG_PAYMENT_USD
        )

    return {
        "estimated_records":     estimated_records,
        "exfil_bytes":           total_exfil_bytes,
        "exfil_mb":              round(total_exfil_bytes / 1_000_000, 2),
        "dark_market_loss_usd":  dark_market_loss,
        "compliance_fine_usd":   compliance_fine,
        "reputation_loss_usd":   reputation_loss,
        "fraud_potential_usd":   fraud_potential,
        "suspicious_transfers":  suspicious_transfers,
        "total_loss_usd":        total_usd + fraud_potential,
        "total_loss_uzs":        (total_usd + fraud_potential) * USD_TO_UZS,
    }
