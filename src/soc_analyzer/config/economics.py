"""
Iqtisodiy zarar baholash konstantalari.

Hay'at iqtisodchilari — pul tilida hisobotlar muhim.
"""

# Ma'lumot qiymati (dark market)
AVG_RECORD_SIZE_BYTES   = 512      # 1 mijoz yozuvi taxminiy hajmi
RECORD_DARK_MARKET_USD  = 5        # 1 bank yozuvi ~$5 dark web'da
USD_TO_UZS              = 12_650   # 2026-04-25 valyuta kursi

# O'rtacha tranzaksiya hajmi (taxminiy)
AVG_TRANSFER_USD        = 250
AVG_PAYMENT_USD         = 80

# Compliance jarima (CBU/markaziy bank standartlari)
GDPR_FINE_PER_RECORD_USD = 50      # data breach jarimasi har 1 mijoz uchun

# Bank reputatsiya zarari ko'paytuvchisi
REPUTATION_DAMAGE_MULTIPLIER = 3.0  # to'g'ridan-to'g'ri zarar × 3 = jami iqtisodiy zarar
