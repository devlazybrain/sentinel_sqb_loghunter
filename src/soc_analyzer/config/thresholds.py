"""
Detection thresholds — 4 LAYER Detection Engine uchun.

Layer 1 — Burst (qisqa muddatli, agressiv hujum)
Layer 2 — Session (1 kunlik faollik)
Layer 3 — Behavioral (haftalik / oylik low-and-slow APT)
Layer 4 — Fingerprint (xulq imzosi)
"""

# ============================================================
# LAYER 1 — BURST (3 soatlik darcha)
# ============================================================
BURST_WINDOW            = "3h"
BURST_LOGIN_COUNT       = 15
BURST_FAILURE_RATIO     = 0.5
BURST_EXFIL_BYTES       = 5_000_000      # 5 MB
BURST_EXFIL_COUNT       = 30

# ============================================================
# LAYER 2 — SESSION (1 kunlik)
# ============================================================
SESSION_WINDOW          = "1D"
SESSION_LOGIN_COUNT     = 30
SESSION_FAILURE_RATIO   = 0.3
SESSION_EXFIL_BYTES     = 10_000_000     # 10 MB / kun
SESSION_EXFIL_COUNT     = 100

# ============================================================
# LAYER 3 — BEHAVIORAL (haftalik / oylik APT)
# ============================================================
WEEKLY_WINDOW           = "7D"
MONTHLY_WINDOW          = "30D"
WEEKLY_LOGIN_COUNT      = 50
MONTHLY_LOGIN_COUNT     = 150
WEEKLY_EXFIL_BYTES      = 30_000_000
LONGTERM_FAILURE_RATIO  = 0.15

# ============================================================
# LAYER 4 — FINGERPRINT
# ============================================================
FINGERPRINT_MIN_REQUESTS    = 20
FINGERPRINT_DUPLICATE_IPS   = 2
FINGERPRINT_IAT_CV          = 0.3        # Inter-arrival CV — bot ritmi

# ============================================================
# SQL Injection
# ============================================================
SQLI_MIN_PAYLOADS           = 1

# ============================================================
# ANONYMIZER (kuchaytirilgan)
# ============================================================
# Faqat bot UA mavjudligi yetarli emas — talab qilinadigan ratio
ANONYMIZER_MIN_BOT_RATIO    = 0.20       # so'rovlarning ≥20% bot UA bo'lsa
ANONYMIZER_MIN_REQUESTS     = 30
ANONYMIZER_UA_ROTATION_MIN  = 4          # ≥4 xil UA bir IP'da

# ============================================================
# ADMIN RECON (kuchaytirilgan)
# ============================================================
# Oddiy /admin landing emas — chuqur yoki muvaffaqiyatli kirish
ADMIN_RECON_MIN_HITS        = 5
ADMIN_RECON_DEEP_PATHS      = ("/admin/users", "/admin/export", "/internal/audit", "/internal")

# ============================================================
# VAQT MINTAQASI (Toshkent UTC+5)
# ============================================================
LOCAL_TZ_OFFSET_HOURS   = 5
OFF_HOURS_START         = 22
OFF_HOURS_END           = 7
