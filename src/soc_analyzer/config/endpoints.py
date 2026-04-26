"""
Endpoint kategoriyalari — qaysi URL nima maqsadda.

Bu ro'yxatlar logingizdagi haqiqiy endpoint'lar asosida tuzilgan.
"""

# Sezgir API'lar — pul yoki shaxsiy ma'lumot bilan ishlovchi
SENSITIVE_API_PREFIXES = [
    "/api/accounts",
    "/api/transactions",
    "/api/transfer",
    "/api/payment",
    "/api/export",
    "/api/report",
    "/api/users",
    "/api/search",
    "/api/cards",
    "/api/profile",
    "/api/settings",
    "/api/download",
    # /api/v1/ variants (Nginx logs)
    "/api/v1/accounts",
    "/api/v1/clients",
    "/api/v1/transactions",
    "/api/v1/transfer",
    "/api/v1/payment",
    "/api/v1/export",
    "/api/v1/users",
    "/api/v1/search",
    "/api/v1/cards",
    "/api/v1/profile",
]

# Pul harakatlanadigan endpoint'lar (haqiqiy tranzaksiya)
TRANSACTION_ENDPOINTS = [
    "/api/transfer",
    "/api/payment",
    "/api/v1/transfer",
    "/api/v1/payment",
]

# Mass export / yuklab olish — exfiltration nishoni
EXFIL_TARGET_ENDPOINTS = [
    "/api/export",
    "/api/report",
    "/api/download",
    "/api/transactions",
    "/api/accounts",
    "/api/users",
    "/admin/export",
    # /api/v1/ variants (Nginx logs)
    "/api/v1/clients/export",
    "/api/v1/clients",
    "/api/v1/accounts/list",
    "/api/v1/accounts",
    "/api/v1/transactions",
    "/api/v1/users",
    "/api/v1/export",
    "/api/v1/report",
    "/api/v1/download",
]

# Oddiy foydalanuvchi HECH QACHON kirmasligi kerak bo'lgan endpoint'lar
ADMIN_INTERNAL_ENDPOINTS = [
    "/admin",
    "/admin/users",
    "/admin/export",
    "/internal/audit",
    "/internal",
]

# Public sahifalar — hujum nishoni emas
PUBLIC_ENDPOINTS = [
    "/", "/about", "/help", "/faq", "/login", "/dashboard",
    "/accounts", "/cards", "/payments",
    "/static/app.js", "/static/app.css",
    "/robots.txt",
]
