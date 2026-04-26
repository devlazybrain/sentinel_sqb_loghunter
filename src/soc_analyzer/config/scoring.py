"""
IP Reputation Score — kumulyativ shubha balli.

Har bir IP butun log davomida ball to'playdi. Severity tier'lar
qattiqroq qilingan (eng yomon IP'lardan farqlanish uchun).
"""

SCORE_WEIGHTS = {
    "failed_login":          5,
    "sqli_payload":         15,    # SQLi muhim — vazn yuqori
    "sensitive_api_200":     1,    # ko'paytirib yubormaslik uchun past
    "admin_endpoint_hit":    8,    # past — chunki ko'p IP'lar /admin'ga kirdi
    "deep_admin_hit":       30,    # /admin/users, /admin/export — yuqori
    "bot_user_agent":       25,    # bir martalik bonus
    "per_mb_api_traffic":   10,
    "off_hours_activity":    1,
    "high_request_rate":    15,
    "regular_interval":     20,    # bot ritmi
    "ua_rotation":          15,
}

# Severity tier'lar — qattiq, real CRITICAL'larni ajratish uchun
SCORE_HIGH      = 200
SCORE_CRITICAL  = 500
SCORE_MEDIUM    = 80


def classify_severity(score: int) -> str:
    if score >= SCORE_CRITICAL:
        return "CRITICAL"
    if score >= SCORE_HIGH:
        return "HIGH"
    if score >= SCORE_MEDIUM:
        return "MEDIUM"
    return "LOW"


# MITRE ATT&CK mapping
MITRE_MAPPING = {
    "credential_stuffing":    ("T1110.004", "Credential Stuffing"),
    "sql_injection":          ("T1190",     "Exploit Public-Facing Application"),
    "data_exfiltration":      ("T1041",     "Exfiltration Over C2 Channel"),
    "anonymizer":             ("T1090",     "Proxy / Anonymizer"),
    "admin_recon":            ("T1087",     "Account Discovery"),
    "low_and_slow":           ("T1078",     "Valid Accounts (slow brute)"),
    "distributed_fingerprint": ("T1583.003", "Botnet Infrastructure"),
}
