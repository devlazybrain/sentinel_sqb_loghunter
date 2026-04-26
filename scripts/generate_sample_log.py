"""
Sintetik log generatori — long-term va short-term hujumlarni testlash uchun.

Yaratiladigan fayl: data/input/sample_logs.txt

Tarkibi:
  - 7 kunlik vaqt davri (2026-04-18 -> 2026-04-25)
  - 18 ta oddiy foydalanuvchi (haqiqatan oddiy xulq)
  - 4 ta hujumchi:
      A) BURST stuffing  — 50 ta failed login 5 daqiqada
      B) BURST sqli      — sqlmap, 8 ta payload 2 daqiqada
      C) BURST exfil     — 100 MB 10 daqiqada
      D) LOW-AND-SLOW stuffing — 7 kun davomida soatiga 1-2 ta failed login
      E) LOW-AND-SLOW exfil    — kuniga 5 MB, 7 kun

Foydalanish:
    python scripts/generate_sample_log.py
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

ROOT = Path(__file__).resolve().parent.parent
OUT  = ROOT / "data" / "input" / "sample_logs.txt"

# ===================== KONFIG =====================
START = datetime(2026, 4, 18, 0, 0, 0, tzinfo=timezone.utc)
DAYS  = 7

NORMAL_IPS = [
    "78.140.21.5", "92.45.67.123", "176.88.45.12", "203.115.67.89",
    "94.158.33.21", "82.215.12.99", "85.140.55.66", "188.40.21.15",
    "62.122.55.90", "91.205.18.77", "213.230.65.12", "84.54.118.33",
    "95.214.10.5", "37.110.220.45", "188.111.144.66", "46.21.243.78",
    "10.0.1.50", "10.0.2.40",  # ichki tarmoq mijozlari
]

NORMAL_UAS = [
    "Mozilla/5.0_(iPhone;_CPU_iPhone_OS_18_0_like_Mac_OS_X)_AppleWebKit/605.1.15",
    "Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_Chrome/121.0",
    "Mozilla/5.0_(Macintosh;_Intel_Mac_OS_X_10_15_7)_AppleWebKit/605.1.15",
    "Mozilla/5.0_(Linux;_Android_14)_AppleWebKit/537.36_Chrome/120.0",
    "Mozilla/5.0_(iPad;_CPU_OS_18_0_like_Mac_OS_X)_AppleWebKit/605.1.15",
]

NORMAL_FLOW = [
    ("GET",  "/",                200, (800, 2500)),
    ("GET",  "/login",           200, (1000, 3000)),
    ("POST", "/login",           200, (200, 600)),
    ("GET",  "/dashboard",       200, (1500, 4000)),
    ("GET",  "/api/profile",     200, (400, 1200)),
    ("GET",  "/accounts",        200, (1000, 5000)),
    ("GET",  "/api/accounts",    200, (500, 2000)),
    ("GET",  "/cards",           200, (1000, 4000)),
    ("GET",  "/api/transactions", 200, (1500, 4500)),
    ("GET",  "/payments",        200, (1000, 3000)),
    ("POST", "/api/transfer",    201, (300, 800)),
    ("POST", "/api/payment",     201, (300, 800)),
    ("GET",  "/help",            200, (1000, 2500)),
    ("GET",  "/about",           200, (800, 2200)),
    ("GET",  "/static/app.js",   200, (3000, 5000)),
    ("GET",  "/static/app.css",  200, (1500, 3000)),
]


def fmt(line: tuple) -> str:
    ts, ip, method, url, status, sz, ua = line
    return f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')} {ip} {method} {url} {status} {sz} {ua}"


# ===================== ODDIY FOYDALANUVCHI =====================
def gen_normal(lines: list):
    """Har kuni 09:00-22:00 oralig'ida tasodifiy faollik.
    Har IP'ning ASOSIY qurilmasi bor (90% sessiya), ba'zan ikkinchi qurilma."""
    # Har IP uchun primary va ikkinchi UA (deterministik)
    ip_devices = {}
    for ip in NORMAL_IPS:
        primary = random.choice(NORMAL_UAS)
        ip_devices[ip] = (primary, random.choice(NORMAL_UAS))

    for day in range(DAYS):
        day_start = START + timedelta(days=day)
        for ip in NORMAL_IPS:
            primary, secondary = ip_devices[ip]
            sessions_today = random.randint(1, 3)
            for _ in range(sessions_today):
                hour   = random.randint(9, 21)
                minute = random.randint(0, 59)
                start_t = day_start + timedelta(hours=hour, minutes=minute)
                # 90% asosiy qurilma, 10% ikkinchi
                ua = primary if random.random() < 0.9 else secondary
                count = random.randint(5, 15)
                t = start_t
                for _ in range(count):
                    method, url, status, sz_range = random.choice(NORMAL_FLOW)
                    sz = random.randint(*sz_range)
                    lines.append((t, ip, method, url, status, sz, ua))
                    t += timedelta(seconds=random.randint(5, 30))


# ===================== HUJUM A: BURST STUFFING =====================
def gen_burst_stuffing(lines: list):
    ip = "185.23.44.12"
    ua = "python-requests/2.31.0"
    # Kun 3, soat 14:00 da 5 daqiqalik burst
    t = START + timedelta(days=3, hours=14, minutes=0)
    for _ in range(50):
        # 80% failed, 20% success (asta-sekin top adi)
        status = 401 if random.random() < 0.85 else 200
        sz = random.randint(150, 400)
        lines.append((t, ip, "POST", "/login", status, sz, ua))
        t += timedelta(seconds=random.randint(2, 8))


# ===================== HUJUM B: BURST SQLi =====================
def gen_burst_sqli(lines: list):
    ip = "91.199.12.77"
    ua = "sqlmap/1.7.2#stable"
    t = START + timedelta(days=4, hours=11, minutes=30)
    payloads = [
        ("/api/accounts", "id=1%20OR%201=1"),
        ("/api/accounts", "id=1%20UNION%20SELECT%20password%20FROM%20users"),
        ("/api/accounts", "id=1%27%20OR%20%271%27=%271"),
        ("/api/search",   "q=test%27%20UNION%20SELECT%20card_no,cvv%20FROM%20cards--"),
        ("/api/report",   "acct=1001%20UNION%20SELECT%20name,balance%20FROM%20accounts"),
        ("/api/report",   "acct=1001%20UNION%20SELECT%20username,password%20FROM%20users"),
        ("/api/users",    "id=1;%20DROP%20TABLE%20users--"),
        ("/api/profile",  "uid=1%20AND%20SLEEP(5)"),
    ]
    for path, q in payloads:
        url = f"{path}?{q}"
        # 40% serverda muvaffaqiyatli (200), 60% xato (500)
        status = 200 if random.random() < 0.4 else 500
        sz = random.randint(2000, 25000) if status == 200 else random.randint(500, 2000)
        lines.append((t, ip, "GET", url, status, sz, ua))
        t += timedelta(seconds=random.randint(5, 20))


# ===================== HUJUM C: BURST EXFILTRATION =====================
def gen_burst_exfil(lines: list):
    ip = "103.44.55.66"
    ua = "curl/8.0.1"
    t = START + timedelta(days=5, hours=2, minutes=15)  # off-hours!
    targets = ["/api/export", "/api/transactions", "/api/accounts", "/api/users", "/api/report"]
    # 40 ta katta so'rov, har biri 2-5 MB, 10 daqiqada
    for _ in range(40):
        url = random.choice(targets)
        sz = random.randint(2_000_000, 5_000_000)
        lines.append((t, ip, "GET", url, 200, sz, ua))
        t += timedelta(seconds=random.randint(10, 25))


# ===================== HUJUM D: LOW-AND-SLOW STUFFING =====================
def gen_slow_stuffing(lines: list):
    """7 kun davomida soatiga 1-2 ta failed login — radar ostidan o'tish."""
    ip = "45.142.213.99"
    ua = "Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36"  # oddiy ko'rinadi
    t = START + timedelta(hours=2)
    end = START + timedelta(days=DAYS)
    while t < end:
        # 80% failed
        status = 401 if random.random() < 0.8 else 200
        sz = random.randint(180, 450)
        lines.append((t, ip, "POST", "/login", status, sz, ua))
        # Keyingi urinish — 30 daqiqa ichida tasodifiy
        t += timedelta(minutes=random.randint(20, 90))


# ===================== HUJUM E: LOW-AND-SLOW EXFIL =====================
def gen_slow_exfil(lines: list):
    """Kuniga ~10 MB, 7 kun = ~70 MB jami. Burst ostida, lekin haftalik thresholddan yuqori."""
    ip = "159.203.45.21"
    ua = "Mozilla/5.0_(Macintosh;_Intel_Mac_OS_X_10_15_7)_AppleWebKit/605.1.15"
    # Faqat haqiqiy exfil-target endpointlar
    targets = ["/api/transactions", "/api/accounts", "/api/users"]
    for day in range(DAYS):
        day_start = START + timedelta(days=day)
        n = random.randint(12, 16)
        for i in range(n):
            t = day_start + timedelta(hours=10 + i*0.5, minutes=random.randint(0, 30))
            sz = random.randint(600_000, 900_000)
            url = random.choice(targets)
            lines.append((t, ip, "GET", url, 200, sz, ua))


# ===================== ASOSIY =====================
def main():
    lines: list[tuple] = []
    print("Oddiy foydalanuvchilarni yaratish...")
    gen_normal(lines)
    print("Hujum A: Burst credential stuffing (185.23.44.12)...")
    gen_burst_stuffing(lines)
    print("Hujum B: Burst SQL injection (91.199.12.77, sqlmap)...")
    gen_burst_sqli(lines)
    print("Hujum C: Burst exfiltration (103.44.55.66, off-hours)...")
    gen_burst_exfil(lines)
    print("Hujum D: Low-and-slow stuffing (45.142.213.99, 7 kun)...")
    gen_slow_stuffing(lines)
    print("Hujum E: Low-and-slow exfiltration (159.203.45.21, 7 kun)...")
    gen_slow_exfil(lines)

    # Vaqt bo'yicha tartiblash
    lines.sort(key=lambda x: x[0])

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(fmt(line) + "\n")

    print(f"\nYaratildi: {OUT}")
    print(f"Jami qator: {len(lines):,}")
    print(f"Davr: {lines[0][0]} -> {lines[-1][0]}")
    print(f"\nKutilayotgan hujumlar:")
    print("  KRITIK   91.199.12.77    - SQL injection (8 payload)")
    print("  YUQORI   185.23.44.12    - Credential stuffing (50 urinish, 5 daq)")
    print("  YUQORI   103.44.55.66    - Data exfiltration (~140 MB, 10 daq)")
    print("  YUQORI   45.142.213.99   - Low-and-slow stuffing (7 kun, ~250 urinish)")
    print("  YUQORI   159.203.45.21   - Low-and-slow exfil (7 kun, ~35 MB)")


if __name__ == "__main__":
    main()
