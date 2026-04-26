"""
1.5 OYLIK (45 kun) sintetik log generatori.

Tarkibi:
  - 25 ta oddiy mijoz (45 kun davomida normal xulq)
  - SHORT-TERM (burst) hujumlar:
      Day 5  — credential stuffing burst (50 ur., 5 daq)
      Day 12 — SQL injection burst (sqlmap, 12 payload)
      Day 20 — data exfiltration burst (200 MB, 12 daq)
      Day 33 — admin recon burst (deep paths)
      Day 41 — credential stuffing burst (turli IP)
  - LONG-TERM (low-and-slow) hujumlar:
      Day 1-45  — slow stuffing (kuniga 5-10 failed login, 45 kun)
      Day 1-45  — slow exfiltration (kuniga 8 MB sezgir API, 45 kun = ~360 MB)
      Day 8-38  — APT campaign: recon -> slow login -> slow exfil

Foydalanish:
    python scripts/generate_long_sample_log.py
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(2026)

ROOT = Path(__file__).resolve().parent.parent
OUT  = ROOT / "data" / "input" / "sample_logs_45days.txt"

# ===================== KONFIG =====================
START = datetime(2026, 3, 10, 0, 0, 0, tzinfo=timezone.utc)
DAYS  = 45

# 25 ta oddiy mijoz IP'lari
NORMAL_IPS = [
    "78.140.21.5",  "92.45.67.123", "176.88.45.12", "203.115.67.89",
    "94.158.33.21", "82.215.12.99", "85.140.55.66", "188.40.21.15",
    "62.122.55.90", "91.205.18.77", "213.230.65.12", "84.54.118.33",
    "95.214.10.5",  "37.110.220.45","188.111.144.66","46.21.243.78",
    "93.184.12.4",  "212.42.99.55", "77.244.21.18", "5.144.55.99",
    # Ichki tarmoq mijozlari
    "10.0.1.50", "10.0.2.40", "10.0.3.15", "10.0.5.20", "10.0.7.91",
]

NORMAL_UAS = [
    "Mozilla/5.0_(iPhone;_CPU_iPhone_OS_18_0_like_Mac_OS_X)_AppleWebKit/605.1.15",
    "Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_Chrome/121.0",
    "Mozilla/5.0_(Macintosh;_Intel_Mac_OS_X_10_15_7)_AppleWebKit/605.1.15",
    "Mozilla/5.0_(Linux;_Android_14)_AppleWebKit/537.36_Chrome/120.0",
    "Mozilla/5.0_(iPad;_CPU_OS_18_0_like_Mac_OS_X)_AppleWebKit/605.1.15",
    "Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_Edge/120.0",
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
    ("GET",  "/faq",             200, (1500, 3500)),
]


def fmt(line: tuple) -> str:
    ts, ip, method, url, status, sz, ua = line
    return f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')} {ip} {method} {url} {status} {sz} {ua}"


# ===================== ODDIY FOYDALANUVCHILAR =====================
def gen_normal(lines: list):
    """Har IP'ning asosiy qurilmasi bor, kuniga 0-3 sessiya."""
    ip_devices = {}
    for ip in NORMAL_IPS:
        primary = random.choice(NORMAL_UAS)
        ip_devices[ip] = (primary, random.choice(NORMAL_UAS))

    for day in range(DAYS):
        day_start = START + timedelta(days=day)
        for ip in NORMAL_IPS:
            primary, secondary = ip_devices[ip]
            # Ba'zi kunlar foydalanuvchi tashrif buyurmasligi mumkin
            sessions_today = random.choices([0, 1, 2, 3], weights=[0.2, 0.5, 0.2, 0.1])[0]
            for _ in range(sessions_today):
                hour = random.randint(8, 22)
                minute = random.randint(0, 59)
                start_t = day_start + timedelta(hours=hour, minutes=minute)
                ua = primary if random.random() < 0.92 else secondary
                count = random.randint(4, 14)
                t = start_t
                for _ in range(count):
                    method, url, status, sz_range = random.choice(NORMAL_FLOW)
                    sz = random.randint(*sz_range)
                    lines.append((t, ip, method, url, status, sz, ua))
                    t += timedelta(seconds=random.randint(5, 35))


# ===================== SHORT-TERM HUJUMLAR =====================
def gen_burst_stuffing_day5(lines: list):
    ip = "185.23.44.12"
    ua = "python-requests/2.31.0"
    t = START + timedelta(days=5, hours=14)
    for _ in range(50):
        status = 401 if random.random() < 0.85 else 200
        sz = random.randint(150, 400)
        lines.append((t, ip, "POST", "/login", status, sz, ua))
        t += timedelta(seconds=random.randint(2, 8))


def gen_burst_sqli_day12(lines: list):
    ip = "91.199.12.77"
    ua = "sqlmap/1.7.2#stable"
    t = START + timedelta(days=12, hours=10, minutes=30)
    payloads = [
        ("/api/accounts", "id=1%20OR%201=1"),
        ("/api/accounts", "id=1%20UNION%20SELECT%20password%20FROM%20users"),
        ("/api/accounts", "id=1%27%20OR%20%271%27=%271"),
        ("/api/search",   "q=test%27%20UNION%20SELECT%20card_no,cvv%20FROM%20cards--"),
        ("/api/report",   "acct=1001%20UNION%20SELECT%20name,balance%20FROM%20accounts"),
        ("/api/report",   "acct=1001%20UNION%20SELECT%20username,password%20FROM%20users"),
        ("/api/users",    "id=1;%20DROP%20TABLE%20users--"),
        ("/api/profile",  "uid=1%20AND%20SLEEP(5)"),
        ("/api/search",   "q=1%27%20UNION%20SELECT%20*%20FROM%20information_schema.tables--"),
        ("/api/accounts", "id=1%27;%20WAITFOR%20DELAY%20%2700:00:05%27--"),
        ("/api/users",    "name=admin%27%20OR%20%271%27=%271"),
        ("/api/transfer", "amount=1%20UNION%20SELECT%20cvv,pan%20FROM%20cards"),
    ]
    for path, q in payloads:
        url = f"{path}?{q}"
        status = 200 if random.random() < 0.4 else 500
        sz = random.randint(2000, 25000) if status == 200 else random.randint(500, 2000)
        lines.append((t, ip, "GET", url, status, sz, ua))
        t += timedelta(seconds=random.randint(5, 20))


def gen_burst_exfil_day20(lines: list):
    ip = "103.44.55.66"
    ua = "curl/8.0.1"
    t = START + timedelta(days=20, hours=2, minutes=15)  # off-hours
    targets = ["/api/export", "/api/transactions", "/api/accounts", "/api/users", "/api/report"]
    for _ in range(55):
        url = random.choice(targets)
        sz = random.randint(2_500_000, 5_500_000)
        lines.append((t, ip, "GET", url, 200, sz, ua))
        t += timedelta(seconds=random.randint(8, 22))


def gen_burst_admin_recon_day33(lines: list):
    ip = "176.88.14.201"
    ua = "PostmanRuntime/7.39.0"
    t = START + timedelta(days=33, hours=23, minutes=30)
    paths = ["/admin", "/admin/users", "/admin/export", "/internal/audit", "/internal",
             "/admin", "/admin/users", "/admin/export"]
    for path in paths:
        status = random.choice([200, 200, 403, 200])
        sz = random.randint(800, 3000)
        lines.append((t, ip, "GET", path, status, sz, ua))
        t += timedelta(seconds=random.randint(3, 15))


def gen_burst_stuffing_day41(lines: list):
    ip = "203.0.113.45"
    ua = "Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)"
    t = START + timedelta(days=41, hours=3, minutes=12)  # off-hours
    for _ in range(65):
        status = 401 if random.random() < 0.9 else 200
        sz = random.randint(150, 400)
        lines.append((t, ip, "POST", "/login", status, sz, ua))
        t += timedelta(seconds=random.randint(1, 5))


# ===================== LONG-TERM HUJUMLAR =====================
def gen_slow_stuffing(lines: list):
    """45 kun davomida soatiga 1-2 ta failed login."""
    ip = "45.142.213.99"
    ua = "Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36"
    t = START + timedelta(hours=2)
    end = START + timedelta(days=DAYS)
    while t < end:
        status = 401 if random.random() < 0.78 else 200
        sz = random.randint(180, 450)
        lines.append((t, ip, "POST", "/login", status, sz, ua))
        # Keyingi urinish 30-120 daq
        t += timedelta(minutes=random.randint(30, 120))


def gen_slow_exfil(lines: list):
    """45 kun davomida kuniga 6-10 ta sezgir API so'rov."""
    ip = "159.203.45.21"
    ua = "Mozilla/5.0_(Macintosh;_Intel_Mac_OS_X_10_15_7)_AppleWebKit/605.1.15"
    targets = ["/api/transactions", "/api/accounts", "/api/users"]
    for day in range(DAYS):
        day_start = START + timedelta(days=day)
        n = random.randint(6, 10)
        for i in range(n):
            t = day_start + timedelta(hours=10 + i*0.7, minutes=random.randint(0, 30))
            sz = random.randint(700_000, 1_100_000)
            url = random.choice(targets)
            lines.append((t, ip, "GET", url, 200, sz, ua))


def gen_apt_campaign(lines: list):
    """APT-style: Day 8-38, 3 bosqichli sekin hujum."""
    ip = "185.220.101.42"  # Tor exit nodes range
    ua_recon = "PostmanRuntime/7.39.0"
    ua_login = "Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_Chrome/120.0"
    ua_exfil = "python-requests/2.31.0"

    # Bosqich 1 (Day 8-15): admin recon, sekin
    for day in range(8, 16):
        if random.random() < 0.6:  # ba'zi kunlar tashrif yo'q
            continue
        t = START + timedelta(days=day, hours=random.randint(0, 6), minutes=random.randint(0, 59))
        path = random.choice(["/admin", "/admin/users", "/admin/export", "/internal/audit"])
        lines.append((t, ip, "GET", path, random.choice([200, 403]), random.randint(500, 2500), ua_recon))

    # Bosqich 2 (Day 15-30): juda sekin login urinishlari
    for day in range(15, 31):
        n = random.randint(2, 4)
        for _ in range(n):
            t = START + timedelta(days=day, hours=random.randint(2, 5),
                                  minutes=random.randint(0, 59))
            status = 401 if random.random() < 0.7 else 200
            lines.append((t, ip, "POST", "/login", status, random.randint(200, 500), ua_login))

    # Bosqich 3 (Day 30-38): sekin ma'lumot tortib chiqarish
    for day in range(30, 39):
        n = random.randint(3, 6)
        for _ in range(n):
            t = START + timedelta(days=day, hours=random.randint(3, 6),
                                  minutes=random.randint(0, 59))
            url = random.choice(["/api/transactions", "/api/accounts", "/api/users", "/api/export"])
            sz = random.randint(800_000, 1_500_000)
            lines.append((t, ip, "GET", url, 200, sz, ua_exfil))


# ===================== ASOSIY =====================
def main():
    lines: list[tuple] = []
    print("Oddiy 25 mijoz, 45 kun...")
    gen_normal(lines)

    print("\nSHORT-TERM (burst) hujumlar:")
    print("  Day 5  — credential stuffing")
    gen_burst_stuffing_day5(lines)
    print("  Day 12 — SQL injection (sqlmap)")
    gen_burst_sqli_day12(lines)
    print("  Day 20 — data exfiltration (off-hours)")
    gen_burst_exfil_day20(lines)
    print("  Day 33 — admin recon (off-hours)")
    gen_burst_admin_recon_day33(lines)
    print("  Day 41 — credential stuffing (off-hours)")
    gen_burst_stuffing_day41(lines)

    print("\nLONG-TERM (low-and-slow) hujumlar:")
    print("  Day 1-45  — slow stuffing")
    gen_slow_stuffing(lines)
    print("  Day 1-45  — slow exfiltration")
    gen_slow_exfil(lines)
    print("  Day 8-38  — APT campaign (recon -> login -> exfil)")
    gen_apt_campaign(lines)

    lines.sort(key=lambda x: x[0])

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(fmt(line) + "\n")

    print(f"\n{'='*70}")
    print(f"Yaratildi: {OUT}")
    print(f"Jami qator: {len(lines):,}")
    print(f"Davr: {lines[0][0]:%Y-%m-%d}  ->  {lines[-1][0]:%Y-%m-%d}")
    print(f"Davomiyligi: 45 kun (1.5 oy)")
    print(f"{'='*70}\n")
    print("KUTILAYOTGAN HUJUMCHILAR (8 ta):")
    print("  SHORT-TERM:")
    print("    185.23.44.12     - stuffing (Day 5)")
    print("    91.199.12.77     - SQL injection (Day 12, sqlmap)")
    print("    103.44.55.66     - exfil 200MB (Day 20, off-hours)")
    print("    176.88.14.201    - admin recon (Day 33)")
    print("    203.0.113.45     - stuffing (Day 41)")
    print("  LONG-TERM:")
    print("    45.142.213.99    - slow stuffing (45 kun)")
    print("    159.203.45.21    - slow exfil (45 kun, ~330MB)")
    print("    185.220.101.42   - APT campaign (30 kun, 3 bosqich)")


if __name__ == "__main__":
    main()
