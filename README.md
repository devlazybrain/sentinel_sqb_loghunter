# sentinel_sqb_loghunter — SQB Mobile Internet-Banking Cyberattack Analyzer

Log analyzer (Nginx and Backend) for SQB bank for cyber attacks.

Nginx + backend log fayllarni tahlil qilib, **3 ta asosiy hujum** turini avtomatik aniqlovchi va hisobot yaratuvchi tizim:

1. **Credential Stuffing** — leaked credentials bilan login urinishlari
2. **SQL Injection** — API'lar orqali zararli so'rovlar
3. **Data Exfiltration** — API orqali ommaviy ma'lumot o'g'irlash

Bonus aniqlash: **Anonymizer/Proxy**, **Admin Recon**, **Distributed Fingerprint** (botnet), **Attack Chains** (ko'p bosqichli hujum).

## Ishga tushirish

```bash
# 1. Paketlarni o'rnatish
pip install -r requirements.txt

# 2. CLI tahlil
python scripts/run_analysis.py
# yoki o'z log faylingiz bilan:
python scripts/run_analysis.py path/to/your.log

# 3. Web dashboard (Streamlit)
python scripts/run_dashboard.py
# yoki to'g'ridan-to'g'ri:
streamlit run src/soc_analyzer/web/dashboard.py

# 4. API (FastAPI — production deployment uchun)
uvicorn soc_analyzer.api.app:app --port 8000
```

Hisobotlar `data/output/` papkasiga yoziladi: `attacks.csv`, `attacks.json`, `attack_chains.json`, `economic_damage.json`, `ip_reputation.csv`.

## Detection arxitekturasi — 4 LAYER

| Layer | Vaqt darchasi | Nima topadi |
|-------|---|---|
| **L1 — Burst** | 3 soat | Tez, agressiv hujum (sqlmap, login burst) |
| **L2 — Session** | 1 kun | O'rta tezlikda anomal xulq |
| **L3 — Behavioral** | 7-30 kun | APT, low-and-slow uzoq muddatli hujumchi |
| **L4 — Fingerprint** | butun davr | Distributed attacker (bir xil imzo, ko'p IP) |

Har bir IP bir necha layer'da flag bo'lishi mumkin. **2+ layer = HIGH confidence**.

## Loyiha strukturasi

```
sentinel_sqb_loghunter/
├── data/
│   ├── input/           # log fayllar
│   └── output/          # generatsiya qilingan hisobotlar
├── scripts/
│   ├── run_analysis.py  # CLI giriş
│   └── run_dashboard.py # Streamlit launcher
├── src/soc_analyzer/
│   ├── config/          # threshold, regex, endpoint, scoring, economics
│   ├── core/            # parser, models (AttackSession, IpReputation)
│   ├── detectors/       # 6 ta detector + base class
│   ├── analysis/        # engine, reputation, attack_chain, economics
│   ├── reporting/       # CSV/JSON exporters
│   ├── web/             # Streamlit dashboard
│   ├── api/             # FastAPI REST API
│   └── utils/           # ip_utils, stats
└── tests/               # smoke tests
```

## TZ talablariga moslik

| Talab | Bajarilgan |
|---|---|
| Hujum boshlanish vaqti | ✅ `start_time` |
| Hujum tugash vaqti | ✅ `end_time` |
| Hujum davomiyligi | ✅ `duration_seconds` |
| So'rovlar soni | ✅ `request_count` |
| Ko'chirilgan ma'lumot (bytes) | ✅ `total_bytes` |
| Detection rules / SOC thinking | ✅ 4-layer + IP reputation + 11 ta xulq signali |
| Attack Chain | ✅ Ko'p bosqichli hujum aniqlash + critical combo flagging |

## Baholash mezonlariga moslik

- **Hujumlarni detektsiya (30 ball):** 6 ta detector, 4 layer
- **Hujum tahlili (20 ball):** 5 majburiy ko'rsatkich + 8 qo'shimcha
- **Attack Chain (20 ball):** Vaqt tartibida zanjirlash, critical combo bayrog'i
- **Detection Rules / SOC thinking (15 ball):** Multi-layer, IP reputation, fingerprint, low-and-slow
- **Yechim sifati (15 ball):** Modulli arxitektura, test'lar, CLI+Web+API
