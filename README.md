# SQB SOC — Mobile Internet-Banking Kiberhujum Analitikasi

Nginx veb-server loglarini tahlil qilib, koordinatsiyalangan ko'p bosqichli kiberhujumlarni avtomatik aniqlaydi va real vaqtda Streamlit dashboard orqali ko'rsatadi.

---

## Aniqlash imkoniyatlari

### Asosiy hujum turlari
| Hujum turi | Aniqlash mantiqi |
|---|---|
| **Credential Stuffing** | 4-qatlamli aniqlash — burst, session, low-and-slow, bot UA |
| **SQL Injection** | URL parametrlarida zararli payload'lar, sqlmap fingerprint |
| **Data Exfiltration** | API orqali ommaviy ma'lumot tortib olish — bayt hajmi va endpoint tahlili |

### Qo'shimcha detektorlar
| Detektor | Nima topadi |
|---|---|
| **Anonymizer / Proxy** | TOR exit node, proxy, bot UA rotatsiyasi |
| **Admin Recon** | `/admin`, `/internal` endpointlarga maxfiy razvedka |
| **Distributed Fingerprint** | Turli IP'lardan bir xil UA — botnet/kampaniya |
| **Distributed Credential Stuffing** | Koordinatsiyalangan ko'p IP login hujumi |

---

## 4-Qatlamli Deteksiya Arxitekturasi

| Qatlam | Vaqt oralig'i | Nima topadi |
|---|---|---|
| **L1 — Burst** | 3 soat | Tez, agressiv hujum — login burst, sqlmap |
| **L2 — Session** | 1 kun | O'rta tezlikda anomal xulq |
| **L3 — Behavioral** | 7–30 kun | APT, low-and-slow uzoq muddatli hujumchi |
| **L4 — Fingerprint** | Butun davr | Distributed attacker — bir xil imzo, ko'p IP |

Bir IP bir necha qatlamda flag olishi mumkin. **2+ qatlam = yuqori ishonch darajasi.**

---

## Attack Chain Aniqlash

Ikki xil zanjir turi aniqlanadi:

**1. Single-IP Chain** — bitta IP ketma-ket 2+ xil hujum turi bajarsa:
```
185.220.101.47: Credential Stuffing → Anonymizer
```

**2. Multi-IP Campaign** — turli IP'lar koordinatsiyali, har bosqich oldingi bosqich tugagandan 3 soat ichida boshlanadi:
```
185.220.101.47 (Germany, TOR)  → Credential Stuffing  09:47–09:53
45.142.212.100  (Moldova)       → SQL Injection        10:15–10:19
194.165.16.8    (Monaco)        → Data Exfiltration    11:02–11:32  →  59.1 MB o'g'irlangan
```

**CRITICAL COMBO** — quyidagi kombinatsiyalar eng xavfli deb belgilanadi:
- SQL Injection + Data Exfiltration
- Credential Stuffing + Data Exfiltration
- Admin Recon + Data Exfiltration

---

## Har bir hujum sessiyasi uchun ko'rsatkichlar

| Ko'rsatkich | Model maydoni |
|---|---|
| Hujum boshlanish vaqti | `start_time` |
| Hujum tugash vaqti | `end_time` |
| Hujum davomiyligi | `duration_seconds` |
| Hujumchi so'rovlari soni | `request_count` |
| Ko'chirilgan ma'lumot hajmi | `total_bytes` |
| Hujumchi mamlakati | `country` (GeoIP) |
| TOR / Proxy | `via_tor`, `via_proxy` |
| Og'irlik balli | `score` |
| Darajasi | `severity` — LOW / MEDIUM / HIGH / CRITICAL |
| MITRE ATT&CK ID | `mitre_id` |

---

## Ishga tushirish

```bash
# 1. Bog'liqliklarni o'rnatish
pip install -r requirements.txt

# 2. Dashboard ishga tushirish
python scripts/run_dashboard.py
# yoki to'g'ridan-to'g'ri:
streamlit run src/soc_analyzer/web/dashboard.py
```

Dashboard `http://localhost:8501` da ochiladi.

---

## Dashboard imkoniyatlari

- **Log yuklash** — o'z log faylingizni yuklang yoki standart faylni ishlating
- **Live Monitor** — `log_streamer.py` orqali log faylni real vaqtda oqitib, har N soniyada tahlilni yangilaydi; fayl tugaganda avtomatik to'xtaydi
- **Hujumlar jadvali** — daraja, hujum turi, davomiylik, payload bo'yicha filtrlash; CSV / JSON eksport
- **IP Detail Panel** — jadvalda IP'ga bosing → o'ng tomonda to'liq ma'lumot: mamlakat, TOR/proxy, barcha sessiyalar, MITRE, oddiy foydalanuvchi bilan taqqoslash
- **Zanjirlar** — ko'p bosqichli hujumlar xronologik tartibda, CRITICAL COMBO belgisi
- **IP Reytingi** — kumulyativ reputation balli bo'yicha barcha hujumchi IP'lar
- **Grafiklar** — Gantt timeline, soatlik faollik, top IP'lar
- **Statistika** — oddiy foydalanuvchi vs hujumchi profili taqqoslash
- **Boshqaruv** — IP'larni Watchlist / Ignore / Block ro'yxatiga qo'shish
- **Endpoints** — login, exfiltration, sensitive endpointlarni sozlash
- **3 til** — O'zbek, Русский, English
- **Mavzu** — Dark / Light

---

## Loyiha tuzilmasi

```
sqb-soc/
├── data/
│   ├── input/                  # log fayllar
│   ├── output/                 # hisobotlar (CSV, JSON)
│   ├── GeoLite2-Country.mmdb   # offline GeoIP bazasi
│   ├── torbulkexitlist.txt     # TOR exit node ro'yxati
│   └── http_proxies.txt        # proxy ro'yxati
├── scripts/
│   ├── run_dashboard.py        # Streamlit launcher
│   ├── log_streamer.py         # live log replay vositasi
│   └── generate_sample_log.py  # test log generator
└── src/soc_analyzer/
    ├── config/                 # threshold, regex, endpoint, scoring
    ├── core/                   # parser, models (AttackSession, IpReputation)
    ├── detectors/              # 7 ta detektor
    ├── analysis/               # engine, reputation, attack_chain, economics
    ├── web/                    # Streamlit dashboard, theme
    └── utils/                  # formatters, ip_utils
```

---

## Live Monitor ishlash prinsipi

```
log_streamer.py  →  _live.txt (o'sib boruvchi fayl)
                         ↓
              Dashboard har N soniyada o'qiydi
                         ↓
              parse_log → AnalysisEngine → UI yangilanadi
                         ↓
              Fayl tugagach → avtomatik to'xtaydi
```

`Speed (ms/line)` — qanchalik tez oqishi; `Refresh (s)` — qanchalik tez yangilanishi.

---

## Talablar

```
Python >= 3.10
pandas >= 2.2.0
streamlit >= 1.32.0
plotly >= 5.20.0
geoip2 >= 4.8
```
