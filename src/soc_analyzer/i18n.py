"""
i18n — 3 tilda matn (uz / ru / en).

Foydalanish:
    from soc_analyzer.i18n import t, set_lang
    set_lang("uz")
    label = t("attacks_tab")
"""
from __future__ import annotations

LANGUAGES = {
    "uz": "O'zbekcha",
    "ru": "Русский",
    "en": "English",
}

TRANSLATIONS: dict[str, dict[str, str]] = {
    # ===================== Sarlavhalar =====================
    "app_title": {
        "uz": "SQB Mobile Internet-Banking — Kiberhujum Analitikasi",
        "ru": "SQB Mobile Internet-Banking — Аналитика кибератак",
        "en": "SQB Mobile Internet-Banking — Cyberattack Analytics",
    },
    "app_subtitle": {
        "uz": "4 qatlamli SOC detection — qisqa va uzoq muddatli hujumlarni topish",
        "ru": "4-уровневая SOC-детекция — обнаружение коротких и длительных атак",
        "en": "4-layer SOC detection — short-term and long-term attacks",
    },
    # ===================== Sidebar =====================
    "language": {"uz": "Til", "ru": "Язык", "en": "Language"},
    "theme": {"uz": "Mavzu", "ru": "Тема", "en": "Theme"},
    "theme_dark": {"uz": "Qorong'i", "ru": "Тёмная", "en": "Dark"},
    "theme_light": {"uz": "Yorug'", "ru": "Светлая", "en": "Light"},
    "log_file": {"uz": "Log fayl", "ru": "Лог файл", "en": "Log file"},
    "upload_log": {
        "uz": "Log faylni yuklash",
        "ru": "Загрузить лог-файл",
        "en": "Upload log file",
    },
    "use_default": {
        "uz": "Standart faylni ishlatish",
        "ru": "Использовать файл по умолчанию",
        "en": "Use default file",
    },
    "analyzing": {"uz": "Tahlil qilinmoqda...", "ru": "Анализ...", "en": "Analyzing..."},
    "default_not_found": {
        "uz": "Standart fayl topilmadi",
        "ru": "Файл по умолчанию не найден",
        "en": "Default file not found",
    },
    "upload_or_default": {
        "uz": "Log faylni yuklang yoki standart variantni tanlang.",
        "ru": "Загрузите лог-файл или выберите вариант по умолчанию.",
        "en": "Upload a log file or select the default option.",
    },
    # ===================== Top metrikalar =====================
    "total_requests": {"uz": "Jami so'rov", "ru": "Всего запросов", "en": "Total requests"},
    "unique_ips": {"uz": "Unikal IP", "ru": "Уникальных IP", "en": "Unique IPs"},
    "attack_sessions": {"uz": "Hujum sessiyalari", "ru": "Сессии атак", "en": "Attack sessions"},
    "attack_chains": {"uz": "Hujum zanjirlari", "ru": "Цепочки атак", "en": "Attack chains"},
    "data_stolen": {"uz": "O'g'irlangan ma'lumot", "ru": "Украдено данных", "en": "Data stolen"},
    "estimated_records": {
        "uz": "Taxminiy yozuvlar",
        "ru": "Ориентир. записей",
        "en": "Estimated records",
    },
    # ===================== Tab nomlari =====================
    "tab_attacks": {"uz": "Hujumlar", "ru": "Атаки", "en": "Attacks"},
    "tab_chains": {"uz": "Zanjirlar", "ru": "Цепочки", "en": "Chains"},
    "tab_reputation": {"uz": "IP reytingi", "ru": "Рейтинг IP", "en": "IP reputation"},
    "tab_charts": {"uz": "Grafiklar", "ru": "Графики", "en": "Charts"},
    "tab_statistics": {"uz": "Statistika", "ru": "Статистика", "en": "Statistics"},
    # ===================== Hujumlar tab =====================
    "attacks_header": {
        "uz": "Aniqlangan hujum sessiyalari",
        "ru": "Обнаруженные сессии атак",
        "en": "Detected attack sessions",
    },
    "no_attacks": {
        "uz": "Hujum aniqlanmadi.",
        "ru": "Атак не обнаружено.",
        "en": "No attacks detected.",
    },
    "filter_severity": {"uz": "Daraja:", "ru": "Уровень:", "en": "Severity:"},
    "filter_attack_type": {"uz": "Hujum turi:", "ru": "Тип атаки:", "en": "Attack type:"},
    "filter_duration": {
        "uz": "Davomiylik:",
        "ru": "Длительность:",
        "en": "Duration:",
    },
    "duration_all": {"uz": "Hammasi", "ru": "Все", "en": "All"},
    "duration_short": {
        "uz": "Qisqa muddatli (< 10 daq)",
        "ru": "Короткие (< 10 мин)",
        "en": "Short-term (< 10 min)",
    },
    "duration_long": {
        "uz": "Uzoq muddatli (> 10 daq)",
        "ru": "Длительные (> 10 мин)",
        "en": "Long-term (> 10 min)",
    },
    "show_internal": {
        "uz": "Ichki tarmoq (10.x.x.x) IP'larini ko'rsatish",
        "ru": "Показать IP внутр. сети (10.x.x.x)",
        "en": "Show internal (10.x.x.x) IPs",
    },
    "download_csv": {"uz": "CSV yuklash", "ru": "Скачать CSV", "en": "Download CSV"},
    "download_json": {"uz": "JSON yuklash", "ru": "Скачать JSON", "en": "Download JSON"},
    # ===================== Jadval ustunlari =====================
    "col_severity": {"uz": "Daraja", "ru": "Уровень", "en": "Severity"},
    "col_attack_type": {"uz": "Hujum turi", "ru": "Тип атаки", "en": "Attack type"},
    "col_ip": {"uz": "IP manzil", "ru": "IP адрес", "en": "IP address"},
    "col_internal": {"uz": "Ichki", "ru": "Внутр.", "en": "Internal"},
    "col_start": {"uz": "Boshlanishi", "ru": "Начало", "en": "Start"},
    "col_end": {"uz": "Tugashi", "ru": "Окончание", "en": "End"},
    "col_duration": {"uz": "Davomiyligi", "ru": "Длительность", "en": "Duration"},
    "col_requests": {"uz": "So'rovlar", "ru": "Запросы", "en": "Requests"},
    "col_bytes": {"uz": "Hajm", "ru": "Объём", "en": "Volume"},
    "col_score": {"uz": "Ball", "ru": "Балл", "en": "Score"},
    # ===================== Severity nomlari =====================
    "sev_CRITICAL": {"uz": "KRITIK", "ru": "КРИТИЧЕСКИЙ", "en": "CRITICAL"},
    "sev_HIGH":     {"uz": "YUQORI", "ru": "ВЫСОКИЙ", "en": "HIGH"},
    "sev_MEDIUM":   {"uz": "O'RTACHA", "ru": "СРЕДНИЙ", "en": "MEDIUM"},
    "sev_LOW":      {"uz": "PAST", "ru": "НИЗКИЙ", "en": "LOW"},
    # ===================== Hujum turi nomlari =====================
    "atk_credential_stuffing": {
        "uz": "Login urinishlari (stuffing)",
        "ru": "Перебор паролей (stuffing)",
        "en": "Credential stuffing",
    },
    "atk_sql_injection": {
        "uz": "SQL injection",
        "ru": "SQL-инъекция",
        "en": "SQL injection",
    },
    "atk_data_exfiltration": {
        "uz": "Ma'lumot o'g'irlash",
        "ru": "Утечка данных",
        "en": "Data exfiltration",
    },
    "atk_anonymizer": {
        "uz": "Anonimlashtiruvchi/proxy",
        "ru": "Анонимайзер/прокси",
        "en": "Anonymizer/proxy",
    },
    "atk_admin_recon": {
        "uz": "Admin tekshiruvi (recon)",
        "ru": "Разведка админ-панели",
        "en": "Admin recon",
    },
    "atk_distributed_fingerprint": {
        "uz": "Tarqatilgan hujum (botnet)",
        "ru": "Распределённая атака",
        "en": "Distributed attack",
    },
    # ===================== Zanjirlar tab =====================
    "chains_header": {
        "uz": "Hujum zanjirlari — bir IP'dan ko'p bosqichli hujum",
        "ru": "Цепочки атак — многоступенчатые атаки с одного IP",
        "en": "Attack chains — multi-stage attacks from one IP",
    },
    "no_chains": {
        "uz": "Zanjir aniqlanmadi.",
        "ru": "Цепочки не обнаружены.",
        "en": "No chains detected.",
    },
    "stages_count": {"uz": "bosqich", "ru": "этап(а/ов)", "en": "stages"},
    "critical_combo": {
        "uz": "KRITIK KOMBINATSIYA",
        "ru": "КРИТИЧЕСКАЯ КОМБИНАЦИЯ",
        "en": "CRITICAL COMBO",
    },
    "stages_label": {
        "uz": "Bosqichlar (vaqt tartibida):",
        "ru": "Этапы (по времени):",
        "en": "Stages (chronological):",
    },
    # ===================== Reputation tab =====================
    "reputation_header": {
        "uz": "IP reytingi — kumulyativ shubha balli",
        "ru": "Рейтинг IP — накопительный балл подозрительности",
        "en": "IP reputation — cumulative suspicion score",
    },
    # ===================== Statistika tab =====================
    "stats_header": {
        "uz": "Oddiy foydalanuvchi profili va hujumchi taqqosi",
        "ru": "Профиль обычного пользователя и сравнение с атакующими",
        "en": "Normal user profile vs attackers",
    },
    "stats_active_hours": {
        "uz": "Faol soatlar",
        "ru": "Активные часы",
        "en": "Active hours",
    },
    "stats_avg_session": {
        "uz": "O'rtacha sessiya davomiyligi",
        "ru": "Средняя длительность сессии",
        "en": "Average session duration",
    },
    "stats_top_endpoints": {
        "uz": "Eng ko'p ziyorat etiladigan sahifalar",
        "ru": "Самые посещаемые страницы",
        "en": "Most visited pages",
    },
    "stats_avg_download": {
        "uz": "O'rtacha yuklab olinadigan hajm",
        "ru": "Средний объём загрузки",
        "en": "Average download volume",
    },
    "stats_request_rate": {
        "uz": "Daqiqasiga o'rtacha so'rov",
        "ru": "Запросов в минуту",
        "en": "Requests per minute",
    },
    "stats_typical_ua": {
        "uz": "Tipik qurilmalar (User-Agent)",
        "ru": "Типичные устройства (User-Agent)",
        "en": "Typical devices (User-Agent)",
    },
    "stats_normal_user": {
        "uz": "Shubhasiz foydalanuvchilar",
        "ru": "Невиновные пользователи",
        "en": "Innocent users",
    },
    "stats_attacker": {
        "uz": "Hujumchilar",
        "ru": "Атакующие",
        "en": "Attackers",
    },
    "stats_innocent_short": {"uz": "Shubhasiz", "ru": "Невиновный", "en": "Innocent"},
    "stats_attacker_short": {"uz": "Hujumchi", "ru": "Атакующий", "en": "Attacker"},
    "stats_summary_innocent": {
        "uz": "Tahdid yo'q — bu IP'lar normal mijoz xulqida",
        "ru": "Без угроз — эти IP ведут себя как обычные клиенты",
        "en": "No threats — these IPs behave like normal customers",
    },
    "stats_summary_attacker": {
        "uz": "Aniqlangan hujumchilar (KRITIK yoki YUQORI darajadagi)",
        "ru": "Обнаруженные атакующие (КРИТИЧЕСКОГО или ВЫСОКОГО уровня)",
        "en": "Detected attackers (CRITICAL or HIGH severity)",
    },
    "stats_no_attackers": {
        "uz": "Hozircha hujumchi aniqlanmadi.",
        "ru": "Атакующих пока не обнаружено.",
        "en": "No attackers detected yet.",
    },
    "stats_no_innocents": {
        "uz": "Loglada faqat hujumchi xulqi bor.",
        "ru": "В логе только атакующее поведение.",
        "en": "Log contains only attacker behavior.",
    },
    "stats_ip_count": {"uz": "IP soni", "ru": "Кол-во IP", "en": "IP count"},
    # ===================== Grafiklar tab =====================
    "chart_timeline": {
        "uz": "Hujum vaqt o'qida (Gantt)",
        "ru": "Атаки на временной шкале (Гантт)",
        "en": "Attack timeline (Gantt)",
    },
    "chart_hourly": {
        "uz": "Soatlik faollik (Toshkent vaqti)",
        "ru": "Активность по часам (время Ташкента)",
        "en": "Hourly activity (Tashkent time)",
    },
    "chart_top_ips": {
        "uz": "Top 15 IP — yuborilgan hajm",
        "ru": "Топ 15 IP — отправленный объём",
        "en": "Top 15 IPs — volume",
    },
    # ===================== Davomiylik so'zlari =====================
    "dur_hour":   {"uz": "soat", "ru": "ч",  "en": "h"},
    "dur_minute": {"uz": "daqiqa", "ru": "мин", "en": "m"},
    "dur_second": {"uz": "soniya", "ru": "сек", "en": "s"},
    "dur_day":    {"uz": "kun", "ru": "дн", "en": "d"},
    # ===================== Boshqa =====================
    "show_internal_short": {"uz": "Ichki", "ru": "Внутр.", "en": "Int."},
    "footer": {
        "uz": "TZ talabiga muvofiq: 5 ta majburiy ko'rsatkich (boshlanish, tugash, davomiylik, so'rovlar soni, hajm).",
        "ru": "Соответствует ТЗ: 5 обязательных метрик (начало, окончание, длительность, кол-во запросов, объём).",
        "en": "Per spec: 5 required metrics (start, end, duration, request count, size).",
    },
    # ===================== IP detail paneli =====================
    "select_ip_hint": {
        "uz": "Jadvaldan IP tanlang — bu yerda batafsil ma'lumot chiqadi",
        "ru": "Выберите IP в таблице — здесь появится подробная информация",
        "en": "Select an IP from the table to see details here",
    },
    "ip_details": {"uz": "IP tafsiloti", "ru": "Детали IP", "en": "IP details"},
    "what_did_this_ip_do": {
        "uz": "Bu IP nima qilgan?",
        "ru": "Что делал этот IP?",
        "en": "What did this IP do?",
    },
    "vs_normal": {
        "uz": "Oddiy foydalanuvchi bilan taqqoslash",
        "ru": "Сравнение с обычным пользователем",
        "en": "Comparison with normal user",
    },
    "why_this_severity": {
        "uz": "Nega bu daraja?",
        "ru": "Почему такой уровень?",
        "en": "Why this severity?",
    },
    "top_endpoints_label": {
        "uz": "Eng ko'p ziyorat etilgan manzillar",
        "ru": "Самые посещаемые страницы",
        "en": "Most visited endpoints",
    },
    "user_agents_label": {
        "uz": "Ishlatilgan qurilmalar (User-Agent)",
        "ru": "Использованные устройства (User-Agent)",
        "en": "Devices used (User-Agent)",
    },
    "status_distribution": {
        "uz": "HTTP javob kodlari taqsimoti",
        "ru": "Распределение HTTP-кодов",
        "en": "HTTP status code distribution",
    },
    "hourly_activity_ip": {
        "uz": "Soatlik faollik",
        "ru": "Активность по часам",
        "en": "Hourly activity",
    },
    "attack_chain_label": {
        "uz": "Hujum zanjiri",
        "ru": "Цепочка атаки",
        "en": "Attack chain",
    },
    "actions": {"uz": "Amallar", "ru": "Действия", "en": "Actions"},
    "action_watchlist": {"uz": "Watchlist'ga", "ru": "В watchlist", "en": "Watchlist"},
    "action_ignore":    {"uz": "E'tibor bermaslik", "ru": "Игнорировать", "en": "Ignore"},
    "action_block":     {"uz": "Bloklash", "ru": "Заблокировать", "en": "Block"},
    "action_clear":     {"uz": "Tozalash", "ru": "Сбросить", "en": "Clear"},
    "action_status":    {"uz": "Holati", "ru": "Статус", "en": "Status"},
    "no_action":        {"uz": "Belgilanmagan", "ru": "Не назначен", "en": "Unassigned"},
    "first_request":    {"uz": "Birinchi so'rov", "ru": "Первый запрос", "en": "First request"},
    "last_request":     {"uz": "Oxirgi so'rov", "ru": "Последний запрос", "en": "Last request"},
    "total_in_log":     {"uz": "Loglagi jami", "ru": "Всего в логе", "en": "Total in log"},
    "stats_value_normal": {"uz": "Oddiy", "ru": "Норма", "en": "Normal"},
    "stats_value_this_ip": {"uz": "Bu IP", "ru": "Этот IP", "en": "This IP"},
    "tab_admin_actions": {"uz": "Boshqaruv", "ru": "Управление", "en": "Management"},
    "managed_ips":       {"uz": "Boshqarilayotgan IP'lar", "ru": "Управляемые IP", "en": "Managed IPs"},
    "saved_at":          {"uz": "Saqlangan vaqt", "ru": "Сохранено", "en": "Saved at"},
}


def t(key: str, lang: str = "uz") -> str:
    """Berilgan kalit uchun tarjima qaytaradi."""
    entry = TRANSLATIONS.get(key)
    if not entry:
        return key
    return entry.get(lang) or entry.get("en") or key


def severity_label(severity: str, lang: str = "uz") -> str:
    return t(f"sev_{severity}", lang)


def attack_type_label(atype: str, lang: str = "uz") -> str:
    return t(f"atk_{atype}", lang)
