"""
SQLi pattern'lari va bot User-Agent imzolari.

Pattern'lar case-insensitive, encoded va decoded ikkala holatda tekshiriladi.
"""

# SQL Injection pattern'lari
SQLI_PATTERNS = [
    r"union\s+select",
    r"%20union%20select",
    r"or\s+1\s*=\s*1",
    r"%27\s*or\s*%271",
    r"'\s*or\s*'1'\s*=\s*'1",
    r"--(?:\s|$)",
    r";\s*drop\s+table",
    r"information_schema",
    r"sleep\s*\(\s*\d+\s*\)",
    r"benchmark\s*\(",
    r"xp_cmdshell",
    r"%27",
    r"\bselect\s+.+\s+from\b",
    r"waitfor\s+delay",
    r"concat\s*\(",
    r"load_file\s*\(",
    r"into\s+outfile",
]

# Bot / anonymizer User-Agent imzolari
BOT_USER_AGENTS = [
    r"sqlmap",
    r"^curl/",
    r"python-requests",
    r"PostmanRuntime",
    r"nikto",
    r"nmap",
    r"masscan",
    r"wget",
    r"go-http-client",
    r"libwww-perl",
    r"scrapy",
]

# Tor Browser imzosi (versiyaga pinned UA)
TOR_UA_PATTERN = r"Mozilla/5\.0 \([^)]+; rv:\d+\.0\) Gecko/20100101 Firefox/\d+\.0$"

# Real foydalanuvchi UA pattern'lari (oq ro'yxat)
LEGITIMATE_UA_PATTERNS = [
    r"Mozilla/5\.0.*iPhone",
    r"Mozilla/5\.0.*Windows.*Chrome",
    r"Mozilla/5\.0.*Macintosh",
    r"Mozilla/5\.0.*Android",
]
