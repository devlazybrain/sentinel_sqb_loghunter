"""Smoke test — pipeline butun yo'lda ishlay olishini tekshiradi."""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from soc_analyzer.core.parser import parse_log
from soc_analyzer.analysis.engine import AnalysisEngine
from soc_analyzer.utils.ip_utils import is_internal_ip


def test_internal_ip_strict():
    assert is_internal_ip("10.0.0.5") is True
    assert is_internal_ip("192.168.1.1") is True
    assert is_internal_ip("172.16.5.4") is True
    assert is_internal_ip("127.0.0.1") is True
    # RFC5737 dokumentatsiya — internal EMAS
    assert is_internal_ip("198.51.100.20") is False
    assert is_internal_ip("203.0.113.45") is False
    # Tashqi IP'lar
    assert is_internal_ip("91.199.12.77") is False
    assert is_internal_ip("not-an-ip") is False


def test_pipeline_end_to_end():
    log_path = ROOT / "data" / "input" / "web_attack_logs.txt"
    if not log_path.exists():
        return  # data fayl bo'lmasa skip
    df = parse_log(log_path)
    assert len(df) > 0
    result = AnalysisEngine().analyze(df)
    assert isinstance(result.sessions, list)
    assert isinstance(result.reputation, dict)
    # Loglarda 91.199.12.77 da SQLi bor — albatta topilishi kerak
    sqli_attackers = {s.ip for s in result.sessions if s.attack_type == "sql_injection"}
    assert "91.199.12.77" in sqli_attackers
    # Credential stuffing — 185.23.44.12
    stuff_attackers = {s.ip for s in result.sessions if s.attack_type == "credential_stuffing"}
    assert "185.23.44.12" in stuff_attackers


if __name__ == "__main__":
    test_internal_ip_strict()
    print("PASS: test_internal_ip_strict")
    test_pipeline_end_to_end()
    print("PASS: test_pipeline_end_to_end")
    print("\nBarcha smoke testlar muvaffaqiyatli o'tdi.")
