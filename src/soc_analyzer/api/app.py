"""
FastAPI giriş — REST API (optional).

Production'da web app sifatida ishga tushiradi. SOC platformalari
(SIEM, Splunk va h.k.) bilan integratsiya uchun.

Foydalanish:
    uvicorn soc_analyzer.api.app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations
from pathlib import Path
import tempfile

try:
    from fastapi import FastAPI, UploadFile, File, HTTPException
    from fastapi.responses import JSONResponse
except ImportError:
    FastAPI = None  # FastAPI ixtiyoriy paket; o'rnatilmagan bo'lsa, modul import qilinmaydi

from soc_analyzer.core.parser import parse_log
from soc_analyzer.analysis.engine import AnalysisEngine


if FastAPI is not None:
    app = FastAPI(
        title="SQB SOC Cyberattack Analyzer API",
        version="0.1.0",
        description="Log fayllarni tahlil qilib, hujumlarni JSON formatida qaytaradi.",
    )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/analyze")
    async def analyze(file: UploadFile = File(...)):
        suffix = Path(file.filename or "").suffix or ".txt"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(await file.read())
            tmp_path = Path(tmp.name)
        try:
            df = parse_log(tmp_path)
            result = AnalysisEngine().analyze(df)
        finally:
            tmp_path.unlink(missing_ok=True)

        return JSONResponse({
            "stats": {
                "rows":           len(df),
                "unique_ips":     int(df["ip"].nunique()),
                "sessions":       len(result.sessions),
                "chains":         len(result.chains),
            },
            "sessions": [s.to_dict() for s in result.sessions],
            "chains":   result.chains,
            "damage":   result.damage,
            "reputation": [r.to_dict() for r in result.reputation.values()],
        })
