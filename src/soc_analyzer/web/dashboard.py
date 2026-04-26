"""
Streamlit Dashboard — 3 tilda (uz/ru/en), tushunarli UI.

Ishga tushirish:
    python scripts/run_dashboard.py
"""
from __future__ import annotations
import sys
import io
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import plotly.express as px
import streamlit as st

from soc_analyzer.core.parser import parse_log
from soc_analyzer.analysis.engine import AnalysisEngine
from soc_analyzer.analysis.severity_reason import explain_score
from soc_analyzer.i18n import t, severity_label, attack_type_label, LANGUAGES
from soc_analyzer.utils.formatters import format_bytes, format_duration
from soc_analyzer.web import ip_actions
from soc_analyzer.web.theme import get_theme_css, get_plotly_layout, get_plotly_layout_no_axes
from soc_analyzer.config.endpoint_store import (
    load_custom, add_endpoint, remove_endpoint,
    get_defaults, get_merged, CATEGORY_LABELS,
)

# ============================================================
# RANGLAR
# ============================================================
SEVERITY_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH":     "#ff7f0e",
    "MEDIUM":   "#bcbd22",
    "LOW":      "#2ca02c",
}

ATTACK_TYPE_COLORS = {
    "credential_stuffing":      "#e74c3c",
    "sql_injection":            "#9b59b6",
    "data_exfiltration":        "#e67e22",
    "anonymizer":               "#34495e",
    "admin_recon":              "#3498db",
    "distributed_fingerprint":  "#16a085",
}


# ============================================================
# YOZLAB OLIB BERUVCHI
# ============================================================
def main():
    st.set_page_config(
        page_title="SQB SOC",
        page_icon="🛡",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # ====== SIDEBAR ======
    with st.sidebar:
        lang = st.selectbox(
            "🌐 " + t("language", "uz") + " / Язык / Language",
            options=list(LANGUAGES.keys()),
            format_func=lambda k: LANGUAGES[k],
            index=0,
            key="lang",
        )
        theme = st.radio(
            "🎨 " + t("theme", lang),
            options=["dark", "light"],
            format_func=lambda x: t(f"theme_{x}", lang),
            horizontal=True,
            key="theme",
        )
        _inject_theme_css(theme)

        st.markdown("---")
        st.markdown("### 📁 " + t("log_file", lang))
        uploaded = st.file_uploader(t("upload_log", lang), type=["txt", "log"])
        use_default = st.checkbox(t("use_default", lang), value=False)

        # ====== LIVE MONITOR ======
        st.markdown("---")
        st.markdown("### 🔴 Live Monitor")
        _live_mode = st.session_state.get("_live_mode", False)
        if _live_mode:
            st.success("● Aktiv", icon="🟢")

        _live_src_map = {
            "default":  ROOT / "data" / "keyes1_nginx_access (1).log",
            "uploaded": ROOT / "data" / "input" / "_uploaded.txt",
        }
        _live_src = st.selectbox(
            "Manba / Source",
            options=list(_live_src_map.keys()),
            format_func=lambda k: "📄 Default log" if k == "default" else "📤 Uploaded log",
            key="live_src_key",
        )
        _live_interval = st.slider("Refresh (s)", 1, 30, 5, key="live_interval_s")
        _live_speed = st.slider("Speed (ms/line)", 10, 1000, 50, key="live_delay_ms")

        _lc1, _lc2 = st.columns(2)
        if _lc1.button("▶ Start", disabled=_live_mode, use_container_width=True, key="live_start"):
            _src_path = _live_src_map[_live_src]
            if not _src_path.exists():
                st.error(f"Fayl topilmadi: {_src_path.name}")
            else:
                # kill existing subprocess
                _old_proc = st.session_state.pop("_live_proc", None)
                if _old_proc:
                    try: _old_proc.kill()
                    except Exception: pass
                _old_fout = st.session_state.pop("_live_fout", None)
                if _old_fout:
                    try: _old_fout.close()
                    except Exception: pass
                _live_log = ROOT / "data" / "input" / "_live.txt"
                _live_log.write_text("")  # truncate
                # Count source lines so we can detect when streaming is done
                try:
                    with open(str(_src_path), encoding="utf-8", errors="replace") as _sf:
                        st.session_state["_live_total_lines"] = sum(1 for _ in _sf)
                except Exception:
                    st.session_state["_live_total_lines"] = 0
                _fout = open(str(_live_log), "a", encoding="utf-8", errors="replace")
                _proc = subprocess.Popen(
                    [sys.executable,
                     str(ROOT / "scripts" / "log_streamer.py"),
                     str(_src_path),
                     "--delay", str(_live_speed / 1000)],
                    stdout=_fout,
                    stderr=subprocess.DEVNULL,
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                )
                st.session_state["_live_proc"] = _proc
                st.session_state["_live_fout"] = _fout
                st.session_state["_live_mode"] = True
                st.session_state["_log_source"] = "live"
                st.session_state.pop("_cached_df", None)
                st.session_state.pop("_cached_result", None)
                # Reset filters so defaults apply cleanly on first live render
                for _fk in ("flt_type", "flt_sev", "flt_dur", "flt_int", "flt_anon",
                             "_panel_ip", "attacks_table"):
                    st.session_state.pop(_fk, None)
                st.rerun()

        if _lc2.button("⏹ Stop", disabled=not _live_mode, use_container_width=True, key="live_stop"):
            _proc = st.session_state.pop("_live_proc", None)
            if _proc:
                try: _proc.kill()
                except Exception: pass
            _fout = st.session_state.pop("_live_fout", None)
            if _fout:
                try: _fout.close()
                except Exception: pass
            st.session_state["_live_mode"] = False
            st.session_state.pop("_log_source", None)
            st.rerun()

    # ====== HEADER ======
    st.title("🛡 " + t("app_title", lang))
    _live_badge_slot = st.empty()  # filled after log_path is resolved

    # ====== LOG FAYLNI YUKLASH ======
    # Track log source in session_state so language/theme changes don't reset the app
    if uploaded is not None:
        file_key = f"{uploaded.name}_{uploaded.size}"
        if st.session_state.get("_file_key") != file_key:
            log_path = ROOT / "data" / "input" / "_uploaded.txt"
            log_path.write_bytes(uploaded.read())
            st.session_state["_file_key"] = file_key
            st.session_state["_log_source"] = "uploaded"
            st.session_state.pop("_cached_df", None)
            st.session_state.pop("_cached_result", None)
        else:
            st.session_state["_log_source"] = "uploaded"
    elif use_default:
        if st.session_state.get("_file_key") != "default":
            st.session_state["_file_key"] = "default"
            st.session_state["_log_source"] = "default"
            st.session_state.pop("_cached_df", None)
            st.session_state.pop("_cached_result", None)
        else:
            st.session_state["_log_source"] = "default"

    log_source = st.session_state.get("_log_source")
    if log_source == "uploaded":
        log_path = ROOT / "data" / "input" / "_uploaded.txt"
    elif log_source == "default":
        log_path = ROOT / "data" / "keyes1_nginx_access (1).log"
        if not log_path.exists():
            st.error(t("default_not_found", lang) + f": {log_path}")
            st.stop()
    elif log_source == "live":
        log_path = ROOT / "data" / "input" / "_live.txt"
        if not log_path.exists():
            log_path.write_text("")
    else:
        st.info(t("upload_or_default", lang))
        st.stop()

    # Fill the header badge slot now that log_path is resolved
    if st.session_state.get("_live_mode"):
        _live_line_count = 0
        try:
            with open(log_path, encoding="utf-8", errors="replace") as _lf:
                _live_line_count = sum(1 for _ in _lf)
        except Exception:
            pass
        _live_badge_slot.markdown(
            f"<span style='background:#ef4444;color:white;padding:4px 12px;"
            f"border-radius:20px;font-weight:700;font-size:13px;'>● LIVE</span>"
            f"&nbsp;&nbsp;<span style='color:#888;font-size:13px;'>{_live_line_count:,} qator · "
            f"har {st.session_state.get('live_interval_s', 5)}s yangilanadi</span>",
            unsafe_allow_html=True,
        )
    else:
        _live_badge_slot.caption(t("app_subtitle", lang))

    if st.session_state.get("_live_mode"):
        # Live mode — always re-parse, no cache
        try:
            df = parse_log(log_path)
            result = AnalysisEngine().analyze(df) if not df.empty else None
        except Exception:
            df = pd.DataFrame()
            result = None
        if result is None or df.empty:
            _line_count = 0
            try:
                with open(log_path, encoding="utf-8", errors="replace") as _f:
                    _line_count = sum(1 for _ in _f)
            except Exception:
                pass
            st.info(f"⏳ Live ma'lumot kutilmoqda... ({_line_count} qator o'qildi)")
            time.sleep(2)
            st.rerun()
    elif "_cached_result" not in st.session_state:
        with st.spinner(t("analyzing", lang)):
            df = parse_log(log_path)
            result = AnalysisEngine().analyze(df)
            st.session_state["_cached_df"] = df
            st.session_state["_cached_result"] = result
    else:
        df = st.session_state["_cached_df"]
        result = st.session_state["_cached_result"]

    # ====== TOP METRIKALAR ======
    # Exclude anonymizer sessions — they share the same IP/bytes as real attack sessions
    total_exfil_bytes = sum(s.total_bytes for s in result.sessions
                            if s.attack_type != "anonymizer")
    estimated_records = result.damage.get("estimated_records", 0)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric(t("total_requests", lang), f"{len(df):,}")
    c2.metric(t("unique_ips", lang), df["ip"].nunique())
    c3.metric(t("attack_sessions", lang), len(result.sessions))
    c4.metric(t("attack_chains", lang), len(result.chains))
    c5.metric(t("data_stolen", lang), format_bytes(total_exfil_bytes),
              f"≈ {estimated_records:,} {t('estimated_records', lang).lower()}")

    st.markdown("---")

    # ====== TABS ======
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "🚨 " + t("tab_attacks", lang),
        "🔗 " + t("tab_chains", lang),
        "👤 " + t("tab_reputation", lang),
        "📈 " + t("tab_statistics", lang),
        "📊 " + t("tab_charts", lang),
        "🛠 " + t("tab_admin_actions", lang),
        "⚙️ Endpoints",
    ])

    with tab1: _render_attacks(result, df, lang, theme)
    with tab2: _render_chains(result, lang)
    with tab3: _render_reputation(result, lang, theme)
    with tab4: _render_statistics(result, lang, theme)
    with tab5: _render_charts(result, df, lang, theme)
    with tab6: _render_admin_actions(lang)
    with tab7: _render_endpoints()

    st.markdown("---")
    st.caption(t("footer", lang))

    # Live mode auto-refresh — runs after all content is rendered
    if st.session_state.get("_live_mode"):
        # Check stop conditions: proc exited OR live file has caught up to source
        _proc = st.session_state.get("_live_proc")
        _proc_done = _proc is not None and _proc.poll() is not None

        _total_lines = st.session_state.get("_live_total_lines", 0)
        _current_lines = 0
        try:
            with open(log_path, encoding="utf-8", errors="replace") as _cf:
                _current_lines = sum(1 for _ in _cf)
        except Exception:
            pass
        _lines_done = _total_lines > 0 and _current_lines >= _total_lines

        if _proc_done or _lines_done:
            _fout = st.session_state.pop("_live_fout", None)
            if _fout:
                try: _fout.close()
                except Exception: pass
            _p = st.session_state.pop("_live_proc", None)
            if _p:
                try: _p.kill()
                except Exception: pass
            st.session_state.pop("_live_total_lines", None)
            st.session_state["_live_mode"] = False
            st.toast("✅ Live stream tugadi — barcha qatorlar o'qildi", icon="🏁")
            st.rerun()
        else:
            time.sleep(st.session_state.get("live_interval_s", 5))
            st.rerun()


# ============================================================
# TAB: HUJUMLAR — 2 ustun: jadval + IP detail panel
# ============================================================
from datetime import timezone, timedelta
_TZ_TASHKENT = timezone(timedelta(hours=5))

def _fmt_dt(dt, fmt="%Y-%m-%d %H:%M") -> str:
    """UTC datetime'ni Toshkent vaqtiga (UTC+5) o'girib formatlaydi."""
    if dt is None:
        return "—"
    try:
        return dt.astimezone(_TZ_TASHKENT).strftime(fmt)
    except Exception:
        return str(dt)


def _session_endpoints(session) -> str:
    """AttackSession evidence'dan hujum qilingan endpoint'larni qaytaradi."""
    ev = session.evidence or {}
    targeted = ev.get("endpoints_targeted", {})
    if not targeted:
        return ""
    top = sorted(targeted.items(), key=lambda x: -x[1])[:3]
    return "  |  ".join(f"{ep} ({cnt})" for ep, cnt in top)


def _session_payloads(session) -> list[str]:
    """AttackSession evidence'dan payload namunalarini qaytaradi."""
    ev = session.evidence or {}
    return ev.get("sample_payloads", [])


def _render_attacks(result, df, lang, theme="dark"):
    if not result.sessions:
        st.subheader(t("attacks_header", lang))
        st.info(t("no_attacks", lang))
        return

    # ===== HEADER + DOWNLOAD SLOTS =====
    h1, h2 = st.columns([3, 2])
    with h1:
        st.subheader(t("attacks_header", lang))
    with h2:
        d1, d2 = st.columns(2)
        download_csv_slot = d1.empty()
        download_json_slot = d2.empty()

    # ===== FILTERS =====
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        all_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        # Live mode: auto-include any new severities
        if st.session_state.get("_live_mode"):
            _saved_sev = st.session_state.get("flt_sev", [])
            _new_sev = [_sv for _sv in all_severities if _sv not in _saved_sev]
            if _new_sev:
                st.session_state["flt_sev"] = _saved_sev + _new_sev
        sev_filter = st.multiselect(
            t("filter_severity", lang),
            options=all_severities,
            default=all_severities,
            format_func=lambda s: severity_label(s, lang),
            key="flt_sev",
        )
    with f2:
        # Anonymizer has its own toggle — keep it out of the main type filter
        all_types = sorted({s.attack_type for s in result.sessions
                            if s.attack_type != "anonymizer"})
        # Live mode: auto-include any newly detected types so they aren't filtered out
        if st.session_state.get("_live_mode"):
            _saved = st.session_state.get("flt_type", [])
            _new = [_tp for _tp in all_types if _tp not in _saved]
            if _new:
                st.session_state["flt_type"] = _saved + _new
        type_filter = st.multiselect(
            t("filter_attack_type", lang),
            options=all_types,
            default=all_types,
            format_func=lambda a: attack_type_label(a, lang),
            key="flt_type",
        )
    with f3:
        dur_choice = st.radio(
            t("filter_duration", lang),
            options=["all", "short", "long"],
            format_func=lambda x: t(f"duration_{x}", lang) if x != "all" else t("duration_all", lang),
            horizontal=True,
            key="flt_dur",
        )
    with f4:
        show_internal = st.checkbox(t("show_internal", lang), value=True, key="flt_int")
        show_anonymizer = st.checkbox("🧅 Anonymizer/Proxy qatorlar", value=False, key="flt_anon")

    # ===== APPLY FILTERS =====
    sessions = result.sessions
    if not show_anonymizer:
        sessions = [s for s in sessions if s.attack_type != "anonymizer"]
    sessions = [s for s in sessions if s.severity in sev_filter]
    sessions = [s for s in sessions if s.attack_type in type_filter]
    if dur_choice == "short":
        sessions = [s for s in sessions if s.duration_seconds < 600]
    elif dur_choice == "long":
        sessions = [s for s in sessions if s.duration_seconds >= 600]
    if not show_internal:
        sessions = [s for s in sessions if not s.is_internal]

    if not sessions:
        st.info(t("no_attacks", lang))
        return

    sessions = sorted(sessions, key=lambda x: -x.score)

    # ===== BUILD TABLE ROWS =====
    rows = []
    for s in sessions:
        action = ip_actions.get_action(s.ip.split(",")[0].strip())
        action_icon = {"watchlist": "👁", "ignore": "🔇", "block": "⛔"}.get(action or "", "")
        anon_badge = "🧅 TOR" if s.via_tor else ("🔀 Proxy" if s.via_proxy else "")
        rot_badge = "🔄" if s.ip_rotation_detected else ""
        endpoints = _session_endpoints(s)
        payloads = _session_payloads(s)
        payload_str = payloads[0][:80] if payloads else ""
        rows.append({
            t("col_severity", lang):     f"{severity_label(s.severity, lang)} ({s.score})",
            t("col_attack_type", lang):  attack_type_label(s.attack_type, lang),
            t("col_ip", lang):           f"{action_icon} {s.ip}".strip(),
            "🌍":                         s.country,
            "Anonymizer":                anon_badge,
            "🔄":                         rot_badge,
            t("col_internal", lang):     "✓" if s.is_internal else "",
            t("col_start", lang):        _fmt_dt(s.start_time),
            t("col_end", lang):          _fmt_dt(s.end_time),
            t("col_duration", lang):     format_duration(s.duration_seconds, lang),
            t("col_requests", lang):     f"{s.request_count:,}",
            "Endpoint":                  endpoints,
            "Payload":                   payload_str,
            t("col_bytes", lang):        f"{s.total_bytes:,}",
        })
    table = pd.DataFrame(rows)
    sev_col = t("col_severity", lang)

    def style_severity(val):
        for sev_key, color in SEVERITY_COLORS.items():
            if val.startswith(severity_label(sev_key, lang)):
                return f"background-color: {color}; color: white; font-weight: bold;"
        return ""

    # ===== LAYOUT: full-width OR table+panel side by side =====
    # _panel_ip is set from the previous rerun; layout is decided before rendering
    panel_ip = st.session_state.get("_panel_ip")

    if panel_ip:
        table_col, detail_col = st.columns([6, 4], gap="medium")
    else:
        table_col = st.container()
        detail_col = None

    with table_col:
        event = st.dataframe(
            table.style.map(style_severity, subset=[sev_col]),
            use_container_width=True,
            height=520,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="attacks_table",
        )
        st.caption(f"📊 {len(sessions)} / {len(result.sessions)}")

        csv_buf = io.StringIO()
        table.to_csv(csv_buf, index=False, encoding="utf-8-sig")
        download_csv_slot.download_button(
            "⬇ CSV", csv_buf.getvalue(), "attacks.csv", "text/csv",
            use_container_width=True,
        )
        json_data = json.dumps([s.to_dict() for s in sessions], indent=2,
                               default=str, ensure_ascii=False)
        download_json_slot.download_button(
            "⬇ JSON", json_data, "attacks.json", "application/json",
            use_container_width=True,
        )

    # ===== PROCESS CLICK: open or switch panel =====
    if event and event.selection and event.selection.rows:
        idx = event.selection.rows[0]
        if idx < len(sessions):
            new_ip = sessions[idx].ip.split(",")[0].strip()
            if new_ip != panel_ip:
                # New IP selected — store and rerun to apply two-column layout
                st.session_state["_panel_ip"] = new_ip
                st.rerun()

    # ===== RIGHT PANEL =====
    if panel_ip and detail_col is not None:
        with detail_col:
            # Panel header: IP + close button
            ph_l, ph_r = st.columns([5, 1])
            with ph_l:
                st.markdown(f"#### 🔍 {panel_ip}")
            with ph_r:
                if st.button("✕", key="close_panel", use_container_width=True):
                    st.session_state.pop("_panel_ip", None)
                    st.session_state.pop("attacks_table", None)
                    st.rerun()
            st.divider()
            _render_ip_detail(panel_ip, result, df, lang, theme)


# ============================================================
# TAB: ZANJIRLAR
# ============================================================
def _render_chains(result, lang):
    st.subheader(t("chains_header", lang))
    if not result.chains:
        st.info(t("no_chains", lang))
        return

    for c in result.chains:
        sev = c["max_severity"]
        emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
        sev_str = severity_label(sev, lang)
        crit_badge = f" ⚠️ **{t('critical_combo', lang)}**" if c["critical_combo"] else ""

        title = (f"{emoji} **{c['ip']}** — {c['stages_count']} "
                 f"{t('stages_count', lang)} [{sev_str}]{crit_badge}")

        with st.expander(title, expanded=c["critical_combo"]):
            st.markdown(
                f"⏱ **{t('col_duration', lang)}:** {format_duration(c['total_duration'], lang)}  ·  "
                f"📨 **{t('col_requests', lang)}:** {c['total_requests']:,}  ·  "
                f"💾 **{t('col_bytes', lang)}:** {format_bytes(c['total_bytes'])}"
            )
            if c.get("chain_type") == "multi_ip_campaign":
                st.caption("🌐 Ko'p IP kampaniyasi — turli manbalardan koordinatsiyali hujum")
            st.markdown(f"**{t('stages_label', lang)}**")
            for i, step in enumerate(c["steps"], 1):
                stage = attack_type_label(step["stage"], lang)
                ip_part = f" · `{step['ip']}`" if c.get("chain_type") == "multi_ip_campaign" else ""
                st.markdown(
                    f"{i}. **{stage}**{ip_part} — `{_fmt_dt(step['start'], '%H:%M:%S')}` → "
                    f"`{_fmt_dt(step['end'], '%H:%M:%S')}` · "
                    f"{format_duration(step['duration'], lang)} · "
                    f"{t('col_requests', lang)}: {step['requests']:,} · "
                    f"{t('col_bytes', lang)}: {format_bytes(step['bytes'])}"
                )


# ============================================================
# TAB: IP REPUTATION
# ============================================================
def _render_reputation(result, lang, theme="dark"):
    st.subheader(t("reputation_header", lang))
    rows = []
    for r in sorted(result.reputation.values(), key=lambda x: -x.score):
        rows.append({
            t("col_ip", lang):         r.ip,
            t("col_severity", lang):   f"{severity_label(r.severity, lang)} ({r.score})",
            t("col_internal", lang):   "✓" if r.is_internal else "",
            t("col_requests", lang):   f"{r.total_requests:,}",
            "Breakdown":               ", ".join(f"{k}={v}" for k, v in r.breakdown.items()),
        })
    rdf = pd.DataFrame(rows)
    if rdf.empty:
        st.info(t("no_attacks", lang))
        return

    sev_col = t("col_severity", lang)
    def style_sev(val):
        for sev_key, color in SEVERITY_COLORS.items():
            if val.startswith(severity_label(sev_key, lang)):
                return f"background-color: {color}; color: white; font-weight: bold;"
        return ""

    st.dataframe(
        rdf.style.map(style_sev, subset=[sev_col]),
        use_container_width=True,
        height=500,
        hide_index=True,
    )


# ============================================================
# TAB: STATISTIKA — oddiy user vs hujumchi profili
# ============================================================
def _render_statistics(result, lang, theme="dark"):
    st.subheader(t("stats_header", lang))
    base = getattr(result, "baseline", None) or {}
    normal = base.get("normal", {})
    attacker = base.get("attacker", {})

    # ============== YUQORIDA — 2 KATTA SUMMARY KARTOCHKA ==============
    if theme == "light":
        card_normal_bg  = "#e8f5e9"
        card_attack_bg  = "#fdecea"
        card_normal_txt = "#1b5e20"
        card_attack_txt = "#7f0000"
        fg_sub = "#555"
    else:
        card_normal_bg  = "#1f4d2a"
        card_attack_bg  = "#5c1a1a"
        card_normal_txt = "#2ca02c"
        card_attack_txt = "#ff6b6b"
        fg_sub = "#bbb"

    c1, c2 = st.columns(2, gap="medium")
    with c1:
        st.markdown(
            f"<div style='background:{card_normal_bg}; padding:16px; border-radius:10px; "
            f"border-left:6px solid #2ca02c;'>"
            f"<h3 style='color:{card_normal_txt}; margin:0;'>🟢 {t('stats_normal_user', lang)}</h3>"
            f"<p style='color:{fg_sub}; margin:4px 0 8px 0; font-size:13px;'>"
            f"{t('stats_summary_innocent', lang)}</p>"
            f"<h1 style='color:{card_normal_txt}; margin:0;'>{base.get('normal_ip_count', 0)}</h1>"
            f"<p style='color:{fg_sub}; margin:0; font-size:12px;'>{t('stats_ip_count', lang)}</p>"
            f"</div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"<div style='background:{card_attack_bg}; padding:16px; border-radius:10px; "
            f"border-left:6px solid #d62728;'>"
            f"<h3 style='color:{card_attack_txt}; margin:0;'>🔴 {t('stats_attacker', lang)}</h3>"
            f"<p style='color:{fg_sub}; margin:4px 0 8px 0; font-size:13px;'>"
            f"{t('stats_summary_attacker', lang)}</p>"
            f"<h1 style='color:{card_attack_txt}; margin:0;'>{base.get('attacker_ip_count', 0)}</h1>"
            f"<p style='color:{fg_sub}; margin:0; font-size:12px;'>{t('stats_ip_count', lang)}</p>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # ============== 2 ALOHIDA UCHASTKA ==============
    col_innocent, col_attacker = st.columns(2, gap="large")

    with col_innocent:
        _render_group_block(
            normal,
            base.get("normal_ips", []),
            title=f"🟢 {t('stats_normal_user', lang)}",
            color="#2ca02c",
            empty_msg=t("stats_no_innocents", lang),
            lang=lang,
            theme=theme,
        )

    with col_attacker:
        _render_group_block(
            attacker,
            base.get("attacker_ips", []),
            title=f"🔴 {t('stats_attacker', lang)}",
            color="#d62728",
            empty_msg=t("stats_no_attackers", lang),
            lang=lang,
            theme=theme,
        )


def _render_group_block(profile: dict, ip_list: list, title: str, color: str,
                        empty_msg: str, lang: str, theme: str = "dark"):
    """Bitta guruh (shubhasiz yoki hujumchi) uchun barcha statistika."""
    st.markdown(f"### {title}")

    if not profile or profile.get("total_requests", 0) == 0:
        st.info(empty_msg)
        return

    # 4 metrika
    m1, m2 = st.columns(2)
    m1.metric(t("stats_avg_session", lang),
              format_duration(profile.get("avg_session_duration", 0), lang))
    m2.metric(t("stats_avg_download", lang),
              format_bytes(profile.get("avg_bytes_per_ip", 0)))

    m3, m4 = st.columns(2)
    m3.metric(t("stats_request_rate", lang),
              f"{profile.get('avg_request_rate', 0):.1f}")
    peak = profile.get("peak_hours", [])
    peak_str = ", ".join(f"{h:02d}:00" for h in sorted(peak)) if peak else "—"
    m4.metric(t("stats_active_hours", lang), peak_str)

    # Top endpoint
    if profile.get("top_endpoints"):
        st.markdown(f"**📍 {t('stats_top_endpoints', lang)}**")
        eps = list(profile["top_endpoints"].items())[:7]
        ndf = pd.DataFrame([{"Endpoint": k, "Count": v} for k, v in eps])
        fig = px.bar(ndf, x="Count", y="Endpoint", orientation="h",
                     color_discrete_sequence=[color])
        pl = get_plotly_layout_no_axes(theme)
        fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0),
                          showlegend=False, yaxis=dict(autorange="reversed"),
                          **pl)
        st.plotly_chart(fig, use_container_width=True)

    # User-Agent
    if profile.get("top_user_agents"):
        with st.expander(f"🖥 {t('stats_typical_ua', lang)}"):
            for ua, cnt in profile["top_user_agents"].items():
                st.markdown(f"- `{ua[:70]}` — **{cnt}**")

    # IP ro'yxati
    if ip_list:
        with st.expander(f"📋 IP ro'yxati ({len(ip_list)})"):
            for ip in ip_list[:30]:
                st.markdown(f"- `{ip}`")


# ============================================================
# TAB: GRAFIKLAR
# ============================================================
def _render_charts(result, df, lang, theme="dark"):
    if df.empty:
        return

    pl = get_plotly_layout(theme)

    # Timeline (Gantt)
    st.markdown(f"### ⏱ {t('chart_timeline', lang)}")
    if result.sessions:
        timeline = []
        for s in result.sessions:
            timeline.append({
                "IP": s.ip,
                "Start": s.start_time,
                "Finish": s.end_time,
                "Type": attack_type_label(s.attack_type, lang),
                "Severity": severity_label(s.severity, lang),
            })
        gdf = pd.DataFrame(timeline)
        fig = px.timeline(gdf, x_start="Start", x_end="Finish", y="IP",
                          color="Type", hover_data=["Severity"])
        fig.update_yaxes(autorange="reversed")
        fig.update_layout(height=500, **pl)
        st.plotly_chart(fig, use_container_width=True)

    # Soatlik faollik
    st.markdown(f"### 📊 {t('chart_hourly', lang)}")
    by_hour = df.groupby("hour_local").size().reset_index(name="count")
    fig = px.bar(by_hour, x="hour_local", y="count")
    fig.update_layout(height=350, **pl)
    st.plotly_chart(fig, use_container_width=True)

    # Top IP'lar
    st.markdown(f"### 🌐 {t('chart_top_ips', lang)}")
    by_ip = (df.groupby("ip")
               .agg(requests=("ip", "size"), bytes=("bytes", "sum"))
               .reset_index()
               .sort_values("bytes", ascending=False)
               .head(15))
    by_ip["volume"] = by_ip["bytes"].apply(format_bytes)
    fig = px.bar(by_ip, x="ip", y="bytes", color="requests",
                 hover_data=["volume"])
    fig.update_layout(height=400, **pl)
    st.plotly_chart(fig, use_container_width=True)


# ============================================================
# IP DETAIL PANEL — o'ng tomonda chiqadi
# ============================================================
def _render_ip_detail(ip: str, result, df, lang, theme="dark"):
    rep = result.reputation.get(ip)

    # ===== HEADER KARTOCHKASI =====
    sev_color = SEVERITY_COLORS.get(rep.severity, "#888") if rep else "#888"
    sev_text = severity_label(rep.severity, lang) if rep else "—"
    score = rep.score if rep else 0
    current_action = ip_actions.get_action(ip)
    action_emoji = {"watchlist": "👁", "ignore": "🔇", "block": "⛔"}.get(current_action or "", "")
    action_label = t(f"action_{current_action}", lang) if current_action else t("no_action", lang)

    card_bg  = f"linear-gradient(135deg, {sev_color}18 0%, {'#f8f9fa' if theme == 'light' else '#1a1d24'} 100%)"
    text_col = "#111827" if theme == "light" else "#e6e6e6"
    sub_col  = "#6b7280" if theme == "light" else "#a0a4ad"
    border   = "#e5e7eb" if theme == "light" else "transparent"

    st.markdown(
        f"""
        <div style='background: {card_bg};
                    border-left: 4px solid {sev_color};
                    border: 1px solid {border};
                    padding: 14px 18px; border-radius: 10px; margin-bottom: 14px;'>
            <div style='display:flex; justify-content:space-between; align-items:center; gap:8px;'>
                <div>
                    <div style='font-size:11px; color:{sub_col}; letter-spacing:0.5px;'>IP</div>
                    <div style='font-family:monospace; font-size:18px; font-weight:600; color:{text_col};'>{ip}</div>
                </div>
                <span style='background:{sev_color}; color:white; padding:6px 14px;
                             border-radius:20px; font-size:13px; font-weight:600;
                             white-space:nowrap;'>{sev_text} · {score}</span>
            </div>
            <div style='margin-top:10px; font-size:13px; color:{sub_col};'>
                {action_emoji} <strong style='color:{text_col};'>{t('action_status', lang)}:</strong> {action_label}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ===== ACTIONS — 2x2 compact buttons =====
    a1, a2 = st.columns(2)
    if a1.button(f"👁 {t('action_watchlist', lang)}", key=f"w_{ip}", use_container_width=True):
        ip_actions.set_action(ip, "watchlist"); st.rerun()
    if a2.button(f"🔇 {t('action_ignore', lang)}", key=f"i_{ip}", use_container_width=True):
        ip_actions.set_action(ip, "ignore"); st.rerun()
    a3, a4 = st.columns(2)
    if a3.button(f"⛔ {t('action_block', lang)}", key=f"b_{ip}", use_container_width=True):
        ip_actions.set_action(ip, "block"); st.rerun()
    if a4.button(f"✕ {t('action_clear', lang)}", key=f"c_{ip}", use_container_width=True):
        ip_actions.clear_action(ip); st.rerun()

    # === GeoIP + Anonymizer badges ===
    ip_sessions = [s for s in result.sessions if ip in s.ip.split(",")]
    if ip_sessions:
        primary_session = ip_sessions[0]
        b1, b2 = st.columns(2)
        country = primary_session.country
        if country and country != "Unknown":
            b1.info(f"🌍 **{country}**")
        if primary_session.via_tor:
            b2.error("🧅 **TOR EXIT NODE**")
        elif primary_session.via_proxy:
            b2.warning("🔀 **PROXY**")
        if primary_session.ip_rotation_detected:
            st.warning("🔄 **IP Rotation / VPN**")
        if primary_session.coordinated and primary_session.shared_user_agent:
            st.error(f"🤝 **Koordinatsiyali** — UA: `{primary_session.shared_user_agent}`")

    g = df[df["ip"] == ip]
    if g.empty:
        return

    # === Asosiy ma'lumot — 2 columns to fit narrow panel ===
    total_bytes = int(g["bytes"].sum())
    span = (g["timestamp"].max() - g["timestamp"].min()).total_seconds()

    c1, c2 = st.columns(2)
    c1.metric(t("total_in_log", lang), f"{len(g):,}")
    c2.metric(t("data_stolen", lang), format_bytes(total_bytes))
    st.metric(t("col_duration", lang), format_duration(span, lang))

    st.caption(
        f"⏱ {t('first_request', lang)}: `{_fmt_dt(g['timestamp'].min(), '%Y-%m-%d %H:%M:%S')}`  \n"
        f"{t('last_request', lang)}: `{_fmt_dt(g['timestamp'].max(), '%Y-%m-%d %H:%M:%S')}` (UTC+5 Toshkent)"
    )

    # === Bu IP ning hujum sessiyalari ===
    if ip_sessions:
        st.markdown(f"#### 🚨 {t('what_did_this_ip_do', lang)}")
        for s in sorted(ip_sessions, key=lambda x: x.start_time):
            endpoints = _session_endpoints(s)
            payloads = _session_payloads(s)
            label = (
                f"**{attack_type_label(s.attack_type, lang)}** · "
                f"`{_fmt_dt(s.start_time, '%H:%M:%S')}` → `{_fmt_dt(s.end_time, '%H:%M:%S')}` · "
                f"{s.request_count:,} so'rov · **{s.total_bytes:,} bayt**"
            )
            with st.expander(label, expanded=True):
                if endpoints:
                    st.markdown(f"📍 **Endpoint:** `{endpoints}`")
                if payloads:
                    st.markdown("💉 **Payloadlar:**")
                    for p in payloads:
                        st.code(p, language=None)

    # === Hujum zanjiri ===
    matched_chain = next((c for c in result.chains
                          if ip == c["ip"]
                          or any(step.get("ip") == ip for step in c.get("steps", []))), None)
    if matched_chain:
        st.markdown(f"#### 🔗 {t('attack_chain_label', lang)}")
        chain_str = " → ".join(attack_type_label(s, lang) for s in matched_chain["stage_types"])
        st.info(chain_str)

    # === Severity sababi (Task 6) ===
    if rep and rep.score > 0:
        with st.expander(f"❓ {t('why_this_severity', lang)} — **{rep.score} ball**", expanded=True):
            reasons = explain_score(ip, df, rep, lang)
            for r in reasons:
                st.markdown(f"- {r['text']} → **+{r['points']}**")

    # === Top endpointlar ===
    with st.expander(f"📍 {t('top_endpoints_label', lang)}"):
        top_eps = g["url_path"].value_counts().head(10)
        for ep, cnt in top_eps.items():
            st.markdown(f"- `{ep}` — **{cnt}**")

    # === User-Agent ===
    with st.expander(f"🖥 {t('user_agents_label', lang)}"):
        for ua, cnt in g["user_agent"].value_counts().head(5).items():
            st.markdown(f"- `{ua[:80]}` — **{cnt}**")

    # === HTTP statuslar ===
    with st.expander(f"🔢 {t('status_distribution', lang)}"):
        for s, cnt in g["status"].value_counts().items():
            st.markdown(f"- **{s}** — {cnt}")

    # === Soatlik faollik ===
    with st.expander(f"⏰ {t('hourly_activity_ip', lang)}"):
        hourly = g.groupby("hour_local").size().reset_index(name="count")
        hourly.columns = ["hour", "count"]
        fig = px.bar(hourly, x="hour", y="count")
        fig.update_layout(height=200, margin=dict(l=0, r=0, t=0, b=0),
                          **get_plotly_layout(theme))
        st.plotly_chart(fig, use_container_width=True)

    # === Oddiy bilan taqqoslash (Task 11) ===
    base = getattr(result, "baseline", None) or {}
    normal = base.get("normal", {})
    if normal and normal.get("avg_session_duration"):
        with st.expander(f"📊 {t('vs_normal', lang)}", expanded=True):
            ip_avg_bytes = int(g["bytes"].sum())
            ip_rate = len(g) / max((g["timestamp"].max() - g["timestamp"].min()).total_seconds() / 60, 1)
            ip_top_ep = g["url_path"].mode().iat[0] if not g["url_path"].mode().empty else "—"
            normal_top_ep = list(normal.get("top_endpoints", {}).keys())[:1]
            normal_top_ep = normal_top_ep[0] if normal_top_ep else "—"

            st.markdown(f"| | {t('stats_value_normal', lang)} | {t('stats_value_this_ip', lang)} |")
            st.markdown("|---|---|---|")
            st.markdown(
                f"| {t('stats_avg_session', lang)} "
                f"| {format_duration(normal['avg_session_duration'], lang)} "
                f"| {format_duration(span, lang)} |"
            )
            st.markdown(
                f"| {t('stats_avg_download', lang)} "
                f"| {format_bytes(normal.get('avg_bytes_per_ip', 0))} "
                f"| {format_bytes(ip_avg_bytes)} |"
            )
            st.markdown(
                f"| {t('stats_request_rate', lang)} "
                f"| {normal.get('avg_request_rate', 0):.1f} "
                f"| {ip_rate:.1f} |"
            )
            st.markdown(
                f"| {t('stats_top_endpoints', lang)} "
                f"| `{normal_top_ep}` "
                f"| `{ip_top_ep}` |"
            )

    # === MITRE (texnik tafsilot — Task 4 dan qaytadi) ===
    mitre_ids = sorted({s.mitre_id for s in ip_sessions})
    if mitre_ids:
        st.caption(f"🏷 MITRE ATT&CK: {', '.join(mitre_ids)}")


# ============================================================
# TAB: BOSHQARUV — Watchlist / Ignore / Block ro'yxati
# ============================================================
def _render_admin_actions(lang):
    st.subheader("🛠 " + t("managed_ips", lang))
    all_actions = ip_actions.get_all()

    if not all_actions:
        st.info(t("no_action", lang))
        return

    rows = []
    for ip, info in all_actions.items():
        action = info.get("action", "")
        emoji = {"watchlist": "👁", "ignore": "🔇", "block": "⛔"}.get(action, "")
        rows.append({
            t("col_ip", lang):       ip,
            t("action_status", lang): f"{emoji} {t(f'action_{action}', lang)}",
            t("saved_at", lang):     info.get("set_at", "")[:19],
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # Bulk clear
    if st.button("✕ " + t("action_clear", lang) + " (all)"):
        for ip in list(all_actions.keys()):
            ip_actions.clear_action(ip)
        st.rerun()


def _render_endpoints():
    st.subheader("⚙️ Endpoint sozlamalari")
    st.caption(
        "Bu yerda login, exfiltration, sensitive va boshqa endpoint'larni qo'shish/o'chirish mumkin. "
        "O'zgarishlar keyingi tahlildan boshlab kuchga kiradi."
    )

    custom = load_custom()

    for cat, (label, description) in CATEGORY_LABELS.items():
        st.markdown(f"### {label}")
        st.caption(description)

        defaults = get_defaults(cat)
        custom_list = custom.get(cat, [])
        merged = get_merged(cat)

        col_add, col_info = st.columns([3, 1])
        with col_add:
            new_ep = st.text_input(
                f"Yangi endpoint qo'shing (`/` bilan boshlanishi kerak)",
                key=f"add_input_{cat}",
                placeholder="/api/v2/login",
            )
        with col_info:
            st.metric("Jami", len(merged), f"+{len(custom_list)} custom")

        if st.button(f"➕ Qo'shish", key=f"add_btn_{cat}"):
            if add_endpoint(cat, new_ep):
                st.success(f"✓ `{new_ep}` qo'shildi")
                st.rerun()
            elif not new_ep.startswith("/"):
                st.error("Endpoint `/` bilan boshlanishi kerak")
            else:
                st.warning(f"`{new_ep}` allaqachon mavjud")

        # Table: defaults (non-deletable) + custom (deletable)
        rows = []
        for ep in defaults:
            rows.append({"Endpoint": ep, "Tur": "🔒 Default", "": ""})
        for ep in custom_list:
            rows.append({"Endpoint": ep, "Tur": "✏️ Custom", "": ep})

        if rows:
            df_ep = pd.DataFrame(rows)
            # Show table without delete column for display
            st.dataframe(
                df_ep[["Endpoint", "Tur"]],
                use_container_width=True,
                hide_index=True,
            )
            # Delete buttons only for custom entries
            if custom_list:
                st.markdown("**Custom endpoint'larni o'chirish:**")
                del_cols = st.columns(min(len(custom_list), 4))
                for i, ep in enumerate(custom_list):
                    if del_cols[i % 4].button(f"✕ {ep}", key=f"del_{cat}_{ep}"):
                        remove_endpoint(cat, ep)
                        st.rerun()

        st.markdown("---")


def _inject_theme_css(theme: str):
    """Light/Dark mavzu uchun to'liq qamrovli CSS injektsiyasi."""
    st.markdown(get_theme_css(theme), unsafe_allow_html=True)


if __name__ == "__main__":
    main()
