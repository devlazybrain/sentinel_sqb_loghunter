"""
Streamlit Dashboard — 3 tilda (uz/ru/en), tushunarli UI.

Ishga tushirish:
    python scripts/run_dashboard.py
"""
from __future__ import annotations
import sys
import io
import json
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
from soc_analyzer.web.theme import get_theme_css
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

    # ====== HEADER ======
    st.title("🛡 " + t("app_title", lang))
    st.caption(t("app_subtitle", lang))

    # ====== LOG FAYLNI YUKLASH ======
    if uploaded:
        log_path = ROOT / "data" / "input" / "_uploaded.txt"
        log_path.write_bytes(uploaded.read())
    elif use_default:
        log_path = ROOT / "data" / "input" / "web_attack_logs.txt"
        if not log_path.exists():
            st.error(t("default_not_found", lang) + f": {log_path}")
            st.stop()
    else:
        st.info(t("upload_or_default", lang))
        st.stop()

    with st.spinner(t("analyzing", lang)):
        df = parse_log(log_path)
        result = AnalysisEngine().analyze(df)

    # ====== TOP METRIKALAR ======
    total_exfil_bytes = sum(s.total_bytes for s in result.sessions
                            if s.attack_type == "data_exfiltration")
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

    with tab1: _render_attacks(result, df, lang)
    with tab2: _render_chains(result, lang)
    with tab3: _render_reputation(result, lang)
    with tab4: _render_statistics(result, lang)
    with tab5: _render_charts(result, df, lang)
    with tab6: _render_admin_actions(lang)
    with tab7: _render_endpoints()

    st.markdown("---")
    st.caption(t("footer", lang))


# ============================================================
# TAB: HUJUMLAR — 2 ustun: jadval + IP detail panel
# ============================================================
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


def _render_attacks(result, df, lang):
    if not result.sessions:
        st.subheader(t("attacks_header", lang))
        st.info(t("no_attacks", lang))
        return

    # ===== HEADER + DOWNLOAD TOOLBAR (yuqorida o'ngda) =====
    h1, h2 = st.columns([3, 2])
    with h1:
        st.subheader(t("attacks_header", lang))
    with h2:
        # Download tugmalari shu yerda — kichik, simmetrik
        d1, d2 = st.columns(2)
        download_csv_slot = d1.empty()
        download_json_slot = d2.empty()

    # ===== FILTERLAR — 4 ta teng kenglikda =====
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        all_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sev_filter = st.multiselect(
            t("filter_severity", lang),
            options=all_severities,
            default=all_severities,
            format_func=lambda s: severity_label(s, lang),
            key="flt_sev",
        )
    with f2:
        all_types = sorted({s.attack_type for s in result.sessions})
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

    # ===== FILTER QO'LLASH =====
    sessions = result.sessions
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

    # ===== JADVAL VA IP DETAIL =====
    left, right = st.columns([3, 2], gap="medium")

    with left:
        rows = []
        for s in sessions:
            action = ip_actions.get_action(s.ip.split(",")[0].strip())
            action_icon = {"watchlist": "👁", "ignore": "🔇", "block": "⛔"}.get(action or "", "")
            tor_badge = "🧅" if s.via_tor else ""
            rot_badge = "🔄" if s.ip_rotation_detected else ""
            endpoints = _session_endpoints(s)
            payloads = _session_payloads(s)
            payload_str = payloads[0][:80] if payloads else ""
            rows.append({
                t("col_severity", lang):     f"{severity_label(s.severity, lang)} ({s.score})",
                t("col_attack_type", lang):  attack_type_label(s.attack_type, lang),
                t("col_ip", lang):           f"{action_icon} {s.ip}".strip(),
                "🌍":                         s.country,
                "🧅 Tor":                     tor_badge,
                "🔄":                         rot_badge,
                t("col_internal", lang):     "✓" if s.is_internal else "",
                t("col_start", lang):        s.start_time.strftime("%Y-%m-%d %H:%M"),
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

        event = st.dataframe(
            table.style.map(style_severity, subset=[sev_col]),
            use_container_width=True,
            height=560,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="attacks_table",
        )
        st.caption(f"📊 {len(sessions)} / {len(result.sessions)}")

        # Download tugmalarini header'dagi slotlarga joylashtiramiz
        csv_buf = io.StringIO()
        table.to_csv(csv_buf, index=False, encoding="utf-8-sig")
        download_csv_slot.download_button(
            "⬇ CSV", csv_buf.getvalue(),
            "attacks.csv", "text/csv",
            use_container_width=True,
        )
        json_data = json.dumps([s.to_dict() for s in sessions], indent=2,
                               default=str, ensure_ascii=False)
        download_json_slot.download_button(
            "⬇ JSON", json_data,
            "attacks.json", "application/json",
            use_container_width=True,
        )

    with right:
        selected_idx = None
        if event and event.selection and event.selection.rows:
            selected_idx = event.selection.rows[0]

        if selected_idx is None:
            st.markdown(
                f"<div style='padding:20px; text-align:center; "
                f"border:2px dashed var(--border, #444); border-radius:12px; "
                f"min-height:560px; display:flex; align-items:center; "
                f"justify-content:center; flex-direction:column;'>"
                f"<h2 style='margin:0; opacity:0.4;'>👆</h2>"
                f"<p style='opacity:0.6; margin-top:10px;'>{t('select_ip_hint', lang)}</p>"
                f"</div>",
                unsafe_allow_html=True,
            )
        else:
            selected_session = sessions[selected_idx]
            selected_ip = selected_session.ip.split(",")[0].strip()
            _render_ip_detail(selected_ip, result, df, lang)


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
                    f"{i}. **{stage}**{ip_part} — `{step['start']:%H:%M:%S}` → "
                    f"`{step['end']:%H:%M:%S}` · "
                    f"{format_duration(step['duration'], lang)} · "
                    f"{t('col_requests', lang)}: {step['requests']:,} · "
                    f"{t('col_bytes', lang)}: {format_bytes(step['bytes'])}"
                )


# ============================================================
# TAB: IP REPUTATION
# ============================================================
def _render_reputation(result, lang):
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
def _render_statistics(result, lang):
    st.subheader(t("stats_header", lang))
    base = getattr(result, "baseline", None) or {}
    normal = base.get("normal", {})
    attacker = base.get("attacker", {})

    # ============== YUQORIDA — 2 KATTA SUMMARY KARTOCHKA ==============
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        st.markdown(
            f"<div style='background:#1f4d2a; padding:16px; border-radius:10px; "
            f"border-left:6px solid #2ca02c;'>"
            f"<h3 style='color:#fff; margin:0;'>🟢 {t('stats_normal_user', lang)}</h3>"
            f"<p style='color:#e0e0e0; margin:4px 0 8px 0; font-size:13px;'>"
            f"{t('stats_summary_innocent', lang)}</p>"
            f"<h1 style='color:#2ca02c; margin:0;'>{base.get('normal_ip_count', 0)}</h1>"
            f"<p style='color:#bbb; margin:0; font-size:12px;'>{t('stats_ip_count', lang)}</p>"
            f"</div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"<div style='background:#5c1a1a; padding:16px; border-radius:10px; "
            f"border-left:6px solid #d62728;'>"
            f"<h3 style='color:#fff; margin:0;'>🔴 {t('stats_attacker', lang)}</h3>"
            f"<p style='color:#e0e0e0; margin:4px 0 8px 0; font-size:13px;'>"
            f"{t('stats_summary_attacker', lang)}</p>"
            f"<h1 style='color:#ff6b6b; margin:0;'>{base.get('attacker_ip_count', 0)}</h1>"
            f"<p style='color:#bbb; margin:0; font-size:12px;'>{t('stats_ip_count', lang)}</p>"
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
        )

    with col_attacker:
        _render_group_block(
            attacker,
            base.get("attacker_ips", []),
            title=f"🔴 {t('stats_attacker', lang)}",
            color="#d62728",
            empty_msg=t("stats_no_attackers", lang),
            lang=lang,
        )


def _render_group_block(profile: dict, ip_list: list, title: str, color: str,
                        empty_msg: str, lang: str):
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
        fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0),
                          showlegend=False, yaxis=dict(autorange="reversed"))
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
def _render_charts(result, df, lang):
    if df.empty:
        return

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
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)

    # Soatlik faollik
    st.markdown(f"### 📊 {t('chart_hourly', lang)}")
    by_hour = df.groupby("hour_local").size().reset_index(name="count")
    fig = px.bar(by_hour, x="hour_local", y="count")
    fig.update_layout(height=350)
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
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)


# ============================================================
# IP DETAIL PANEL — o'ng tomonda chiqadi
# ============================================================
def _render_ip_detail(ip: str, result, df, lang):
    rep = result.reputation.get(ip)

    # ===== HEADER KARTOCHKASI =====
    sev_color = SEVERITY_COLORS.get(rep.severity, "#888") if rep else "#888"
    sev_text = severity_label(rep.severity, lang) if rep else "—"
    score = rep.score if rep else 0
    current_action = ip_actions.get_action(ip)
    action_emoji = {"watchlist": "👁", "ignore": "🔇", "block": "⛔"}.get(current_action or "", "")
    action_label = t(f"action_{current_action}", lang) if current_action else t("no_action", lang)

    st.markdown(
        f"""
        <div style='background: linear-gradient(135deg, {sev_color}22 0%, transparent 100%);
                    border-left: 4px solid {sev_color};
                    padding: 14px 18px; border-radius: 10px; margin-bottom: 14px;'>
            <div style='display:flex; justify-content:space-between; align-items:center; gap:8px;'>
                <div>
                    <div style='font-size:11px; opacity:0.7; letter-spacing:0.5px;'>IP</div>
                    <div style='font-family:monospace; font-size:18px; font-weight:600;'>{ip}</div>
                </div>
                <span style='background:{sev_color}; color:white; padding:6px 14px;
                             border-radius:20px; font-size:13px; font-weight:600;
                             white-space:nowrap;'>{sev_text} · {score}</span>
            </div>
            <div style='margin-top:10px; font-size:13px; opacity:0.8;'>
                {action_emoji} <strong>{t('action_status', lang)}:</strong> {action_label}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ===== ACTIONS — kichik, kompakt tugmalar =====
    a1, a2, a3, a4 = st.columns(4)
    if a1.button("👁", key=f"w_{ip}", use_container_width=True,
                 help=t("action_watchlist", lang)):
        ip_actions.set_action(ip, "watchlist"); st.rerun()
    if a2.button("🔇", key=f"i_{ip}", use_container_width=True,
                 help=t("action_ignore", lang)):
        ip_actions.set_action(ip, "ignore"); st.rerun()
    if a3.button("⛔", key=f"b_{ip}", use_container_width=True,
                 help=t("action_block", lang)):
        ip_actions.set_action(ip, "block"); st.rerun()
    if a4.button("✕", key=f"c_{ip}", use_container_width=True,
                 help=t("action_clear", lang)):
        ip_actions.clear_action(ip); st.rerun()

    # === GeoIP + Tor badges ===
    ip_sessions = [s for s in result.sessions if ip in s.ip.split(",")]
    if ip_sessions:
        primary_session = ip_sessions[0]
        badge_cols = st.columns(3)
        country = primary_session.country
        if country and country != "Unknown":
            badge_cols[0].info(f"🌍 **{country}**")
        if primary_session.via_tor:
            badge_cols[1].error("🧅 **TOR EXIT NODE**")
        if primary_session.ip_rotation_detected:
            badge_cols[2].warning("🔄 **IP ROTATION / VPN**")
        if primary_session.coordinated and primary_session.shared_user_agent:
            st.warning(f"🤝 **Koordinatsiyali hujum** — ortaq UA: `{primary_session.shared_user_agent}`")

    g = df[df["ip"] == ip]
    if g.empty:
        return

    # === Asosiy ma'lumot ===
    c1, c2, c3 = st.columns(3)
    c1.metric(t("total_in_log", lang), f"{len(g):,}")
    c2.metric(t("data_stolen", lang), f"{int(g['bytes'].sum()):,} bayt")
    span = (g["timestamp"].max() - g["timestamp"].min()).total_seconds()
    c3.metric(t("col_duration", lang), format_duration(span, lang))

    st.caption(
        f"⏱ {t('first_request', lang)}: `{g['timestamp'].min():%Y-%m-%d %H:%M:%S}`  ·  "
        f"{t('last_request', lang)}: `{g['timestamp'].max():%Y-%m-%d %H:%M:%S}`"
    )

    # === Bu IP ning hujum sessiyalari ===
    if ip_sessions:
        st.markdown(f"#### 🚨 {t('what_did_this_ip_do', lang)}")
        for s in sorted(ip_sessions, key=lambda x: x.start_time):
            endpoints = _session_endpoints(s)
            payloads = _session_payloads(s)
            label = (
                f"**{attack_type_label(s.attack_type, lang)}** · "
                f"`{s.start_time:%H:%M:%S}` → `{s.end_time:%H:%M:%S}` · "
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
        fig.update_layout(height=200, margin=dict(l=0, r=0, t=0, b=0))
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
