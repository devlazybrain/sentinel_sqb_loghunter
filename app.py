"""
app.py — Streamlit dashboard for SQB LogHunter.

Run:  streamlit run app.py
"""

from __future__ import annotations

import io

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer import build_attack_chain, build_attack_sessions
from detectors import run_all
from enrichment import enrich_all
from parser import parse_file
from report import to_csv_string, to_dataframe

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SQB LogHunter",
    page_icon="🛡️",
    layout="wide",
)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <h1 style='text-align:center; color:#e63946;'>🛡️ SQB LogHunter</h1>
    <p style='text-align:center; color:#aaa; font-size:16px;'>
        Cybersecurity Log Analysis · SQB Mobile Internet-Banking
    </p>
    <hr style='border-color:#333;'>
    """,
    unsafe_allow_html=True,
)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")
    use_sample = st.checkbox("Use bundled sample log", value=True)
    uploaded   = None
    if not use_sample:
        uploaded = st.file_uploader(
            "Upload Nginx / backend log (.txt, .log)",
            type=["txt", "log"],
        )
    st.divider()
    st.markdown("**Detection thresholds**")
    st.caption("These match SOC-tunable constants in detectors.py")
    st.markdown("- Cred. stuffing per-IP: **10 fails / 60 s**")
    st.markdown("- Distributed CS: **30 fails / 5 min** across IPs")
    st.markdown("- SQLi: **≥ 3 pattern hits** per IP")
    st.markdown("- Exfiltration: **≥ 3 × 1 MB** responses / 5 min")
    st.divider()
    run_btn = st.button("🔍 Run Detection", type="primary", use_container_width=True)

# ── Main area placeholder ─────────────────────────────────────────────────────
if not run_btn:
    st.info("Configure the log source in the sidebar, then click **Run Detection**.")
    st.stop()

# ── Load log ──────────────────────────────────────────────────────────────────
with st.spinner("Parsing log file …"):
    if use_sample:
        df_log = parse_file("web_attack_logs.txt")
        log_label = "web_attack_logs.txt (bundled sample)"
    elif uploaded is not None:
        df_log = parse_file(io.BytesIO(uploaded.read()))
        log_label = uploaded.name
    else:
        st.error("Please upload a log file or enable the bundled sample.")
        st.stop()

# ── Run detectors ─────────────────────────────────────────────────────────────
with st.spinner("Running attack detectors …"):
    raw      = run_all(df_log)
    sessions = build_attack_sessions(raw)
    sessions = enrich_all(sessions)
    chain    = build_attack_chain(sessions)

# ── Top stats bar ─────────────────────────────────────────────────────────────
st.success(f"Analysis complete — **{log_label}**")
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Log Entries",    f"{len(df_log):,}")
col2.metric("Time Range",
            f"{df_log['timestamp'].min().strftime('%H:%M')} – "
            f"{df_log['timestamp'].max().strftime('%H:%M')} UTC")
col3.metric("Unique IPs",     df_log["ip"].nunique())
col4.metric("Attacks Found",  len(sessions))
total_mb = sum(s["total_bytes"] for s in sessions) / (1024 * 1024)
col5.metric("Total Data at Risk", f"{total_mb:.1f} MB")

st.divider()

# ── Attack chain ──────────────────────────────────────────────────────────────
st.subheader("🔗 Attack Chain Timeline")
st.code(chain, language="")

st.divider()

# ── Results table ─────────────────────────────────────────────────────────────
st.subheader("📋 Detected Attack Sessions")

if not sessions:
    st.warning("No attacks detected in this log file.")
else:
    report_df = to_dataframe(sessions)

    # Colour-code attack type column
    def style_attack(val: str) -> str:
        colours = {
            "Credential Stuffing":             "background-color:#7c1a1a; color:#fff",
            "Distributed Credential Stuffing": "background-color:#7c3a00; color:#fff",
            "SQL Injection":                   "background-color:#1a3a7c; color:#fff",
            "Data Exfiltration":               "background-color:#1a6b1a; color:#fff",
        }
        return colours.get(val, "")

    styled = report_df.style.map(style_attack, subset=["attack_type"])
    st.dataframe(styled, use_container_width=True, hide_index=True)

    # Download CSV
    csv_bytes = to_csv_string(sessions).encode("utf-8")
    st.download_button(
        label="⬇️ Download CSV Report",
        data=csv_bytes,
        file_name="sqb_attack_report.csv",
        mime="text/csv",
    )

st.divider()

# ── Charts ────────────────────────────────────────────────────────────────────
if sessions:
    st.subheader("📊 Attack Analytics")
    chart_col1, chart_col2 = st.columns(2)

    chart_df = to_dataframe(sessions).copy()
    chart_df["total_mb"] = (
        pd.to_numeric(chart_df["total_bytes"], errors="coerce") / (1024 * 1024)
    ).round(2)

    with chart_col1:
        fig_req = px.bar(
            chart_df,
            x="attack_type",
            y="num_requests",
            color="attack_type",
            text="num_requests",
            title="Requests per Attack Type",
            labels={"num_requests": "Requests", "attack_type": "Attack"},
            color_discrete_map={
                "Credential Stuffing":             "#e63946",
                "Distributed Credential Stuffing": "#f4a261",
                "SQL Injection":                   "#457b9d",
                "Data Exfiltration":               "#2a9d8f",
            },
        )
        fig_req.update_traces(textposition="outside")
        fig_req.update_layout(showlegend=False, plot_bgcolor="#0e1117",
                              paper_bgcolor="#0e1117", font_color="#fff")
        st.plotly_chart(fig_req, use_container_width=True)

    with chart_col2:
        fig_bytes = px.bar(
            chart_df,
            x="attack_type",
            y="total_mb",
            color="attack_type",
            text="total_mb",
            title="Data Volume per Attack (MB)",
            labels={"total_mb": "MB", "attack_type": "Attack"},
            color_discrete_map={
                "Credential Stuffing":             "#e63946",
                "Distributed Credential Stuffing": "#f4a261",
                "SQL Injection":                   "#457b9d",
                "Data Exfiltration":               "#2a9d8f",
            },
        )
        fig_bytes.update_traces(textposition="outside",
                                texttemplate="%{text:.1f} MB")
        fig_bytes.update_layout(showlegend=False, plot_bgcolor="#0e1117",
                                paper_bgcolor="#0e1117", font_color="#fff")
        st.plotly_chart(fig_bytes, use_container_width=True)

    # Timeline scatter: requests over time coloured by attack
    st.subheader("🕐 Request Timeline by Attack")
    attack_ips = {s["attacker_ip"].split(",")[0].strip() for s in sessions}
    timeline_df = df_log[df_log["ip"].isin(attack_ips)].copy()
    # Annotate each row with its attack type
    ip_to_type: dict[str, str] = {}
    for s in sessions:
        for ip in (s.get("involved_ips") or [s["attacker_ip"]]):
            ip_to_type[ip.strip()] = s["attack_type"]
    timeline_df["detected_attack"] = timeline_df["ip"].map(ip_to_type).fillna("Other")
    timeline_df["mb"] = (timeline_df["bytes"] / (1024 * 1024)).round(3)

    fig_time = px.scatter(
        timeline_df,
        x="timestamp",
        y="ip",
        color="detected_attack",
        size="mb",
        size_max=20,
        hover_data=["method", "url", "status", "bytes"],
        title="Attacker Requests Over Time (bubble size = response size)",
        color_discrete_map={
            "Credential Stuffing":             "#e63946",
            "Distributed Credential Stuffing": "#f4a261",
            "SQL Injection":                   "#457b9d",
            "Data Exfiltration":               "#2a9d8f",
            "Other":                           "#aaa",
        },
    )
    fig_time.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117",
                           font_color="#fff", height=400)
    st.plotly_chart(fig_time, use_container_width=True)

st.divider()

# ── Detailed per-attack breakdown ─────────────────────────────────────────────
st.subheader("🔎 Detailed Session Breakdown")
for s in sorted(sessions, key=lambda x: x["start_time"]):
    attack_icons = {
        "Credential Stuffing":             "🔐",
        "Distributed Credential Stuffing": "🌐",
        "SQL Injection":                   "💉",
        "Data Exfiltration":               "📤",
    }
    icon = attack_icons.get(s["attack_type"], "⚠️")
    with st.expander(
        f"{icon} {s['attack_type']} — {s['attacker_ip']} "
        f"({s['start_time'].strftime('%H:%M:%S')} UTC)"
    ):
        info_col, flag_col = st.columns([3, 1])
        with info_col:
            st.markdown(f"**Attacker IP:** `{s['attacker_ip']}`")
            st.markdown(f"**Country:** {s.get('country', 'Unknown')}")
            st.markdown(
                f"**Time:** {s['start_time'].strftime('%H:%M:%S')} → "
                f"{s['end_time'].strftime('%H:%M:%S')} UTC"
            )
            st.markdown(f"**Duration:** {s['duration_seconds']} seconds")
            st.markdown(f"**Requests:** {s['num_requests']:,}")
            mb = s["total_bytes"] / (1024 * 1024)
            st.markdown(f"**Total Bytes:** {s['total_bytes']:,} ({mb:.2f} MB)")
            if s.get("sample_payloads"):
                st.markdown("**Sample Payloads:**")
                for p in s["sample_payloads"]:
                    st.code(p, language="")
        with flag_col:
            if s.get("via_tor"):
                st.error("🧅 TOR EXIT NODE")
            if s.get("ip_rotation_detected"):
                st.warning("🔄 IP ROTATION / VPN")
            if s.get("coordinated"):
                st.warning(f"🤝 COORDINATED\nUA: `{s.get('shared_user_agent','?')}`")
            involved = s.get("involved_ips", [])
            if isinstance(involved, list) and len(involved) > 1:
                st.info(f"**{len(involved)} IPs involved:**\n" +
                        "\n".join(f"• {ip}" for ip in involved[:10]))
