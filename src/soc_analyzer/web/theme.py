"""
Light va Dark themalar uchun CSS — to'liq qamrovli styling.

Streamlit'ning barcha asosiy elementlari uchun ranglarni belgilaydi:
sidebar, dataframe, buttons, multiselect, expander, metrics, charts va h.k.
"""
from __future__ import annotations


def get_theme_css(theme: str = "dark") -> str:
    """Berilgan theme uchun to'liq CSS qaytaradi."""
    if theme == "light":
        v = LIGHT_VARS
    else:
        v = DARK_VARS
    return BASE_CSS.format(**v)


DARK_VARS = {
    "bg":              "#0e1117",
    "bg_secondary":    "#1a1d24",
    "bg_card":         "#1e2129",
    "bg_hover":        "#262a33",
    "border":          "#2d3139",
    "fg":              "#e6e6e6",
    "fg_secondary":    "#a0a4ad",
    "fg_muted":        "#6c7280",
    "accent":          "#ef4444",
    "accent_hover":    "#dc2626",
    "success":         "#22c55e",
    "warning":         "#f59e0b",
    "info":            "#3b82f6",
    "shadow":          "0 4px 12px rgba(0,0,0,0.4)",
    "shadow_hover":    "0 8px 20px rgba(0,0,0,0.6)",
}

LIGHT_VARS = {
    "bg":              "#fafafa",
    "bg_secondary":    "#f1f3f5",
    "bg_card":         "#ffffff",
    "bg_hover":        "#e9ecef",
    "border":          "#dee2e6",
    "fg":              "#1a1a1a",
    "fg_secondary":    "#495057",
    "fg_muted":        "#868e96",
    "accent":          "#dc2626",
    "accent_hover":    "#b91c1c",
    "success":         "#16a34a",
    "warning":         "#d97706",
    "info":            "#2563eb",
    "shadow":          "0 2px 8px rgba(0,0,0,0.08)",
    "shadow_hover":    "0 4px 16px rgba(0,0,0,0.12)",
}


BASE_CSS = """
<style>
    /* ============ ASOSIY KONTEYNER ============ */
    .stApp {{
        background-color: {bg} !important;
        color: {fg} !important;
    }}

    /* Asosiy markaziy konteynerni stabillashtirish — sidebar yopilganda
       butun sayt emas, faqat sidebar harakatlanishi uchun */
    .main .block-container {{
        max-width: 100% !important;
        padding-top: 1.5rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        transition: none !important;
    }}
    section.main {{
        transition: none !important;
    }}
    /* Sidebar qator yo'q paytida — main content kengayadi, lekin tezkorsiz */
    [data-testid="stAppViewContainer"] {{
        transition: none !important;
    }}

    /* ============ SIDEBAR — O'NG TOMONGA O'TKAZISH ============ */
    [data-testid="stSidebar"] {{
        right: 0 !important;
        left: auto !important;
        background-color: {bg_secondary} !important;
        border-left: 1px solid {border} !important;
        border-right: none !important;
    }}
    [data-testid="stSidebar"] > div {{
        background-color: {bg_secondary} !important;
    }}
    [data-testid="stSidebar"] * {{
        color: {fg} !important;
    }}

    /* Sidebar collapse tugmasi ham o'ngga */
    [data-testid="stSidebarCollapsedControl"] {{
        right: 0 !important;
        left: auto !important;
    }}

    /* Sidebar resize handle */
    [data-testid="stSidebarResizeHandle"] {{
        right: auto !important;
        left: 0 !important;
    }}

    /* ============ HEADER / TOOLBAR ============ */
    [data-testid="stHeader"] {{
        background-color: {bg} !important;
    }}

    /* ============ MATN VA SARLAVHALAR ============ */
    h1, h2, h3, h4, h5, h6,
    .stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown span,
    .stCaption, [data-testid="stCaptionContainer"] {{
        color: {fg} !important;
    }}

    p, span, label {{
        color: {fg} !important;
    }}

    /* ============ METRICS ============ */
    [data-testid="stMetric"] {{
        background-color: {bg_card};
        padding: 16px;
        border-radius: 10px;
        border: 1px solid {border};
        box-shadow: {shadow};
        transition: transform 0.2s, box-shadow 0.2s;
    }}
    [data-testid="stMetric"]:hover {{
        transform: translateY(-2px);
        box-shadow: {shadow_hover};
    }}
    [data-testid="stMetricValue"] {{
        color: {fg} !important;
        font-weight: 700 !important;
    }}
    [data-testid="stMetricLabel"] {{
        color: {fg_secondary} !important;
        font-weight: 500 !important;
        font-size: 13px !important;
    }}
    [data-testid="stMetricDelta"] {{
        color: {fg_muted} !important;
    }}
    [data-testid="stMetricDelta"] svg {{
        fill: {fg_muted} !important;
    }}

    /* ============ TABS ============ */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 4px;
        background-color: transparent;
        border-bottom: 1px solid {border};
    }}
    .stTabs [data-baseweb="tab"] {{
        color: {fg_secondary} !important;
        background-color: transparent !important;
        border-radius: 8px 8px 0 0;
        padding: 10px 16px;
        font-weight: 500;
        transition: all 0.2s;
    }}
    .stTabs [data-baseweb="tab"]:hover {{
        background-color: {bg_hover} !important;
        color: {fg} !important;
    }}
    .stTabs [aria-selected="true"] {{
        color: {accent} !important;
        background-color: {bg_card} !important;
        border-bottom: 2px solid {accent} !important;
    }}

    /* ============ DATAFRAME ============ */
    [data-testid="stDataFrame"] {{
        border-radius: 10px;
        overflow: hidden;
        border: 1px solid {border};
        box-shadow: {shadow};
    }}

    /* Selection checkbox ustunini yashirish — qator bosish bilan tanlanadi */
    [data-testid="stDataFrame"] [role="grid"] > [role="row"] > [role="gridcell"]:first-child,
    [data-testid="stDataFrame"] [role="grid"] > [role="rowgroup"] > [role="row"] > [role="gridcell"]:first-child,
    [data-testid="stDataFrame"] [role="grid"] > [role="row"] > [role="columnheader"]:first-child {{
        max-width: 0 !important;
        width: 0 !important;
        padding: 0 !important;
        border: none !important;
        overflow: hidden !important;
    }}
    /* Qator hover */
    [data-testid="stDataFrame"] [role="row"]:hover {{
        background-color: {bg_hover} !important;
        cursor: pointer !important;
    }}

    /* ============ BUTTONS ============ */
    .stButton > button,
    [data-testid="stDownloadButton"] > button {{
        background-color: {bg_card} !important;
        color: {fg} !important;
        border: 1px solid {border} !important;
        border-radius: 8px !important;
        padding: 8px 16px !important;
        font-weight: 500 !important;
        transition: all 0.2s !important;
        box-shadow: {shadow};
        white-space: nowrap !important;
    }}
    .stButton > button:hover,
    [data-testid="stDownloadButton"] > button:hover {{
        background-color: {bg_hover} !important;
        border-color: {accent} !important;
        transform: translateY(-1px);
        box-shadow: {shadow_hover};
    }}
    .stButton > button:active {{
        transform: translateY(0);
    }}

    /* ============ MULTISELECT ============ */
    .stMultiSelect [data-baseweb="select"] {{
        background-color: {bg_card} !important;
        border: 1px solid {border} !important;
        border-radius: 8px !important;
    }}
    .stMultiSelect [data-baseweb="select"]:hover {{
        border-color: {accent} !important;
    }}
    .stMultiSelect [data-baseweb="tag"] {{
        background-color: {accent} !important;
        color: white !important;
        border-radius: 6px !important;
    }}
    .stMultiSelect [data-baseweb="tag"] svg {{
        fill: white !important;
    }}

    /* ============ SELECTBOX ============ */
    .stSelectbox [data-baseweb="select"] {{
        background-color: {bg_card} !important;
        border: 1px solid {border} !important;
        border-radius: 8px !important;
    }}

    /* ============ RADIO ============ */
    .stRadio [role="radiogroup"] label {{
        background-color: {bg_card};
        padding: 8px 14px;
        border-radius: 8px;
        margin-right: 6px;
        border: 1px solid {border};
        cursor: pointer;
        transition: all 0.2s;
    }}
    .stRadio [role="radiogroup"] label:hover {{
        border-color: {accent};
        background-color: {bg_hover};
    }}

    /* ============ CHECKBOX ============ */
    .stCheckbox label {{
        color: {fg} !important;
    }}

    /* ============ FILE UPLOADER ============ */
    [data-testid="stFileUploader"] {{
        background-color: {bg_card} !important;
        border: 2px dashed {border} !important;
        border-radius: 10px !important;
        padding: 16px !important;
    }}
    [data-testid="stFileUploader"]:hover {{
        border-color: {accent} !important;
    }}
    [data-testid="stFileUploader"] section {{
        background-color: transparent !important;
    }}

    /* ============ EXPANDER ============ */
    [data-testid="stExpander"] {{
        background-color: {bg_card} !important;
        border: 1px solid {border} !important;
        border-radius: 10px !important;
        margin-bottom: 8px !important;
        box-shadow: {shadow};
    }}
    [data-testid="stExpander"] details summary {{
        color: {fg} !important;
        font-weight: 500 !important;
        padding: 12px 16px !important;
    }}
    [data-testid="stExpander"] details summary:hover {{
        background-color: {bg_hover} !important;
    }}
    [data-testid="stExpander"] * {{
        color: {fg} !important;
    }}

    /* ============ ALERT / INFO ============ */
    [data-testid="stAlert"] {{
        background-color: {bg_card} !important;
        border: 1px solid {border} !important;
        border-radius: 10px !important;
        box-shadow: {shadow};
    }}
    [data-testid="stAlert"] * {{
        color: {fg} !important;
    }}

    /* ============ INPUT ============ */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input {{
        background-color: {bg_card} !important;
        color: {fg} !important;
        border: 1px solid {border} !important;
        border-radius: 8px !important;
    }}

    /* ============ PLOTLY GRAFIKLAR ============ */
    .js-plotly-plot .plot-container {{
        background-color: transparent !important;
    }}

    /* ============ DIVIDER ============ */
    hr {{
        border-color: {border} !important;
        opacity: 0.5;
    }}

    /* ============ CUSTOM CARD STYLE ============ */
    .soc-card {{
        background-color: {bg_card};
        border: 1px solid {border};
        border-radius: 12px;
        padding: 16px;
        box-shadow: {shadow};
        margin-bottom: 12px;
    }}

    /* ============ SCROLLBAR ============ */
    ::-webkit-scrollbar {{
        width: 10px;
        height: 10px;
    }}
    ::-webkit-scrollbar-track {{
        background: {bg};
    }}
    ::-webkit-scrollbar-thumb {{
        background: {border};
        border-radius: 5px;
    }}
    ::-webkit-scrollbar-thumb:hover {{
        background: {fg_muted};
    }}

    /* ============ DEEPLINK ICON BUTTON ============ */
    .stDeployButton {{ display: none !important; }}

    /* Top-right toolbar inline button styling */
    div[data-testid="column"] > div[data-testid="stDownloadButton"] > button {{
        padding: 6px 14px !important;
        font-size: 13px !important;
    }}
</style>
"""
