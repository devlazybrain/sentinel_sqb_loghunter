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
    "bg":              "#f0f2f6",
    "bg_secondary":    "#e4e7ed",
    "bg_card":         "#ffffff",
    "bg_hover":        "#dde1e8",
    "border":          "#c8cdd6",
    "fg":              "#111827",
    "fg_secondary":    "#374151",
    "fg_muted":        "#6b7280",
    "accent":          "#dc2626",
    "accent_hover":    "#b91c1c",
    "success":         "#16a34a",
    "warning":         "#d97706",
    "info":            "#2563eb",
    "shadow":          "0 2px 8px rgba(0,0,0,0.10)",
    "shadow_hover":    "0 4px 16px rgba(0,0,0,0.16)",
}

# Plotly chart layout kwargs per theme
PLOTLY_THEME = {
    "dark": {
        "paper_bgcolor": "#1e2129",
        "plot_bgcolor":  "#1e2129",
        "font_color":    "#e6e6e6",
        "gridcolor":     "#2d3139",
    },
    "light": {
        "paper_bgcolor": "#ffffff",
        "plot_bgcolor":  "#f8f9fa",
        "font_color":    "#111827",
        "gridcolor":     "#dee2e6",
    },
}


def get_plotly_layout(theme: str) -> dict:
    t = PLOTLY_THEME.get(theme, PLOTLY_THEME["dark"])
    return dict(
        paper_bgcolor=t["paper_bgcolor"],
        plot_bgcolor=t["plot_bgcolor"],
        font=dict(color=t["font_color"]),
        xaxis=dict(gridcolor=t["gridcolor"], linecolor=t["gridcolor"]),
        yaxis=dict(gridcolor=t["gridcolor"], linecolor=t["gridcolor"]),
    )


def get_plotly_layout_no_axes(theme: str) -> dict:
    """Same as get_plotly_layout but without xaxis/yaxis — use when the
    caller sets its own yaxis/xaxis kwargs to avoid duplicate keyword errors."""
    t = PLOTLY_THEME.get(theme, PLOTLY_THEME["dark"])
    return dict(
        paper_bgcolor=t["paper_bgcolor"],
        plot_bgcolor=t["plot_bgcolor"],
        font=dict(color=t["font_color"]),
    )


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
    .stMultiSelect [data-baseweb="select"],
    .stMultiSelect [data-baseweb="select"] > div,
    .stMultiSelect [class*="valueContainer"],
    .stMultiSelect [class*="placeholder"],
    .stMultiSelect [data-baseweb="select"] input {{
        background-color: {bg_card} !important;
        color: {fg} !important;
        border-color: {border} !important;
    }}
    .stMultiSelect [data-baseweb="select"] {{
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
    .stMultiSelect [data-baseweb="select"] svg {{
        fill: {fg_secondary} !important;
    }}

    /* ============ SELECTBOX ============ */
    .stSelectbox [data-baseweb="select"],
    .stSelectbox [data-baseweb="select"] > div,
    .stSelectbox [data-baseweb="select"] [data-baseweb="select-control"],
    .stSelectbox [class*="valueContainer"],
    .stSelectbox [class*="singleValue"],
    .stSelectbox [class*="placeholder"],
    .stSelectbox [class*="indicatorContainer"],
    .stSelectbox [data-baseweb="select"] input {{
        background-color: {bg_card} !important;
        color: {fg} !important;
        border-color: {border} !important;
    }}
    .stSelectbox [data-baseweb="select"] {{
        border: 1px solid {border} !important;
        border-radius: 8px !important;
    }}
    .stSelectbox [data-baseweb="select"] svg {{
        fill: {fg_secondary} !important;
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
    [data-testid="stFileUploader"] section,
    [data-testid="stFileUploader"] > div,
    [data-testid="stFileUploaderDropzone"],
    [data-testid="stFileUploaderDropzone"] > div {{
        background-color: {bg_card} !important;
        color: {fg} !important;
    }}
    [data-testid="stFileUploader"] button,
    [data-testid="stFileUploaderDropzone"] button {{
        background-color: {bg_secondary} !important;
        color: {fg} !important;
        border: 1px solid {border} !important;
        border-radius: 6px !important;
    }}
    [data-testid="stFileUploader"] small,
    [data-testid="stFileUploader"] span {{
        color: {fg_muted} !important;
    }}

    /* ============ EXPANDER ============ */
    [data-testid="stExpander"] {{
        background-color: {bg_card} !important;
        border: 1px solid {border} !important;
        border-radius: 10px !important;
        margin-bottom: 8px !important;
        box-shadow: {shadow};
    }}
    [data-testid="stExpander"] details summary,
    [data-testid="stExpander"] > div > div > div > button {{
        background-color: {bg_card} !important;
        color: {fg} !important;
        font-weight: 500 !important;
        padding: 12px 16px !important;
    }}
    [data-testid="stExpander"] details summary:hover,
    [data-testid="stExpander"] > div > div > div > button:hover {{
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

    /* ============ SELECTBOX / DROPDOWN MENU ============ */
    [data-baseweb="popover"] [data-baseweb="menu"] {{
        background-color: {bg_card} !important;
        border: 1px solid {border} !important;
    }}
    [data-baseweb="popover"] [role="option"] {{
        color: {fg} !important;
        background-color: {bg_card} !important;
    }}
    [data-baseweb="popover"] [role="option"]:hover {{
        background-color: {bg_hover} !important;
    }}

    /* ============ CODE BLOCKS ============ */
    .stCodeBlock, pre, code {{
        background-color: {bg_secondary} !important;
        color: {fg} !important;
        border: 1px solid {border} !important;
    }}
</style>
"""
