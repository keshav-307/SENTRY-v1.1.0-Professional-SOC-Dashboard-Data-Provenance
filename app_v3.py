"""
SENTRY — Security Monitoring & Threat Detection Platform.

Streamlit dashboard for SENTRY v1.1.0.

Data-origin policy
------------------
Events carry an explicit ``event_origin``:

    SYNTHETIC  produced by SENTRY's event generator
    LIVE       captured from real network traffic
    UNKNOWN    historical rows whose origin cannot be established

The dashboard never infers an origin from an IP address or event type.
"""

import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
import threading

import altair as alt
import pandas as pd
import streamlit as st
from scapy.all import conf

from core.database import SentryDatabase, resolve_database_path
from core.detector import RULE_METADATA, load_rules_config
from core.generator import EventGenerator
from core.pipeline import SentryPipeline
from sensors.network_sensor import NetworkSensor


SENTRY_VERSION = "1.1.0"
DATABASE_PATH = resolve_database_path()

SCENARIOS = {
    "Normal Traffic": "normal",
    "SSH Brute Force": "ssh_brute_force",
    "SQL Injection": "sql_injection",
    "Path Traversal": "path_traversal",
    "Mixed Attack Campaign": "mixed",
}

ORIGIN_OPTIONS = ["All Sources", "Live", "Synthetic", "Unknown"]
ORIGIN_FILTERS = {
    "All Sources": "All",
    "Live": "LIVE",
    "Synthetic": "SYNTHETIC",
    "Unknown": "UNKNOWN",
}

ORIGIN_COLORS = {
    "LIVE": "#34d399",
    "SYNTHETIC": "#22d3ee",
    "UNKNOWN": "#64748b",
}

SEVERITY_COLORS = {
    "CRITICAL": "#f87171",
    "HIGH": "#fb923c",
    "MEDIUM": "#fbbf24",
    "LOW": "#34d399",
}

STATUS_LABELS = {
    "OPEN": "Open",
    "INVESTIGATING": "Investigating",
    "RESOLVED": "Resolved",
    "FALSE_POSITIVE": "False positive",
}

NAV_PAGES = [
    "◈  Security Overview",
    "▣  Live Network Monitoring",
    "△  Alerts & Incidents",
    "◇  Network Activity",
    "☰  Event Explorer",
    "⬡  Synthetic Lab",
    "⊙  Detection Rules",
    "ⓘ  About SENTRY",
]


st.set_page_config(
    page_title="SENTRY — Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =============================================================
# THEME AND LAYOUT
# =============================================================

st.markdown(
    """
    <style>
    :root {
        --bg: #0a111f;
        --panel: #101b2d;
        --panel-soft: #0d1626;
        --border: #1e2c44;
        --border-soft: #17233a;
        --text: #e6eefc;
        --muted: #8ea3c0;
        --accent: #22d3ee;
        --green: #34d399;
        --amber: #fbbf24;
        --orange: #fb923c;
        --red: #f87171;
        --slate: #64748b;
    }

    html, body, [class*="css"] {
        font-family: "Inter", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    .stApp {
        background: var(--bg);
        color: var(--text);
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    .block-container {
        padding-top: 1.6rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    h1, h2, h3, h4 {
        color: var(--text) !important;
        letter-spacing: -0.25px;
    }

    p, li, label, span {
        color: inherit;
    }

    /* -----------------------------------------------------
       SIDEBAR
       ----------------------------------------------------- */

    section[data-testid="stSidebar"] {
        background: #0b1424;
        border-right: 1px solid var(--border);
    }

    section[data-testid="stSidebar"] > div {
        padding-top: 1.1rem;
    }

    .brand {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 0 4px 14px 4px;
        border-bottom: 1px solid var(--border-soft);
        margin-bottom: 10px;
    }

    .brand svg {
        flex: 0 0 38px;
    }

    .brand-name {
        font-size: 21px;
        font-weight: 800;
        letter-spacing: 2.5px;
        color: #f2f7ff;
        line-height: 1.1;
    }

    .brand-sub {
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 1.5px;
        color: var(--accent);
        margin-top: 3px;
    }

    .nav-label {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.6px;
        color: #607493;
        margin: 14px 4px 6px 4px;
    }

    section[data-testid="stSidebar"] div[role="radiogroup"] {
        gap: 2px;
    }

    section[data-testid="stSidebar"] div[role="radiogroup"] > label {
        padding: 8px 10px;
        border-radius: 7px;
        border-left: 2px solid transparent;
        transition: background 120ms ease, border-color 120ms ease;
        font-size: 13px;
        color: #b9c8de;
        cursor: pointer;
    }

    section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
        background: #111d31;
        color: var(--text);
    }

    section[data-testid="stSidebar"]
    div[role="radiogroup"] > label:has(input:checked) {
        background: #122238;
        border-left-color: var(--accent);
        color: #f2f7ff;
        font-weight: 600;
    }

    section[data-testid="stSidebar"]
    label[data-testid="stRadioOption"] > div > div > div:first-child {
        display: none;
    }

    .sidebar-status {
        margin: 14px 2px 4px 2px;
        padding: 10px 12px;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--panel-soft);
        font-size: 11px;
        color: var(--muted);
        line-height: 1.6;
    }

    .sidebar-status strong {
        color: var(--text);
        font-weight: 600;
    }

    .dot {
        display: inline-block;
        width: 7px;
        height: 7px;
        border-radius: 50%;
        margin-right: 6px;
        vertical-align: 1px;
    }

    .dot-live { background: var(--green); }
    .dot-idle { background: #475569; }
    .dot-warn { background: var(--amber); }

    .sidebar-footer {
        font-size: 10px;
        color: #5c708f;
        letter-spacing: 0.3px;
        margin: 18px 4px 0 4px;
    }

    /* -----------------------------------------------------
       PAGE HEADER
       ----------------------------------------------------- */

    .page-kicker {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.8px;
        color: var(--accent);
        text-transform: uppercase;
        margin-bottom: 5px;
    }

    .page-title {
        font-size: 27px !important;
        font-weight: 750 !important;
        line-height: 1.15 !important;
        margin: 0 0 5px 0 !important;
    }

    .page-sub {
        font-size: 13px;
        color: var(--muted);
        max-width: 900px;
        margin: 0 0 14px 0;
        line-height: 1.5;
    }

    .section-title {
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 0.9px;
        text-transform: uppercase;
        color: #c9d7ea;
        margin: 4px 0 8px 0;
    }

    .section-sub {
        font-size: 12px;
        color: var(--muted);
        margin: -4px 0 10px 0;
    }

    /* -----------------------------------------------------
       METRIC CARDS
       ----------------------------------------------------- */

    .metric-card {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 13px 14px 12px 14px;
        min-height: 94px;
    }

    .metric-card.tone-accent { border-top: 2px solid var(--accent); }
    .metric-card.tone-live { border-top: 2px solid var(--green); }
    .metric-card.tone-critical { border-top: 2px solid var(--red); }
    .metric-card.tone-high { border-top: 2px solid var(--orange); }
    .metric-card.tone-warning { border-top: 2px solid var(--amber); }
    .metric-card.tone-muted { border-top: 2px solid var(--slate); }

    .metric-label {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.1px;
        text-transform: uppercase;
        color: var(--muted);
    }

    .metric-value {
        font-size: 26px;
        font-weight: 750;
        line-height: 1.15;
        color: var(--text);
        margin-top: 7px;
        font-variant-numeric: tabular-nums;
    }

    .metric-sub {
        font-size: 11px;
        color: var(--muted);
        margin-top: 4px;
    }

    /* -----------------------------------------------------
       PILLS AND BADGES
       ----------------------------------------------------- */

    .pill {
        display: inline-block;
        padding: 3px 9px;
        border-radius: 999px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.8px;
        text-transform: uppercase;
        border: 1px solid transparent;
    }

    .pill-live {
        color: #a7f3d0;
        background: rgba(52, 211, 153, 0.12);
        border-color: rgba(52, 211, 153, 0.4);
    }

    .pill-synthetic {
        color: #a5f3fc;
        background: rgba(34, 211, 238, 0.10);
        border-color: rgba(34, 211, 238, 0.38);
    }

    .pill-unknown {
        color: #cbd5e1;
        background: rgba(100, 116, 139, 0.16);
        border-color: rgba(100, 116, 139, 0.42);
    }

    .pill-critical {
        color: #fecaca;
        background: rgba(248, 113, 113, 0.12);
        border-color: rgba(248, 113, 113, 0.42);
    }

    .pill-high {
        color: #fed7aa;
        background: rgba(251, 146, 60, 0.12);
        border-color: rgba(251, 146, 60, 0.4);
    }

    .pill-medium {
        color: #fde68a;
        background: rgba(251, 191, 36, 0.11);
        border-color: rgba(251, 191, 36, 0.38);
    }

    .pill-low {
        color: #bbf7d0;
        background: rgba(52, 211, 153, 0.10);
        border-color: rgba(52, 211, 153, 0.35);
    }

    .pill-open {
        color: #fecaca;
        background: rgba(248, 113, 113, 0.10);
        border-color: rgba(248, 113, 113, 0.32);
    }

    .pill-investigating {
        color: #a5f3fc;
        background: rgba(34, 211, 238, 0.10);
        border-color: rgba(34, 211, 238, 0.32);
    }

    .pill-resolved {
        color: #bbf7d0;
        background: rgba(52, 211, 153, 0.10);
        border-color: rgba(52, 211, 153, 0.32);
    }

    .pill-false_positive {
        color: #cbd5e1;
        background: rgba(100, 116, 139, 0.14);
        border-color: rgba(100, 116, 139, 0.34);
    }

    .mono {
        font-family: "Cascadia Code", "Consolas", monospace;
        font-size: 12px;
    }

    .muted { color: var(--muted); }

    .banner {
        padding: 11px 14px;
        border-radius: 8px;
        border: 1px solid var(--border);
        background: var(--panel-soft);
        font-size: 12px;
        color: var(--muted);
        margin: 6px 0 12px 0;
        line-height: 1.55;
    }

    .banner strong { color: var(--text); }

    .banner-synthetic {
        border-color: rgba(34, 211, 238, 0.32);
        background: rgba(34, 211, 238, 0.055);
    }

    .banner-live {
        border-color: rgba(52, 211, 153, 0.30);
        background: rgba(52, 211, 153, 0.05);
    }

    /* -----------------------------------------------------
       STREAMLIT PANELS / CONTROLS
       ----------------------------------------------------- */

    [data-testid="stVerticalBlockBorderWrapper"] {
        background: var(--panel-soft);
        border-color: var(--border) !important;
        border-radius: 10px;
    }

    [data-testid="stMetric"] {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 10px 12px;
    }

    [data-testid="stMetricLabel"] {
        font-size: 10px !important;
        font-weight: 700 !important;
        letter-spacing: 0.9px;
        text-transform: uppercase;
        color: var(--muted) !important;
    }

    [data-testid="stMetricValue"] {
        font-size: 22px !important;
        font-weight: 700 !important;
        color: var(--text);
    }

    .stButton > button {
        border-radius: 7px;
        border: 1px solid var(--border);
        background: #142136;
        color: var(--text);
        font-size: 12px;
        font-weight: 650;
        letter-spacing: 0.3px;
        min-height: 34px;
    }

    .stButton > button:hover {
        border-color: var(--accent);
        color: #ffffff;
        background: #17283f;
    }

    .stButton > button[kind="primary"] {
        background: #0e7490;
        border-color: #22d3ee;
        color: #f0fdff;
    }

    .stButton > button[kind="primary"]:hover {
        background: #0891b2;
        border-color: #67e8f9;
    }

    .stButton > button:disabled {
        background: #101a2a;
        color: #607493;
        border-color: #1b2940;
    }

    .stSelectbox label,
    .stTextInput label,
    .stTextArea label,
    .stNumberInput label {
        font-size: 11px !important;
        font-weight: 650 !important;
        letter-spacing: 0.3px;
        color: var(--muted) !important;
    }

    .stTextInput input,
    .stTextArea textarea,
    .stNumberInput input {
        background: #0d1727 !important;
        color: var(--text) !important;
        border-color: var(--border) !important;
        font-size: 13px !important;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 8px;
        overflow: hidden;
    }

    .stDataFrame [role="columnheader"] {
        background: #111d30 !important;
        color: #aebfd6 !important;
        font-size: 11px !important;
        letter-spacing: 0.3px;
    }

    [data-testid="stExpander"] {
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--panel-soft);
    }

    [data-testid="stExpander"] summary {
        font-size: 12px;
        font-weight: 650;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
        border-bottom: 1px solid var(--border);
    }

    .stTabs [data-baseweb="tab"] {
        font-size: 12px;
        font-weight: 650;
        color: var(--muted);
        padding: 7px 14px;
    }

    .stTabs [aria-selected="true"] {
        color: var(--accent);
        border-bottom: 2px solid var(--accent);
    }

    [data-testid="stAlert"] {
        font-size: 12px;
        border-radius: 8px;
    }

    code, pre {
        font-family: "Cascadia Code", "Consolas", monospace !important;
        font-size: 12px !important;
    }

    [data-testid="stCaptionContainer"] {
        font-size: 11px !important;
        color: var(--muted);
        line-height: 1.45;
    }

    hr {
        margin: 14px 0 !important;
        border-color: var(--border-soft) !important;
    }

    .footer {
        margin-top: 30px;
        padding-top: 12px;
        border-top: 1px solid var(--border-soft);
        font-size: 10px;
        letter-spacing: 0.5px;
        color: #5c708f;
        display: flex;
        justify-content: space-between;
        gap: 12px;
    }

    @media (max-width: 900px) {
        .page-title { font-size: 23px !important; }
        .metric-value { font-size: 22px; }
        .block-container { padding-left: 1rem; padding-right: 1rem; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =============================================================
# SESSION STATE
# =============================================================

if "database" not in st.session_state:
    st.session_state.database = SentryDatabase(DATABASE_PATH)

if "pipeline" not in st.session_state:
    st.session_state.pipeline = SentryPipeline(
        database_path=DATABASE_PATH
    )

if "generator" not in st.session_state:
    st.session_state.generator = EventGenerator()

if "network_monitor_thread" not in st.session_state:
    st.session_state.network_monitor_thread = None

if "network_sensor" not in st.session_state:
    st.session_state.network_sensor = None

database = st.session_state.database
pipeline = st.session_state.pipeline
generator = st.session_state.generator


# =============================================================
# SMALL HELPERS
# =============================================================

def esc(value):
    """Escape a value before inserting it into custom HTML."""

    return html.escape("" if value is None else str(value))


def normalise_origin(value):
    """Return LIVE, SYNTHETIC or UNKNOWN for display and filtering."""

    origin = str(value or "").strip().upper()

    return origin if origin in ("LIVE", "SYNTHETIC") else "UNKNOWN"


def origin_badge(value):
    origin = normalise_origin(value)

    return (
        f'<span class="pill pill-{origin.lower()}">'
        f"{origin}</span>"
    )


def severity_badge(value):
    severity = str(value or "UNKNOWN").upper()
    css = severity.lower() if severity in SEVERITY_COLORS else "unknown"

    return f'<span class="pill pill-{css}">{esc(severity)}</span>'


def status_badge(value):
    status = str(value or "OPEN").upper()
    css = status.lower()

    return (
        f'<span class="pill pill-{css}">'
        f"{esc(STATUS_LABELS.get(status, status))}</span>"
    )


def metric_card(label, value, sub="", tone="accent"):
    st.markdown(
        f"""
        <div class="metric-card tone-{esc(tone)}">
            <div class="metric-label">{esc(label)}</div>
            <div class="metric-value">{esc(value)}</div>
            <div class="metric-sub">{esc(sub)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def page_header(kicker, title, subtitle):
    st.markdown(
        f"""
        <div class="page-kicker">{esc(kicker)}</div>
        <div class="page-title">{esc(title)}</div>
        <div class="page-sub">{esc(subtitle)}</div>
        """,
        unsafe_allow_html=True,
    )


def section_title(title, subtitle=None):
    st.markdown(
        f'<div class="section-title">{esc(title)}</div>',
        unsafe_allow_html=True,
    )

    if subtitle:
        st.markdown(
            f'<div class="section-sub">{esc(subtitle)}</div>',
            unsafe_allow_html=True,
        )


def format_timestamp(value):
    if not value:
        return "—"

    text = str(value).replace("T", " ")

    if "." in text:
        text = text.split(".")[0]

    return text


def parse_json(raw):
    if not raw:
        return None

    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None

    return parsed if isinstance(parsed, dict) else None


def confidence_text(value):
    if isinstance(value, (int, float)):
        return f"{value:.0%}"

    return "—"


def alert_table_rows(alerts):
    rows = []

    for alert in alerts:
        rows.append(
            {
                "ID": alert["id"],
                "Time": format_timestamp(alert["timestamp"]),
                "Severity": str(alert["severity"]).upper(),
                "Rule": alert["rule_id"],
                "Detection": alert["alert_type"],
                "Source IP": alert["source_ip"] or "—",
                "Confidence": confidence_text(alert["confidence"]),
                "Status": STATUS_LABELS.get(
                    alert["status"],
                    alert["status"],
                ),
                "Origin": normalise_origin(
                    alert["event_origin"]
                    if "event_origin" in alert.keys()
                    else None
                ),
            }
        )

    return rows


def event_table_rows(events):
    rows = []

    for event in events:
        rows.append(
            {
                "Time": format_timestamp(event["timestamp"]),
                "Origin": normalise_origin(
                    event["event_origin"]
                    if "event_origin" in event.keys()
                    else None
                ),
                "Event Type": event["event_type"] or "—",
                "Source": event["source"] or "—",
                "Source IP": event["source_ip"] or "—",
                "Destination IP": event["destination_ip"] or "—",
                "Protocol": event["protocol"] or "—",
                "Destination Port": (
                    str(event["destination_port"])
                    if event["destination_port"] is not None
                    else "—"
                ),
                "User": event["username"] or "—",
                "Detail": (
                    event["path"]
                    or event["method"]
                    or event["raw"]
                    or "—"
                ),
            }
        )

    return rows


def chart_theme(chart):
    return (
        chart.configure_view(stroke=None)
        .configure_axis(
            labelColor="#8ea3c0",
            titleColor="#8ea3c0",
            gridColor="#1e2c44",
            domainColor="#1e2c44",
            tickColor="#1e2c44",
            labelFontSize=10,
            titleFontSize=10,
        )
        .configure_legend(
            labelColor="#b9c8de",
            titleColor="#8ea3c0",
            labelFontSize=10,
        )
    )


def origin_bar_chart(rows, height=220):
    """Horizontal bar chart of counts per origin."""

    data = pd.DataFrame(
        [
            {
                "Origin": row["origin"],
                "Events": row["count"],
            }
            for row in rows
        ]
    )

    if data.empty:
        st.info("No data available yet.")
        return

    chart = (
        alt.Chart(data)
        .mark_bar(cornerRadiusEnd=3)
        .encode(
            x=alt.X("Events:Q", title=None),
            y=alt.Y(
                "Origin:N",
                title=None,
                sort=["LIVE", "SYNTHETIC", "UNKNOWN"],
            ),
            color=alt.Color(
                "Origin:N",
                scale=alt.Scale(
                    domain=["LIVE", "SYNTHETIC", "UNKNOWN"],
                    range=[
                        ORIGIN_COLORS["LIVE"],
                        ORIGIN_COLORS["SYNTHETIC"],
                        ORIGIN_COLORS["UNKNOWN"],
                    ],
                ),
                legend=None,
            ),
            tooltip=["Origin:N", "Events:Q"],
        )
        .properties(height=height)
    )

    st.altair_chart(
        chart_theme(chart),
        width="stretch",
    )


def simple_bar_chart(
    dataframe,
    category,
    value,
    color=None,
    color_scale=None,
    horizontal=False,
    height=220,
    sort=None,
):
    if dataframe.empty:
        st.info("No data available yet.")
        return

    if horizontal:
        x = alt.X(f"{value}:Q", title=None)
        y = alt.Y(
            f"{category}:N",
            title=None,
            sort=sort or "-x",
        )
    else:
        x = alt.X(f"{category}:N", title=None, sort="-y")
        y = alt.Y(f"{value}:Q", title=None)

    encoding = {
        "x": x,
        "y": y,
        "tooltip": [f"{category}:N", f"{value}:Q"],
    }

    if color:
        encoding["color"] = alt.Color(
            f"{color}:N",
            scale=(
                alt.Scale(**color_scale)
                if color_scale
                else alt.Undefined
            ),
            legend=None,
        )
    else:
        encoding["color"] = alt.value("#22d3ee")

    chart = (
        alt.Chart(dataframe)
        .mark_bar(cornerRadiusEnd=3)
        .encode(**encoding)
        .properties(height=height)
    )

    st.altair_chart(
        chart_theme(chart),
        width="stretch",
    )


def render_footer():
    st.markdown(
        f"""
        <div class="footer">
            <span>SENTRY v{esc(SENTRY_VERSION)} · Local-first security operations</span>
            <span>SQLite · Streamlit · Scapy/Npcap</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


# =============================================================
# NETWORK CAPTURE HELPERS
# =============================================================

def get_capture_interfaces():
    """Discover usable Scapy/Npcap interfaces for the dashboard."""

    interfaces = {}

    for iface in conf.ifaces.values():
        name = getattr(iface, "name", None)
        description = getattr(iface, "description", None)
        ip_address = getattr(iface, "ip", None)
        guid = getattr(iface, "guid", None)

        if not name or not guid:
            continue

        description_lower = (
            description.lower() if description else ""
        )

        if "wan miniport" in description_lower:
            continue

        if "wi-fi direct" in description_lower:
            continue

        if name == "Loopback Pseudo-Interface 1":
            label = "Loopback — 127.0.0.1"
        elif (
            ip_address
            and not str(ip_address).startswith("169.254.")
        ):
            label = f"{name} — {ip_address}"
        else:
            label = f"{name} — no active IPv4"

        interfaces[label] = iface

    return interfaces


def network_monitor_running():
    thread = st.session_state.get("network_monitor_thread")

    return thread is not None and thread.is_alive()


def npcap_available():
    system_root = os.environ.get("SystemRoot", r"C:\Windows")

    candidates = [
        Path(system_root) / "System32" / "Npcap" / "wpcap.dll",
        Path(system_root) / "SysWOW64" / "Npcap" / "wpcap.dll",
    ]

    if any(path.exists() for path in candidates):
        return True

    try:
        import winreg

        for root, path in (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
        ):
            try:
                winreg.OpenKey(root, path).Close()
                return True
            except OSError:
                continue
    except ImportError:
        return False

    return False


# =============================================================
# ALERT DETAIL RENDERING
# =============================================================

def render_evidence(evidence):
    if not isinstance(evidence, dict):
        st.info(
            "Detection evidence is not available for this historical alert."
        )
        return

    mitre = evidence.get("mitre") or {}

    st.markdown(
        f"**Rule** `{esc(evidence.get('rule_id', '—'))}` · "
        f"{esc(evidence.get('rule_name', '—'))}"
    )

    if evidence.get("rule_description"):
        st.write(evidence["rule_description"])

    if mitre:
        st.caption(
            f"MITRE ATT&CK · {mitre.get('technique_id', '—')} "
            f"{mitre.get('technique', '')} · "
            f"{mitre.get('tactic', '—')}"
        )

    if evidence.get("explanation"):
        st.markdown(
            f"**Why this matters** — {evidence['explanation']}"
        )

    conditions = evidence.get("conditions") or []

    if conditions:
        st.markdown("**Triggering conditions**")

        st.dataframe(
            [
                {
                    "Condition": item.get("condition", "—"),
                    "Expected": item.get("expected", "—"),
                    "Observed": item.get("observed", "—"),
                    "Result": item.get("result", "—"),
                }
                for item in conditions
            ],
            width="stretch",
            hide_index=True,
        )

    window = evidence.get("window") or {}

    if window:
        st.caption(
            f"Detection window · {window.get('start', '—')} → "
            f"{window.get('end', '—')} "
            f"({window.get('seconds', '—')}s)"
        )

    threshold = evidence.get("threshold")

    if threshold is not None:
        st.caption(f"Rule threshold · {threshold}")

    triggering = evidence.get("triggering_events") or []

    if triggering:
        st.markdown("**Matching events that triggered this alert**")

        st.dataframe(
            [
                {
                    "Time": format_timestamp(
                        item.get("timestamp")
                    ),
                    "Origin": normalise_origin(
                        item.get("event_origin")
                    ),
                    "Source": item.get("source", "—"),
                    "Event Type": item.get("event_type", "—"),
                    "Source IP": item.get("source_ip") or "—",
                    "Destination IP": (
                        item.get("destination_ip") or "—"
                    ),
                    "Destination Port": (
                        item.get("destination_port")
                        if item.get("destination_port") is not None
                        else "—"
                    ),
                }
                for item in triggering
            ],
            width="stretch",
            hide_index=True,
        )

        total = evidence.get("triggering_event_count")

        if isinstance(total, int) and total > len(triggering):
            st.caption(
                f"Showing first {len(triggering)} of "
                f"{total} matching events."
            )

    if evidence.get("matched_pattern"):
        st.caption(
            f"Matched pattern · `{evidence['matched_pattern']}`"
        )

    unique_ports = evidence.get("unique_destination_ports") or []

    if unique_ports:
        st.caption(
            "Unique destination ports · "
            + ", ".join(str(port) for port in unique_ports)
        )

    confidence = evidence.get("confidence") or {}
    score = confidence.get("score")

    if isinstance(score, (int, float)):
        st.caption(
            f"Rule confidence {score:.0%} · "
            f"{confidence.get('basis', '')}"
        )

    actions = evidence.get("recommended_actions") or []

    if actions:
        st.markdown("**Recommended actions**")

        for action in actions:
            st.markdown(f"- {action}")


def render_related_events(alert):
    related = database.get_related_events(
        alert["source_ip"],
        alert["timestamp"],
        window_seconds=120,
    )

    if not related:
        st.info(
            "No related events were found within the ±120 second "
            "investigation window."
        )
        return

    st.caption(
        f"{len(related)} events from the same source within "
        "±120 seconds. This is context, not necessarily evidence."
    )

    st.dataframe(
        event_table_rows(related[:200]),
        width="stretch",
        hide_index=True,
        height=320,
    )


def render_alert_investigation(alert):
    investigation = database.get_investigation(alert["id"])

    existing_notes = ""
    existing_action = ""

    if investigation:
        existing_notes = investigation["analyst_notes"] or ""
        existing_action = (
            investigation["recommended_action"] or ""
        )

    notes = st.text_area(
        "Analyst notes",
        value=existing_notes,
        height=140,
        placeholder=(
            "Document what you observed and what you checked."
        ),
        key=f"notes_{alert['id']}",
    )

    action = st.text_area(
        "Recommended action",
        value=existing_action,
        height=110,
        placeholder=(
            "Describe the recommended response or next step."
        ),
        key=f"action_{alert['id']}",
    )

    if st.button(
        "Save investigation",
        key=f"save_investigation_{alert['id']}",
        width="stretch",
    ):
        database.update_investigation(
            alert["id"],
            notes,
            action,
        )
        st.success(f"Investigation for alert #{alert['id']} saved.")
        st.rerun()

    st.markdown("---")
    st.markdown("**Lifecycle**")

    status_options = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE",
    ]

    current_status = (
        alert["status"]
        if alert["status"] in status_options
        else "OPEN"
    )

    new_status = st.selectbox(
        "Alert status",
        status_options,
        index=status_options.index(current_status),
        format_func=lambda value: STATUS_LABELS.get(value, value),
        key=f"status_{alert['id']}",
    )

    if st.button(
        "Update status",
        key=f"update_status_{alert['id']}",
        width="stretch",
    ):
        if new_status == current_status:
            st.info(
                f"Alert #{alert['id']} is already "
                f"{STATUS_LABELS.get(new_status, new_status)}."
            )
        else:
            database.update_alert_status(
                alert["id"],
                new_status,
            )
            st.success(
                f"Alert #{alert['id']} updated to "
                f"{STATUS_LABELS.get(new_status, new_status)}."
            )
            st.rerun()


def render_alert_detail(alert):
    evidence = parse_json(
        alert["evidence_json"]
        if "evidence_json" in alert.keys()
        else None
    )
    intel = parse_json(
        alert["threat_intel_json"]
        if "threat_intel_json" in alert.keys()
        else None
    )
    origin = normalise_origin(
        alert["event_origin"]
        if "event_origin" in alert.keys()
        else None
    )

    st.markdown(
        f"""
        <div class="metric-card tone-{origin.lower()}"
             style="min-height:0; margin-bottom:10px;">
            <div style="display:flex; gap:8px; flex-wrap:wrap;
                        align-items:center;">
                {severity_badge(alert['severity'])}
                {status_badge(alert['status'])}
                {origin_badge(origin)}
                <span class="muted mono">
                    {esc(alert['rule_id'])} · Alert #{esc(alert['id'])}
                </span>
            </div>
            <div style="font-size:18px; font-weight:700; margin-top:9px;">
                {esc(alert['alert_type'])}
            </div>
            <div class="muted" style="font-size:12px; margin-top:4px;">
                {esc(format_timestamp(alert['timestamp']))} ·
                source {esc(alert['source_ip'] or '—')} ·
                confidence {esc(confidence_text(alert['confidence']))}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    overview_tab, evidence_tab, context_tab, notes_tab = st.tabs(
        ["Overview", "Detection evidence", "Investigation context", "Notes & lifecycle"]
    )

    with overview_tab:
        st.markdown("**Detection detail**")
        st.code(alert["detail"] or "—", language=None)

        st.markdown("**Threat intelligence**")

        if not isinstance(intel, dict):
            st.caption(
                "No threat-intelligence enrichment is stored for this alert."
            )
        else:
            intel_col1, intel_col2, intel_col3 = st.columns(3)

            intel_col1.metric(
                "IP",
                intel.get("ip") or "—",
            )
            intel_col2.metric(
                "Reputation",
                str(intel.get("status", "unknown")).upper(),
            )
            intel_col3.metric(
                "Source",
                intel.get("source") or "—",
            )

            if intel.get("details"):
                st.caption(str(intel["details"]))

            st.caption(
                "Unknown means no configured source has data for this "
                "address; it is not proof of benign activity."
            )

        st.markdown("**Event origin**")
        st.write(
            f"{origin_badge(origin)} This alert was produced by "
            f"**{origin}** events."
        )

        if origin == "SYNTHETIC":
            st.caption(
                "Synthetic alerts come from SENTRY's demonstration "
                "generator and do not represent observed network traffic."
            )
        elif origin == "UNKNOWN":
            st.caption(
                "This alert predates origin labelling, or its triggering "
                "events had mixed origins. SENTRY does not guess."
            )

    with evidence_tab:
        render_evidence(evidence)

    with context_tab:
        render_related_events(alert)

    with notes_tab:
        render_alert_investigation(alert)


# =============================================================
# PAGE: SECURITY OVERVIEW
# =============================================================

def render_overview():
    page_header(
        "Security operations / overview",
        "Security Overview",
        "Live posture across detections, incidents and telemetry sources. "
        "All figures are read directly from the SENTRY database.",
    )

    running = network_monitor_running()

    total_events = database.get_event_count()
    total_alerts = database.get_alert_count()
    critical = database.get_alert_count_by_severity("CRITICAL")
    high = database.get_alert_count_by_severity("HIGH")
    open_alerts = database.get_open_alert_count()

    status_html = (
        f'<span class="pill pill-live">Monitoring running</span>'
        if running
        else f'<span class="pill pill-unknown">Monitoring stopped</span>'
    )

    st.markdown(
        f"""
        <div class="banner {'banner-live' if running else ''}">
            <strong>Collection status</strong> · {status_html}
            &nbsp; SQLite connected ·
            <span class="mono">{esc(DATABASE_PATH)}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    metric_cols = st.columns(6)

    with metric_cols[0]:
        metric_card(
            "Total events",
            f"{total_events:,}",
            "Stored security events",
            "accent",
        )

    with metric_cols[1]:
        metric_card(
            "Total alerts",
            f"{total_alerts:,}",
            "All detections",
            "high",
        )

    with metric_cols[2]:
        metric_card(
            "Critical",
            f"{critical:,}",
            "Immediate attention",
            "critical",
        )

    with metric_cols[3]:
        metric_card(
            "High",
            f"{high:,}",
            "Priority review",
            "high",
        )

    with metric_cols[4]:
        metric_card(
            "Open incidents",
            f"{open_alerts:,}",
            "Status OPEN",
            "warning",
        )

    with metric_cols[5]:
        metric_card(
            "Live monitoring",
            "RUNNING" if running else "STOPPED",
            "Scapy/Npcap capture",
            "live" if running else "muted",
        )

    st.markdown("")

    if total_events == 0 and total_alerts == 0:
        st.info(
            "No events or alerts have been stored yet. Start live "
            "monitoring, or use the Synthetic Lab to demonstrate the "
            "detection engine with clearly labelled simulated data."
        )
        return

    origin_counts = {
        row["origin"]: row["count"]
        for row in database.get_event_origin_counts()
    }

    synthetic_count = origin_counts.get("SYNTHETIC", 0)
    live_count = origin_counts.get("LIVE", 0)
    unknown_count = origin_counts.get("UNKNOWN", 0)

    st.markdown(
        f"""
        <div class="banner">
            <strong>Data provenance</strong> ·
            {origin_badge('LIVE')} {live_count:,} live ·
            {origin_badge('SYNTHETIC')} {synthetic_count:,} synthetic ·
            {origin_badge('UNKNOWN')} {unknown_count:,} unknown
            <div class="muted" style="margin-top:6px;">
                Synthetic events are generated for demonstration and are
                never presented as observed network traffic. Historical
                rows without an explicit origin remain UNKNOWN.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ---------------------------------------------------------
    # EVENT VOLUME
    # ---------------------------------------------------------

    trend_col, severity_col = st.columns([1.55, 1])

    with trend_col:
        with st.container(border=True):
            section_title(
                "Event volume · last 24 hours",
                "Hourly event counts split by data origin.",
            )

            timeline_rows = database.get_event_timeline(24)

            now = datetime.now().replace(
                minute=0,
                second=0,
                microsecond=0,
            )

            buckets = {}

            for offset in range(23, -1, -1):
                hour = now - timedelta(hours=offset)
                buckets[hour.strftime("%Y-%m-%dT%H")] = {
                    "Hour": hour.strftime("%H:00"),
                    "LIVE": 0,
                    "SYNTHETIC": 0,
                    "UNKNOWN": 0,
                }

            for row in timeline_rows:
                bucket = buckets.get(row["hour"])

                if bucket is not None:
                    bucket[row["origin"]] += row["count"]

            timeline_data = pd.DataFrame(
                list(buckets.values())
            )

            if timeline_data[["LIVE", "SYNTHETIC", "UNKNOWN"]].to_numpy().sum() == 0:
                st.info(
                    "No events were recorded in the last 24 hours. "
                    "Start live monitoring or generate a synthetic "
                    "scenario to populate the timeline."
                )
            else:
                chart = (
                    alt.Chart(timeline_data)
                    .mark_line(strokeWidth=2)
                    .encode(
                        x=alt.X(
                            "Hour:N",
                            title=None,
                            axis=alt.Axis(labelAngle=0),
                        ),
                        y=alt.Y("value:Q", title="Events"),
                        color=alt.Color(
                            "origin:N",
                            title=None,
                            scale=alt.Scale(
                                domain=[
                                    "LIVE",
                                    "SYNTHETIC",
                                    "UNKNOWN",
                                ],
                                range=[
                                    ORIGIN_COLORS["LIVE"],
                                    ORIGIN_COLORS["SYNTHETIC"],
                                    ORIGIN_COLORS["UNKNOWN"],
                                ],
                            ),
                        ),
                    )
                    .transform_fold(
                        ["LIVE", "SYNTHETIC", "UNKNOWN"],
                        as_=["origin", "value"],
                    )
                    .properties(height=235)
                )

                st.altair_chart(
                    chart_theme(chart),
                    width="stretch",
                )

    with severity_col:
        with st.container(border=True):
            section_title(
                "Alert severity",
                "Distribution across stored detections.",
            )

            severity_rows = [
                {
                    "Severity": severity,
                    "Alerts": database.get_alert_count_by_severity(
                        severity
                    ),
                }
                for severity in (
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                )
            ]

            severity_data = pd.DataFrame(severity_rows)

            simple_bar_chart(
                severity_data,
                category="Severity",
                value="Alerts",
                color="Severity",
                color_scale={
                    "domain": [
                        "CRITICAL",
                        "HIGH",
                        "MEDIUM",
                        "LOW",
                    ],
                    "range": [
                        SEVERITY_COLORS["CRITICAL"],
                        SEVERITY_COLORS["HIGH"],
                        SEVERITY_COLORS["MEDIUM"],
                        SEVERITY_COLORS["LOW"],
                    ],
                },
                horizontal=True,
                height=235,
                sort=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            )

    # ---------------------------------------------------------
    # SOURCE / TARGET / RULE BREAKDOWN
    # ---------------------------------------------------------

    origin_col, source_col, port_col, rule_col = st.columns(
        [1, 1, 1, 1.25]
    )

    with origin_col:
        with st.container(border=True):
            section_title("Event sources")
            origin_bar_chart(
                database.get_event_origin_counts(),
                height=210,
            )

    with source_col:
        with st.container(border=True):
            section_title("Top source IPs")

            source_rows = database.get_top_source_ips(8)
            source_data = pd.DataFrame(
                [
                    {
                        "Source IP": row["source_ip"],
                        "Events": row["count"],
                    }
                    for row in source_rows
                ]
            )

            simple_bar_chart(
                source_data,
                category="Source IP",
                value="Events",
                horizontal=True,
                height=210,
            )

    with port_col:
        with st.container(border=True):
            section_title("Top destination ports")

            port_rows = database.get_top_destination_ports(8)
            port_data = pd.DataFrame(
                [
                    {
                        "Port": str(row["destination_port"]),
                        "Events": row["count"],
                    }
                    for row in port_rows
                ]
            )

            simple_bar_chart(
                port_data,
                category="Port",
                value="Events",
                horizontal=True,
                height=210,
            )

    with rule_col:
        with st.container(border=True):
            section_title("Detection rules")

            rule_rows = database.get_rule_distribution(8)
            rule_data = pd.DataFrame(
                [
                    {
                        "Rule": row["rule_id"],
                        "Alerts": row["count"],
                    }
                    for row in rule_rows
                ]
            )

            simple_bar_chart(
                rule_data,
                category="Rule",
                value="Alerts",
                horizontal=True,
                height=210,
            )

    # ---------------------------------------------------------
    # RECENT ALERTS
    # ---------------------------------------------------------

    with st.container(border=True):
        section_title(
            "Recent alerts",
            "Newest detections across all data sources.",
        )

        recent_alerts = database.get_recent_alerts(8)

        if not recent_alerts:
            st.info("No alerts have been recorded yet.")
        else:
            st.dataframe(
                alert_table_rows(recent_alerts),
                width="stretch",
                hide_index=True,
            )

            st.caption(
                "Open Alerts & Incidents for filters, evidence, MITRE "
                "mapping and investigation notes."
            )


# =============================================================
# PAGE: LIVE NETWORK MONITORING
# =============================================================

@st.fragment(run_every=2)
def render_live_monitoring():
    page_header(
        "Collection / network sensor",
        "Live Network Monitoring",
        "Capture real packets through Scapy/Npcap. Payloads are never "
        "stored; captured metadata is converted into LIVE security events.",
    )

    running = network_monitor_running()

    status_pill = (
        '<span class="pill pill-live">RUNNING</span>'
        if running
        else '<span class="pill pill-unknown">STOPPED</span>'
    )

    st.markdown(
        f"""
        <div class="banner {'banner-live' if running else ''}">
            <strong>Sensor state</strong> · {status_pill}
            &nbsp; Events produced here are labelled
            {origin_badge('LIVE')}
        </div>
        """,
        unsafe_allow_html=True,
    )

    interfaces = get_capture_interfaces()

    if not interfaces:
        st.error(
            "No usable network capture interfaces were detected. "
            "Check that Npcap is installed and that an adapter is enabled."
        )
        return

    labels = list(interfaces.keys())

    if (
        st.session_state.get("selected_network_interface")
        not in labels
    ):
        st.session_state.selected_network_interface = labels[0]

    control_col, duration_col, packet_col, event_col, alert_col = st.columns(
        [2.4, 1.3, 1, 1, 1]
    )

    with control_col:
        selected_label = st.selectbox(
            "Network interface",
            labels,
            index=labels.index(
                st.session_state.selected_network_interface
            ),
            disabled=running,
            key="network_interface_selector",
        )

    st.session_state.selected_network_interface = selected_label

    selected_interface = interfaces[selected_label]

    interface_description = getattr(
        selected_interface,
        "description",
        None,
    )
    interface_ip = getattr(selected_interface, "ip", None)

    st.caption(
        f"Adapter · {interface_description or 'Unknown'}   |   "
        f"IP · {interface_ip or 'No IP assigned'}"
    )

    if (
        st.session_state.network_sensor is None
        or (
            not running
            and st.session_state.get(
                "network_sensor_interface_label"
            )
            != selected_label
        )
    ):
        st.session_state.network_sensor = NetworkSensor(
            pipeline=st.session_state.pipeline,
            interface=selected_interface,
        )
        st.session_state.network_sensor_interface_label = (
            selected_label
        )

    sensor = st.session_state.network_sensor

    duration_options = {
        "10 seconds": 10,
        "30 seconds": 30,
        "1 minute": 60,
        "5 minutes": 300,
        "10 minutes": 600,
        "Continuous": None,
    }

    with duration_col:
        selected_duration = st.selectbox(
            "Capture duration",
            list(duration_options.keys()),
            disabled=running,
            key="capture_duration",
        )

    with packet_col:
        metric_card(
            "Packets",
            f"{sensor.packet_count:,}",
            "Captured",
            "accent",
        )

    with event_col:
        metric_card(
            "Events",
            f"{sensor.event_count:,}",
            "LIVE events",
            "live",
        )

    with alert_col:
        metric_card(
            "Alerts",
            f"{sensor.alert_count:,}",
            "From capture",
            "high",
        )

    start_col, stop_col, spacer = st.columns([1, 1, 3])

    with start_col:
        start = st.button(
            "Start monitoring",
            type="primary",
            width="stretch",
            disabled=running,
            key="start_network_monitor",
        )

    with stop_col:
        stop = st.button(
            "Stop monitoring",
            width="stretch",
            disabled=not running,
            key="stop_network_monitor",
        )

    if start:
        duration = duration_options[selected_duration]

        monitor_thread = threading.Thread(
            target=sensor.start,
            kwargs={"duration": duration},
            daemon=True,
            name="sentry-network-monitor",
        )

        st.session_state.network_monitor_thread = monitor_thread
        monitor_thread.start()
        st.rerun()

    if stop:
        sensor.stop()
        st.rerun()

    running = network_monitor_running()

    if running:
        st.success(
            "Live capture is running. Real packets are being converted "
            "into LIVE events and processed by the detection engine."
        )
    else:
        st.info(
            "Capture is stopped. Select an interface and duration, then "
            "press Start monitoring."
        )

    if sensor.last_error:
        st.error(f"Capture error · {sensor.last_error}")

    recent_live = database.get_recent_network_events(limit=500)

    if recent_live:
        protocol_counts = Counter(
            event["protocol"]
            for event in recent_live
            if event["protocol"]
        )

        chart_col, table_col = st.columns([1, 1.7])

        with chart_col:
            with st.container(border=True):
                section_title(
                    "Protocol distribution",
                    "Last 500 captured network events.",
                )

                protocol_data = pd.DataFrame(
                    [
                        {"Protocol": protocol, "Events": count}
                        for protocol, count
                        in protocol_counts.most_common()
                    ]
                )

                simple_bar_chart(
                    protocol_data,
                    category="Protocol",
                    value="Events",
                    horizontal=True,
                    height=230,
                )

        with table_col:
            with st.container(border=True):
                section_title(
                    "Recent network events",
                    "Captured metadata; historical rows may show UNKNOWN.",
                )

                st.dataframe(
                    event_table_rows(recent_live[:10]),
                    width="stretch",
                    hide_index=True,
                    height=230,
                )
    else:
        st.info(
            "No live network events have been captured yet. Start "
            "monitoring to collect real traffic metadata."
        )


# =============================================================
# PAGE: ALERTS & INCIDENTS
# =============================================================

def render_alerts():
    page_header(
        "Triage / detections",
        "Alerts & Incidents",
        "Filter, inspect and investigate every detection. Evidence, "
        "MITRE mapping, related events and analyst notes are preserved.",
    )

    alerts = database.get_recent_alerts(limit=500)

    if not alerts:
        st.info(
            "No alerts have been recorded yet. Generate a synthetic "
            "scenario in the Synthetic Lab, or start live monitoring."
        )
        return

    severity_filter = st.columns([1, 1, 1.4, 1, 1.6])

    with severity_filter[0]:
        severity = st.selectbox(
            "Severity",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="alert_severity_filter",
        )

    with severity_filter[1]:
        status = st.selectbox(
            "Status",
            ["All"] + list(STATUS_LABELS.keys()),
            format_func=lambda value: (
                value
                if value == "All"
                else STATUS_LABELS.get(value, value)
            ),
            key="alert_status_filter",
        )

    with severity_filter[2]:
        rules = sorted(
            {
                alert["rule_id"]
                for alert in alerts
                if alert["rule_id"]
            }
        )

        rule = st.selectbox(
            "Detection rule",
            ["All"] + rules,
            key="alert_rule_filter",
        )

    with severity_filter[3]:
        origin_label = st.selectbox(
            "Event origin",
            ORIGIN_OPTIONS,
            key="alert_origin_filter",
        )

    with severity_filter[4]:
        search = st.text_input(
            "Search",
            placeholder="Source IP, rule, type or detail",
            key="alert_search",
        ).strip().lower()

    origin_filter = ORIGIN_FILTERS[origin_label]

    filtered = []

    for alert in alerts:
        origin = normalise_origin(
            alert["event_origin"]
            if "event_origin" in alert.keys()
            else None
        )

        if severity != "All" and alert["severity"] != severity:
            continue

        if status != "All" and alert["status"] != status:
            continue

        if rule != "All" and alert["rule_id"] != rule:
            continue

        if origin_filter != "All" and origin != origin_filter:
            continue

        if search:
            haystack = " ".join(
                str(
                    alert[field] or ""
                )
                for field in (
                    "source_ip",
                    "rule_id",
                    "alert_type",
                    "detail",
                )
            ).lower()

            if search not in haystack:
                continue

        filtered.append(alert)

    st.caption(
        f"Showing {len(filtered)} of {len(alerts)} recent alerts. "
        "Filters combine with AND."
    )

    if not filtered:
        st.info("No alerts match the selected filters.")
        return

    with st.container(border=True):
        st.dataframe(
            alert_table_rows(filtered),
            width="stretch",
            hide_index=True,
            height=min(330, 40 + len(filtered) * 35),
        )

    options = {
        (
            f"#{alert['id']} · {alert['severity']} · "
            f"{alert['alert_type']} · "
            f"{STATUS_LABELS.get(alert['status'], alert['status'])} · "
            f"{normalise_origin(alert['event_origin'] if 'event_origin' in alert.keys() else None)}"
        ): alert
        for alert in filtered
    }

    selected_label = st.selectbox(
        "Select an alert to investigate",
        list(options.keys()),
        key="selected_alert",
    )

    render_alert_detail(options[selected_label])


# =============================================================
# PAGE: NETWORK ACTIVITY
# =============================================================

def render_network_activity():
    page_header(
        "Telemetry / network",
        "Network Activity",
        "Observed traffic metadata, communicating hosts, flows and "
        "capture direction. Synthetic events never appear as live packets.",
    )

    events = database.get_recent_network_events(limit=500)

    if not events:
        st.info(
            "No network events have been captured yet. Open Live Network "
            "Monitoring and start a capture."
        )
        return

    source_counts = Counter(
        event["source_ip"]
        for event in events
        if event["source_ip"]
    )
    destination_counts = Counter(
        event["destination_ip"]
        for event in events
        if event["destination_ip"]
    )
    protocol_counts = Counter(
        event["protocol"]
        for event in events
        if event["protocol"]
    )
    port_counts = Counter(
        event["destination_port"]
        for event in events
        if event["destination_port"] is not None
    )

    flow_keys = {
        (
            event["source_ip"],
            event["destination_ip"],
            event["protocol"],
            event["destination_port"],
        )
        for event in events
    }

    metric_cols = st.columns(4)

    with metric_cols[0]:
        metric_card(
            "Network events",
            f"{len(events):,}",
            "Last 500 captured",
            "accent",
        )

    with metric_cols[1]:
        metric_card(
            "Unique flows",
            f"{len(flow_keys):,}",
            "Source/destination/protocol",
            "live",
        )

    with metric_cols[2]:
        metric_card(
            "Source hosts",
            f"{len(source_counts):,}",
            "Distinct source IPs",
            "accent",
        )

    with metric_cols[3]:
        metric_card(
            "Destination ports",
            f"{len(port_counts):,}",
            "Distinct ports",
            "muted",
        )

    iface_col1, iface_col2 = st.columns(2)

    with iface_col1:
        with st.container(border=True):
            section_title(
                "Top source hosts",
                "Most active source addresses.",
            )

            simple_bar_chart(
                pd.DataFrame(
                    [
                        {"Host": host, "Events": count}
                        for host, count in source_counts.most_common(10)
                    ]
                ),
                category="Host",
                value="Events",
                horizontal=True,
                height=230,
            )

    with iface_col2:
        with st.container(border=True):
            section_title(
                "Top destination ports",
                "Service ports seen in captured traffic.",
            )

            simple_bar_chart(
                pd.DataFrame(
                    [
                        {
                            "Port": str(port),
                            "Events": count,
                        }
                        for port, count in port_counts.most_common(10)
                    ]
                ),
                category="Port",
                value="Events",
                horizontal=True,
                height=230,
            )

    # ---------------------------------------------------------
    # FILTERS
    # ---------------------------------------------------------

    with st.container(border=True):
        section_title(
            "Recent network events",
            "Bounded to the most recent 500 captured packets.",
        )

        (
            filter_direction,
            filter_initiation,
            filter_protocol,
            filter_origin,
            filter_limit,
        ) = st.columns(5)

        direction = filter_direction.selectbox(
            "Direction",
            ["All", "Inbound", "Outbound", "Local", "Unknown"],
            key="network_direction_filter",
        )

        initiation = filter_initiation.selectbox(
            "Connection initiated",
            ["All", "Initiated", "Not Initiated", "Unknown"],
            key="network_initiation_filter",
        )

        protocol = filter_protocol.selectbox(
            "Protocol",
            ["All", "TCP", "UDP", "IP"],
            key="network_protocol_filter",
        )

        origin_label = filter_origin.selectbox(
            "Origin",
            ORIGIN_OPTIONS,
            key="network_origin_filter",
        )

        limit = filter_limit.selectbox(
            "Events shown",
            [15, 50, 100, 250, 500],
            key="network_event_limit",
        )

        filtered = [
            event
            for event in events
            if network_event_matches_filters(
                event,
                direction,
                initiation,
                protocol,
                ORIGIN_FILTERS[origin_label],
            )
        ]

        st.caption(
            f"Showing {min(len(filtered), limit)} of "
            f"{len(filtered)} matching events."
        )

        if not filtered:
            st.info("No events match the selected filters.")
        else:
            rows = []

            for event in filtered[:limit]:
                rows.append(
                    {
                        "Time": format_timestamp(
                            event["timestamp"]
                        ),
                        "Origin": normalise_origin(
                            event["event_origin"]
                            if "event_origin" in event.keys()
                            else None
                        ),
                        "Direction": describe_direction(event),
                        "Initiated": describe_initiation(event),
                        "Source IP": event["source_ip"] or "—",
                        "Source Port": (
                            str(event["source_port"])
                            if event["source_port"] is not None
                            else "—"
                        ),
                        "Destination IP": (
                            event["destination_ip"] or "—"
                        ),
                        "Destination Port": (
                            str(event["destination_port"])
                            if event["destination_port"] is not None
                            else "—"
                        ),
                        "Protocol": event["protocol"] or "—",
                        "Event Type": event["event_type"] or "—",
                    }
                )

            st.dataframe(
                rows,
                width="stretch",
                hide_index=True,
                height=360,
            )

    # ---------------------------------------------------------
    # FLOW SUMMARY
    # ---------------------------------------------------------

    flows = {}

    for event in events:
        key = (
            event["source_ip"] or "—",
            event["destination_ip"] or "—",
            event["protocol"] or "—",
            event["destination_port"],
        )

        flow = flows.setdefault(
            key,
            {
                "Source IP": key[0],
                "Destination IP": key[1],
                "Protocol": key[2],
                "Destination Port": (
                    str(key[3]) if key[3] is not None else "—"
                ),
                "Event Count": 0,
                "First Seen": event["timestamp"],
                "Last Seen": event["timestamp"],
            },
        )

        flow["Event Count"] += 1

        timestamp = event["timestamp"]

        if timestamp:
            if not flow["First Seen"] or timestamp < flow["First Seen"]:
                flow["First Seen"] = timestamp
            if not flow["Last Seen"] or timestamp > flow["Last Seen"]:
                flow["Last Seen"] = timestamp

    with st.container(border=True):
        section_title(
            "Flow summary",
            "Aggregated conversations from captured metadata.",
        )

        flow_rows = sorted(
            flows.values(),
            key=lambda row: row["Event Count"],
            reverse=True,
        )[:15]

        for row in flow_rows:
            row["First Seen"] = format_timestamp(row["First Seen"])
            row["Last Seen"] = format_timestamp(row["Last Seen"])

        st.dataframe(
            flow_rows,
            width="stretch",
            hide_index=True,
        )


def event_value(event, key, default=None):
    try:
        keys = event.keys()
    except (AttributeError, TypeError):
        return default

    if key not in keys:
        return default

    return event[key]


def describe_direction(event):
    direction = event_value(event, "direction")

    labels = {
        "inbound": "Inbound",
        "outbound": "Outbound",
        "local": "Local",
        "unknown": "Unknown",
    }

    if direction is None:
        return "Unknown"

    return labels.get(
        str(direction).strip().lower(),
        "Unknown",
    )


def describe_initiation(event):
    initiated = event_value(event, "initiated")

    if initiated is None:
        return "Unknown"

    try:
        return "Yes" if int(initiated) == 1 else "No"
    except (TypeError, ValueError):
        return "Unknown"


def network_event_matches_filters(
    event,
    direction,
    initiation,
    protocol,
    origin,
):
    if (
        direction != "All"
        and describe_direction(event) != direction
    ):
        return False

    if (
        initiation != "All"
        and describe_initiation(event) != initiation
    ):
        return False

    if protocol != "All":
        if str(event_value(event, "protocol") or "").upper() != protocol:
            return False

    if origin != "All":
        event_origin = normalise_origin(
            event_value(event, "event_origin")
        )

        if event_origin != origin:
            return False

    return True


# =============================================================
# PAGE: EVENT EXPLORER
# =============================================================

def render_event_explorer():
    page_header(
        "Telemetry / events",
        "Event Explorer",
        "Search the raw event store with server-side filtering and "
        "pagination. Large tables are never loaded in full.",
    )

    filter_cols = st.columns([1, 2, 1, 1])

    with filter_cols[0]:
        origin_label = st.selectbox(
            "Origin",
            ORIGIN_OPTIONS,
            key="explorer_origin_filter",
        )

    with filter_cols[1]:
        search = st.text_input(
            "Search events",
            placeholder="IP, event type, user, path or source",
            key="explorer_search",
        ).strip()

    with filter_cols[2]:
        page_size = st.selectbox(
            "Rows per page",
            [25, 50, 100, 250],
            index=1,
            key="explorer_page_size",
        )

    with filter_cols[3]:
        page = st.number_input(
            "Page",
            min_value=1,
            value=1,
            step=1,
            key="explorer_page",
        )

    origin = ORIGIN_FILTERS[origin_label]

    total = database.count_events(origin, search)
    max_page = max(1, (total + page_size - 1) // page_size)

    page = min(int(page), max_page)
    offset = (page - 1) * page_size

    rows = database.get_events_page(
        origin=origin,
        search=search,
        limit=page_size,
        offset=offset,
    )

    st.caption(
        f"{total:,} events match · page {page} of {max_page} · "
        f"showing {len(rows)} rows"
    )

    if not rows:
        st.info(
            "No events match the selected origin and search. Historical "
            "events without a recorded origin appear under Unknown."
        )
        return

    with st.container(border=True):
        st.dataframe(
            event_table_rows(rows),
            width="stretch",
            hide_index=True,
            height=520,
        )

    st.caption(
        "Origin is recorded by the producer: LIVE for captured network "
        "traffic, SYNTHETIC for generated demonstrations, UNKNOWN for "
        "historical rows that predate origin labelling."
    )


# =============================================================
# PAGE: SYNTHETIC LAB
# =============================================================

def render_synthetic_lab():
    page_header(
        "Demonstration / synthetic data",
        "Synthetic Lab",
        "Exercise the full detection pipeline with clearly labelled "
        "simulated events. Nothing is generated until you press the button.",
    )

    st.markdown(
        """
        <div class="banner banner-synthetic">
            <strong>Simulated data</strong> · Every event created here is
            stored with origin SYNTHETIC and is visually distinguished from
            live network observations throughout SENTRY. Synthetic events
            are useful for demonstrations, rule testing and onboarding.
        </div>
        """,
        unsafe_allow_html=True,
    )

    control_col, action_col = st.columns([1.2, 1])

    with control_col:
        with st.container(border=True):
            section_title(
                "Configure a scenario",
                "Five scenarios cover normal traffic and common attacks.",
            )

            scenario_label = st.selectbox(
                "Security scenario",
                list(SCENARIOS.keys()),
                key="synthetic_scenario",
            )

            intensity = st.selectbox(
                "Attack intensity",
                ["Low", "Medium", "High", "Critical"],
                index=1,
                key="synthetic_intensity",
            )

            st.caption(
                "Detection thresholds, evidence, severity and MITRE "
                "mappings are identical to live processing."
            )

    with action_col:
        with st.container(border=True):
            section_title("Generate")

            st.write(
                "Generation is an explicit action. SENTRY never seeds "
                "synthetic events at startup."
            )

            generate = st.button(
                "Generate synthetic events",
                type="primary",
                width="stretch",
                key="generate_synthetic",
            )

    if generate:
        events = generator.generate(
            scenario=SCENARIOS[scenario_label],
            intensity=intensity.lower(),
        )

        alerts = pipeline.process_events(events)

        st.session_state.last_synthetic_run = {
            "timestamp": datetime.now().isoformat(),
            "scenario": scenario_label,
            "intensity": intensity,
            "events": len(events),
            "alerts": len(alerts),
        }

        st.rerun()

    summary = st.session_state.get("last_synthetic_run")

    if summary:
        st.markdown("")

        summary_cols = st.columns(4)

        with summary_cols[0]:
            metric_card(
                "Scenario",
                summary["scenario"],
                summary["intensity"],
                "accent",
            )

        with summary_cols[1]:
            metric_card(
                "Events generated",
                f"{summary['events']:,}",
                "Stored as SYNTHETIC",
                "accent",
            )

        with summary_cols[2]:
            metric_card(
                "Alerts generated",
                f"{summary['alerts']:,}",
                "New detections",
                "high",
            )

        with summary_cols[3]:
            metric_card(
                "Generated at",
                format_timestamp(summary["timestamp"]),
                "Local time",
                "muted",
            )

        st.caption(
            f"Last run · {summary['scenario']} "
            f"({summary['intensity'].lower()} intensity) · "
            f"{summary['events']} events · {summary['alerts']} alerts."
        )

    # ---------------------------------------------------------
    # SYNTHETIC DATA IN THE STORE
    # ---------------------------------------------------------

    origin_counts = {
        row["origin"]: row["count"]
        for row in database.get_event_origin_counts()
    }

    synthetic_total = origin_counts.get("SYNTHETIC", 0)

    with st.container(border=True):
        section_title(
            "Synthetic events in the database",
            f"{synthetic_total:,} events are currently labelled SYNTHETIC.",
        )

        synthetic_events = database.get_events_page(
            origin="SYNTHETIC",
            limit=15,
        )

        if not synthetic_events:
            st.info(
                "No synthetic events have been generated yet. Choose a "
                "scenario above and press Generate synthetic events."
            )
        else:
            st.dataframe(
                event_table_rows(synthetic_events),
                width="stretch",
                hide_index=True,
            )

            st.caption(
                "These events are demonstrations. They do not represent "
                "network activity observed on this machine."
            )

    # ---------------------------------------------------------
    # RECENT SYNTHETIC ALERTS
    # ---------------------------------------------------------

    recent_alerts = database.get_recent_alerts(limit=100)
    synthetic_alerts = [
        alert
        for alert in recent_alerts
        if normalise_origin(
            alert["event_origin"]
            if "event_origin" in alert.keys()
            else None
        )
        == "SYNTHETIC"
    ]

    if synthetic_alerts:
        with st.container(border=True):
            section_title(
                "Recent synthetic alerts",
                "Detections produced by demonstration events.",
            )

            st.dataframe(
                alert_table_rows(synthetic_alerts[:10]),
                width="stretch",
                hide_index=True,
            )


# =============================================================
# PAGE: DETECTION RULES
# =============================================================

def render_detection_rules():
    page_header(
        "Configuration / detection",
        "Detection Rules",
        "Read-only view of the active rule configuration. Rule behaviour "
        "and thresholds are unchanged in this release.",
    )

    rules_config = load_rules_config()

    rows = []

    for rule_id, metadata in RULE_METADATA.items():
        config = rules_config.get(rule_id, {})
        mitre = metadata.get("mitre") or {}

        rows.append(
            {
                "Rule ID": rule_id,
                "Name": metadata.get("name", "—"),
                "Severity": metadata.get("severity", "—"),
                "Enabled": (
                    "Yes" if config.get("enabled", True) else "No"
                ),
                "Threshold": str(
                    config.get("threshold", "—")
                ),
                "Window (s)": str(
                    config.get("window_seconds", "—")
                ),
                "Cooldown (s)": str(
                    config.get("dedup_cooldown_seconds", "—")
                ),
                "MITRE ID": mitre.get("technique_id", "—"),
            }
        )

    with st.container(border=True):
        st.dataframe(
            rows,
            width="stretch",
            hide_index=True,
        )

    for rule_id, metadata in RULE_METADATA.items():
        mitre = metadata.get("mitre") or {}
        config = rules_config.get(rule_id, {})

        with st.expander(
            f"{metadata.get('name', rule_id)} · {rule_id}",
        ):
            st.write(metadata.get("description", "—"))

            st.caption(
                f"MITRE ATT&CK · "
                f"{mitre.get('technique_id', '—')} "
                f"{mitre.get('technique', '')} · "
                f"{mitre.get('tactic', '—')}   |   "
                f"Threshold · {config.get('threshold', '—')}   |   "
                f"Window · {config.get('window_seconds', '—')} seconds"
            )

            actions = metadata.get("recommended_actions") or []

            if actions:
                st.markdown("**Recommended actions**")

                for action in actions:
                    st.markdown(f"- {action}")

    st.caption(
        "Edit config/detection_rules.json to enable or disable rules and "
        "change thresholds. Changes apply on the next pipeline run."
    )


# =============================================================
# PAGE: ABOUT
# =============================================================

def render_about():
    page_header(
        "Product / information",
        "About SENTRY",
        "A local-first, rule-based SIEM with explainable detections, "
        "live capture and clearly separated demonstration data.",
    )

    origin_counts = {
        row["origin"]: row["count"]
        for row in database.get_event_origin_counts()
    }

    alert_origins = {
        row["origin"]: row["count"]
        for row in database.get_alert_origin_counts()
    }

    db_file = Path(DATABASE_PATH)
    db_size = (
        db_file.stat().st_size / (1024 * 1024)
        if db_file.exists()
        else 0
    )

    col1, col2 = st.columns(2)

    with col1:
        with st.container(border=True):
            section_title("Deployment")

            st.markdown(
                f"""
                <div class="muted" style="line-height:2;">
                Version <strong>{esc(SENTRY_VERSION)}</strong><br>
                Database <span class="mono">{esc(db_file.resolve())}</span><br>
                Size <strong>{db_size:.1f} MB</strong><br>
                Events <strong>{database.get_event_count():,}</strong><br>
                Alerts <strong>{database.get_alert_count():,}</strong><br>
                Python <strong>{esc(sys.version.split()[0])}</strong><br>
                Npcap <strong>{'available' if npcap_available() else 'not detected'}</strong>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with col2:
        with st.container(border=True):
            section_title("Data provenance")

            st.markdown(
                f"""
                <div style="line-height:2.1;">
                {origin_badge('LIVE')}
                <strong>{origin_counts.get('LIVE', 0):,}</strong>
                events / <strong>{alert_origins.get('LIVE', 0):,}</strong> alerts<br>
                {origin_badge('SYNTHETIC')}
                <strong>{origin_counts.get('SYNTHETIC', 0):,}</strong>
                events / <strong>{alert_origins.get('SYNTHETIC', 0):,}</strong> alerts<br>
                {origin_badge('UNKNOWN')}
                <strong>{origin_counts.get('UNKNOWN', 0):,}</strong>
                events / <strong>{alert_origins.get('UNKNOWN', 0):,}</strong> alerts
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.caption(
                "Origin is recorded when an event is produced. Historical "
                "rows are never reclassified by guessing."
            )

    with st.container(border=True):
        section_title("Operating principles")

        st.markdown(
            """
            - **Local-first** — events, alerts and investigations live in
              SQLite on this machine.
            - **Explainable** — every alert carries the rule, conditions,
              evidence, MITRE mapping and recommended actions.
            - **Honest provenance** — SYNTHETIC demonstration data and LIVE
              captured traffic are separate and labelled.
            - **Bounded queries** — dashboards read recent or aggregated
              data instead of loading the entire event store.
            - **No hidden automation** — synthetic events are only created
              by an explicit action in the Synthetic Lab.
            """
        )

    st.caption(
        "Documentation: README.md, docs/ARCHITECTURE.md and "
        "docs/DETECTIONS.md in the project directory."
    )


# =============================================================
# SIDEBAR AND ROUTING
# =============================================================

st.sidebar.markdown(
    """
    <div class="brand">
        <svg width="38" height="42" viewBox="0 0 38 42" fill="none"
             xmlns="http://www.w3.org/2000/svg">
            <path d="M19 2L35 8V20C35 30 28.5 37 19 40C9.5 37 3 30 3 20V8L19 2Z"
                  stroke="#22d3ee" stroke-width="2"/>
            <path d="M19 8L29 12V20C29 26.5 25 31 19 33.5C13 31 9 26.5 9 20V12L19 8Z"
                  fill="#0e7490" fill-opacity="0.35"/>
            <path d="M13 20L17 24L25 15" stroke="#a5f3fc" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <div>
            <div class="brand-name">SENTRY</div>
            <div class="brand-sub">SECURITY OPERATIONS</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.sidebar.markdown(
    '<div class="nav-label">OPERATIONS</div>',
    unsafe_allow_html=True,
)

selected_page = st.sidebar.radio(
    "Navigation",
    NAV_PAGES,
    label_visibility="collapsed",
    key="nav_page",
)

running = network_monitor_running()

st.sidebar.markdown(
    f"""
    <div class="sidebar-status">
        <div><span class="dot {'dot-live' if running else 'dot-idle'}"></span>
        <strong>{'Live capture running' if running else 'Live capture idle'}</strong></div>
        <div><span class="dot dot-live"></span>SQLite connected</div>
        <div><span class="dot {'dot-live' if npcap_available() else 'dot-warn'}"></span>
        {'Npcap available' if npcap_available() else 'Npcap not detected'}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.sidebar.markdown(
    f'<div class="sidebar-footer">SENTRY v{esc(SENTRY_VERSION)}<br>'
    "Local-first · rule-based · explainable</div>",
    unsafe_allow_html=True,
)

if selected_page == NAV_PAGES[0]:
    render_overview()
elif selected_page == NAV_PAGES[1]:
    render_live_monitoring()
elif selected_page == NAV_PAGES[2]:
    render_alerts()
elif selected_page == NAV_PAGES[3]:
    render_network_activity()
elif selected_page == NAV_PAGES[4]:
    render_event_explorer()
elif selected_page == NAV_PAGES[5]:
    render_synthetic_lab()
elif selected_page == NAV_PAGES[6]:
    render_detection_rules()
else:
    render_about()

render_footer()
