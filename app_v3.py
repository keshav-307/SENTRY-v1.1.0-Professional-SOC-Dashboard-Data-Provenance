import json

import streamlit as st
from collections import Counter
import threading

from scapy.all import conf

from core.database import SentryDatabase
from core.generator import EventGenerator
from core.pipeline import SentryPipeline
from sensors.network_sensor import NetworkSensor


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="SENTRY — Security Monitoring",
    page_icon="🛡️",
    layout="wide",
)


# =========================================================
# SENTRY UI — PROFESSIONAL SIEM/SOC TYPOGRAPHY
# =========================================================

st.markdown(
    """
    <style>

    /* =====================================================
       GLOBAL TYPOGRAPHY
       ===================================================== */

    html,
    body,
    [class*="css"] {
        font-family:
            "Inter",
            "Segoe UI",
            Roboto,
            Helvetica,
            Arial,
            sans-serif;
    }

    .stApp {
        font-size: 14px;
    }

    .stMarkdown,
    .stMarkdown p,
    .stMarkdown li {
        font-size: 14px;
        line-height: 1.45;
    }


    /* =====================================================
       MAIN HEADER
       ===================================================== */

    h1 {
        font-size: 30px !important;
        font-weight: 700 !important;
        letter-spacing: -0.5px;
        line-height: 1.15 !important;
        margin-bottom: 4px !important;
    }

    h2 {
        font-size: 20px !important;
        font-weight: 650 !important;
        letter-spacing: -0.2px;
        line-height: 1.25 !important;
        margin-top: 18px !important;
        margin-bottom: 8px !important;
    }

    h3 {
        font-size: 16px !important;
        font-weight: 600 !important;
        line-height: 1.3 !important;
        margin-top: 12px !important;
        margin-bottom: 6px !important;
    }


    /* =====================================================
       METRICS
       ===================================================== */

    [data-testid="stMetric"] {
        padding: 4px 2px;
    }

    [data-testid="stMetricLabel"] {
        font-size: 11px !important;
        font-weight: 600 !important;
        letter-spacing: 0.7px;
        text-transform: uppercase;
    }

    [data-testid="stMetricValue"] {
        font-size: 26px !important;
        font-weight: 700 !important;
        line-height: 1.1 !important;
    }

    [data-testid="stMetricDelta"] {
        font-size: 11px !important;
    }


    /* =====================================================
       SIDEBAR
       ===================================================== */

    section[data-testid="stSidebar"] {
        font-size: 13px;
    }

    section[data-testid="stSidebar"] h1 {
        font-size: 20px !important;
    }

    section[data-testid="stSidebar"] h2 {
        font-size: 16px !important;
    }

    section[data-testid="stSidebar"] p,
    section[data-testid="stSidebar"] label {
        font-size: 13px !important;
    }

    section[data-testid="stSidebar"] .stMarkdown {
        font-size: 13px !important;
    }


    /* =====================================================
       FORM CONTROLS
       ===================================================== */

    .stSelectbox label,
    .stTextInput label,
    .stTextArea label {
        font-size: 12px !important;
        font-weight: 600 !important;
    }

    .stSelectbox div,
    .stTextInput input,
    .stTextArea textarea {
        font-size: 13px !important;
    }


    /* =====================================================
       BUTTONS
       ===================================================== */

    .stButton > button {
        font-size: 13px !important;
        font-weight: 600 !important;
        letter-spacing: 0.15px;
        min-height: 36px;
    }


    /* =====================================================
       ALERT / STATUS BOXES
       ===================================================== */

    [data-testid="stAlert"] {
        font-size: 13px !important;
        line-height: 1.4 !important;
    }

    [data-testid="stAlert"] p {
        font-size: 13px !important;
    }


    /* =====================================================
       EXPANDERS
       ===================================================== */

    [data-testid="stExpander"] summary {
        font-size: 13px !important;
        font-weight: 600 !important;
    }

    [data-testid="stExpander"] .stMarkdown,
    [data-testid="stExpander"] p {
        font-size: 13px !important;
        line-height: 1.4 !important;
    }


    /* =====================================================
       CODE / LOG DATA
       ===================================================== */

    code {
        font-family:
            "Cascadia Code",
            "Consolas",
            "SFMono-Regular",
            monospace !important;

        font-size: 12px !important;
    }

    pre {
        font-family:
            "Cascadia Code",
            "Consolas",
            monospace !important;

        font-size: 12px !important;
        line-height: 1.45 !important;
    }


    /* =====================================================
       CAPTIONS
       ===================================================== */

    .stCaption,
    [data-testid="stCaptionContainer"] {
        font-size: 11px !important;
        line-height: 1.35 !important;
    }


    /* =====================================================
       QUICK NAVIGATION
       ===================================================== */

    .sentry-nav {
        font-size: 12px;
        line-height: 1.5;
        font-weight: 500;
    }

    .sentry-nav a {
        font-size: 12px;
        text-decoration: none;
    }


    /* =====================================================
       DENSE DASHBOARD SPACING
       ===================================================== */

    [data-testid="stVerticalBlock"] .stMarkdown p {
        margin-bottom: 4px;
    }

    [data-testid="stVerticalBlock"] {
        gap: 0.55rem;
    }

    hr {
        margin-top: 10px !important;
        margin-bottom: 10px !important;
    }


    /* =====================================================
       FOOTER
       ===================================================== */

    .sentry-footer {
        font-size: 11px;
        opacity: 0.65;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# INITIALIZE SENTRY COMPONENTS
# =========================================================

if "generator" not in st.session_state:
    st.session_state.generator = EventGenerator()

if "pipeline" not in st.session_state:
    st.session_state.pipeline = SentryPipeline()

if "database" not in st.session_state:
    st.session_state.database = SentryDatabase()

if "network_monitor_thread" not in st.session_state:
    st.session_state.network_monitor_thread = None


generator = st.session_state.generator
pipeline = st.session_state.pipeline
database = st.session_state.database


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ SENTRY")

st.subheader(
    "Security Monitoring & Threat Detection Platform"
)

st.write(
    "Persistent security monitoring powered by "
    "event generation, detection rules, and SQLite."
)


# =========================================================
# SIDEBAR — EVENT GENERATOR
# =========================================================

st.sidebar.title("⚙️ Event Generator")

st.sidebar.caption(
    "Events created here are SYNTHETIC test data and are "
    "stored alongside real captured events."
)

scenario = st.sidebar.selectbox(
    "Security Scenario",
    [
        "Normal Traffic",
        "SSH Brute Force",
        "SQL Injection",
        "Path Traversal",
        "Mixed Attack Campaign",
    ],
)

intensity = st.sidebar.selectbox(
    "Attack Intensity",
    [
        "Low",
        "Medium",
        "High",
        "Critical",
    ],
    index=1,
)

scenario_map = {
    "Normal Traffic": "normal",
    "SSH Brute Force": "ssh_brute_force",
    "SQL Injection": "sql_injection",
    "Path Traversal": "path_traversal",
    "Mixed Attack Campaign": "mixed",
}


st.sidebar.markdown("---")


if st.sidebar.button(
    "🚨 GENERATE EVENTS",
    width="stretch",
    type="primary",
):
    selected_scenario = scenario_map[scenario]

    events = generator.generate(
        scenario=selected_scenario,
        intensity=intensity.lower(),
    )

    pipeline.process_events(events)

    st.rerun()


# =========================================================
# SIDEBAR — QUICK NAVIGATION
# =========================================================

st.sidebar.markdown("---")

with st.sidebar.expander(
    "🧭 QUICK NAVIGATION",
    expanded=True,
):
    st.markdown(
        """
        <div class="sentry-nav">

        <a href="#security-overview">
        📊 Security Overview
        </a><br>

        <a href="#live-network-monitoring">
        🌐 Live Network Monitoring
        </a><br>

        <a href="#network-activity">
        🌐 Network Activity
        </a><br>

        <a href="#recent-security-alerts">
        🚨 Recent Security Alerts
        </a><br>

        <a href="#attack-analysis">
        📈 Attack Analysis
        </a><br>

        <a href="#recent-event-stream">
        📡 Event Stream
        </a>

        </div>
        """,
        unsafe_allow_html=True,
    )


# =========================================================
# NETWORK EVENT METADATA DISPLAY
# =========================================================

def _event_value(event, key, default=None):
    """
    Read one column from a sqlite Row or dict without raising when the
    column is absent. Keeps the dashboard robust for databases that
    have not been migrated yet.
    """

    try:
        keys = event.keys()
    except (AttributeError, TypeError):
        return default

    if key not in keys:
        return default

    return event[key]


def _port_display(port):
    """Render a port number, or an em dash when there is no port."""

    if port is None:
        return "—"

    return str(port)


def describe_event_direction(event):
    """
    Return a readable direction label for a captured network event.

    The value comes from capture-time metadata, never from guessing
    based on port numbers. Historical events without metadata are
    shown as Unknown.
    """

    direction = _event_value(event, "direction")

    labels = {
        "inbound": "⬅️ Inbound",
        "outbound": "➡️ Outbound",
        "local": "🔁 Local",
        "unknown": "❔ Unknown",
    }

    if direction is None:
        return "❔ Unknown"

    return labels.get(
        str(direction).strip().lower(),
        "❔ Unknown",
    )


def describe_connection_initiation(event):
    """
    Return whether this packet begins a connection.

    Yes  = TCP SYN without ACK, or the first packet of a UDP flow.
    No   = a reply or a mid-stream packet.
    Unknown = historical events without metadata, and protocols such
              as ICMP that have no connection initiation.
    """

    initiated = _event_value(event, "initiated")

    if initiated is None:
        return "❔ Unknown"

    try:
        return "✅ Yes" if int(initiated) == 1 else "❌ No"
    except (TypeError, ValueError):
        return "❔ Unknown"


def normalise_direction_filter(event):
    """
    Map stored direction metadata to a filter bucket.

    NULL and unrecognised values are treated as Unknown so historical
    events can always be found with the Unknown filter.
    """

    direction = _event_value(event, "direction")

    if direction is None:
        return "Unknown"

    return {
        "inbound": "Inbound",
        "outbound": "Outbound",
        "local": "Local",
        "unknown": "Unknown",
    }.get(
        str(direction).strip().lower(),
        "Unknown",
    )


def normalise_initiation_filter(event):
    """
    Map stored initiation metadata to a filter bucket.

    NULL means the metadata was never captured, so it is Unknown
    rather than being guessed from port numbers.
    """

    initiated = _event_value(event, "initiated")

    if initiated is None:
        return "Unknown"

    try:
        return (
            "Initiated"
            if int(initiated) == 1
            else "Not Initiated"
        )
    except (TypeError, ValueError):
        return "Unknown"


def network_event_matches_filters(
    event,
    direction_filter,
    initiation_filter,
    protocol_filter,
):
    """
    Return True when an event satisfies every selected filter.

    Filters combine with AND: an event must match direction,
    initiation and protocol before it is displayed.
    """

    if (
        direction_filter != "All"
        and normalise_direction_filter(event)
        != direction_filter
    ):
        return False

    if (
        initiation_filter != "All"
        and normalise_initiation_filter(event)
        != initiation_filter
    ):
        return False

    if protocol_filter != "All":

        protocol = (
            _event_value(event, "protocol") or ""
        )

        if str(protocol).strip().upper() != protocol_filter:
            return False

    return True


# =========================================================
# NETWORK INTERFACE DISCOVERY
# =========================================================

def get_capture_interfaces():
    """
    Discover usable Scapy/Npcap network interfaces.

    Returns:
        Dictionary mapping a user-friendly dashboard label
        to the corresponding Scapy interface object.
    """

    interfaces = {}

    for iface in conf.ifaces.values():

        name = getattr(
            iface,
            "name",
            None,
        )

        description = getattr(
            iface,
            "description",
            None,
        )

        ip_address = getattr(
            iface,
            "ip",
            None,
        )

        guid = getattr(
            iface,
            "guid",
            None,
        )

        if not name or not guid:
            continue

        description_lower = (
            description.lower()
            if description
            else ""
        )

        # Skip Windows WAN Miniport interfaces.
        if "wan miniport" in description_lower:
            continue

        # Skip Microsoft Wi-Fi Direct virtual adapters.
        if "wi-fi direct" in description_lower:
            continue

        # =====================================================
        # FRIENDLY DASHBOARD LABEL
        #
        # Green  = active IPv4 address
        # Blue   = loopback
        # White  = no active IPv4 / APIPA address
        # =====================================================

        if name == "Loopback Pseudo-Interface 1":

            label = "🔵 Loopback — 127.0.0.1"

        elif (
            ip_address
            and not str(ip_address).startswith("169.254.")
        ):

            label = f"🟢 {name} — {ip_address}"

        else:

            label = f"⚪ {name} — No active IPv4"

        interfaces[label] = iface

    return interfaces


# =========================================================
# NETWORK MONITOR STATE
# =========================================================

def _network_monitor_running():

    thread = (
        st.session_state.network_monitor_thread
    )

    return (
        thread is not None
        and thread.is_alive()
    )


duration_options = {
    "10 seconds": 10,
    "30 seconds": 30,
    "1 minute": 60,
    "5 minutes": 300,
    "10 minutes": 600,
    "Continuous": None,
}


# =========================================================
# MAIN DASHBOARD
#
# Refreshes automatically every second so live network
# statistics and database-backed metrics stay current.
# =========================================================

@st.fragment(run_every=1)
def dashboard():

    # =====================================================
    # LIVE NETWORK MONITORING
    # =====================================================

    st.markdown(
        '<div id="live-network-monitoring"></div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        "## 🌐 LIVE NETWORK MONITORING"
    )

    st.write(
        "Monitor real network traffic through SENTRY using "
        "Scapy/Npcap. Captured packet metadata is converted "
        "into security events and sent directly to the "
        "detection pipeline."
    )

    monitoring_running = _network_monitor_running()

    # =====================================================
    # NETWORK INTERFACE SELECTION
    # =====================================================

    capture_interfaces = get_capture_interfaces()

    if not capture_interfaces:

        st.error(
            "No usable network capture interfaces were detected."
        )

        st.stop()

    interface_labels = list(
        capture_interfaces.keys()
    )

    if (
        "selected_network_interface"
        not in st.session_state
        or
        st.session_state.selected_network_interface
        not in interface_labels
    ):

        st.session_state.selected_network_interface = (
            interface_labels[0]
        )

    selected_interface_label = st.selectbox(
        "Network Interface",
        interface_labels,
        index=interface_labels.index(
            st.session_state.selected_network_interface
        ),
        disabled=monitoring_running,
        key="network_interface_selector",
    )

    selected_interface = capture_interfaces[
        selected_interface_label
    ]

    st.session_state.selected_network_interface = (
        selected_interface_label
    )

    interface_ip = getattr(
        selected_interface,
        "ip",
        None,
    )

    interface_description = getattr(
        selected_interface,
        "description",
        None,
    )

    st.caption(
        f"Adapter: "
        f"{interface_description or 'Unknown'}"
        f"  •  IP: "
        f"{interface_ip or 'No IP assigned'}"
    )

    # =====================================================
    # CREATE SENSOR FOR SELECTED INTERFACE
    # =====================================================

    if (
        "network_sensor" not in st.session_state
        or st.session_state.network_sensor is None
        or (
            not monitoring_running
            and st.session_state.get(
                "network_sensor_interface_label"
            ) != selected_interface_label
        )
    ):

        st.session_state.network_sensor = NetworkSensor(
            pipeline=st.session_state.pipeline,
            interface=selected_interface,
        )

        st.session_state.network_sensor_interface_label = (
            selected_interface_label
        )

    network_sensor = (
        st.session_state.network_sensor
    )

    # =====================================================
    # MONITORING METRICS
    # =====================================================

    monitor_col1, monitor_col2, monitor_col3 = st.columns(
        [1.4, 1, 1]
    )

    with monitor_col1:

        selected_duration = st.selectbox(
            "Capture Duration",
            list(duration_options.keys()),
            disabled=monitoring_running,
            key="capture_duration",
        )

    with monitor_col2:

        st.metric(
            "PACKETS CAPTURED",
            network_sensor.packet_count,
        )

    with monitor_col3:

        st.metric(
            "NETWORK EVENTS",
            network_sensor.event_count,
        )

    # =====================================================
    # START / STOP CONTROLS
    # =====================================================

    button_col1, button_col2 = st.columns(2)

    with button_col1:

        start_monitoring = st.button(
            "▶️ START MONITORING",
            width="stretch",
            type="primary",
            disabled=monitoring_running,
            key="start_network_monitor",
        )

    with button_col2:

        stop_monitoring = st.button(
            "⏹️ STOP MONITORING",
            width="stretch",
            disabled=not monitoring_running,
            key="stop_network_monitor",
        )

    # =====================================================
    # START MONITORING
    # =====================================================

    if start_monitoring:

        duration = duration_options[
            selected_duration
        ]

        monitor_thread = threading.Thread(
            target=network_sensor.start,
            kwargs={
                "duration": duration
            },
            daemon=True,
            name="sentry-network-monitor",
        )

        st.session_state.network_monitor_thread = (
            monitor_thread
        )

        monitor_thread.start()

        st.rerun(scope="fragment")

    # =====================================================
    # STOP MONITORING
    # =====================================================

    if stop_monitoring:

        network_sensor.stop()

        st.rerun(scope="fragment")

    # =====================================================
    # MONITORING STATUS
    # =====================================================

    monitoring_running = _network_monitor_running()

    if monitoring_running:

        st.success(
            "🟢 Live network monitoring is running. "
            "Real packets are being processed by SENTRY."
        )

    else:

        st.info(
            "⚪ Live network monitoring is stopped. "
            "Select a duration and press START MONITORING."
        )

    if network_sensor.last_error:

        st.error(
            f"Capture error: {network_sensor.last_error}"
        )

    live_col1, live_col2 = st.columns(2)

    with live_col1:

        st.metric(
            "NETWORK ALERTS",
            network_sensor.alert_count,
        )

    with live_col2:

        st.metric(
            "MONITORING STATUS",
            "RUNNING"
            if monitoring_running
            else "STOPPED",
        )

    # =====================================================
    # DATABASE STATISTICS
    # =====================================================

    total_events = database.get_event_count()

    total_alerts = database.get_alert_count()

    open_alerts = (
        database.get_open_alert_count()
    )

    investigating_alerts = (
        database.get_investigating_alert_count()
    )

    resolved_alerts = (
        database.get_resolved_alert_count()
    )

    false_positive_alerts = (
        database.get_false_positive_alert_count()
    )

    critical_count = (
        database.get_alert_count_by_severity(
            "CRITICAL"
        )
    )

    high_count = (
        database.get_alert_count_by_severity(
            "HIGH"
        )
    )

    medium_count = (
        database.get_alert_count_by_severity(
            "MEDIUM"
        )
    )

    low_count = (
        database.get_alert_count_by_severity(
            "LOW"
        )
    )

    # =====================================================
    # NETWORK ACTIVITY
    # =====================================================

    st.markdown(
        '<div id="network-activity"></div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        "## 🌐 NETWORK ACTIVITY"
    )

    st.write(
        "A concise view of recent live network traffic captured by SENTRY. "
        "Detailed telemetry is available below when investigation is needed."
    )

    # Keep this query bounded so the 1-second dashboard refresh
    # does not repeatedly scan an ever-growing database.
    recent_network_events = database.get_recent_network_events(
    limit=500
)

    network_event_count = len(
        recent_network_events
    )

    network_source_counts = Counter(
        event["source_ip"]
        for event in recent_network_events
        if event["source_ip"]
    )

    network_destination_counts = Counter(
        event["destination_ip"]
        for event in recent_network_events
        if event["destination_ip"]
    )

    network_protocol_counts = Counter(
        event["protocol"]
        for event in recent_network_events
        if event["protocol"]
    )

    network_port_counts = Counter(
        event["destination_port"]
        for event in recent_network_events
        if event["destination_port"] is not None
    )

    network_flow_keys = {
        (
            event["source_ip"],
            event["destination_ip"],
            event["protocol"],
            event["destination_port"],
        )
        for event in recent_network_events
    }

    network_metric1, network_metric2, network_metric3, network_metric4 = (
        st.columns(4)
    )

    with network_metric1:

        st.metric(
            "NETWORK EVENTS (LAST 500)",
            network_event_count,
        )

    with network_metric2:

        st.metric(
            "UNIQUE FLOWS",
            len(network_flow_keys),
        )

    with network_metric3:

        st.metric(
            "UNIQUE SOURCE IPS",
            len(network_source_counts),
        )

    recent_network_alerts = [
        alert
        for alert in database.get_recent_alerts(limit=500)
        if str(alert["rule_id"]).startswith("NET-")
    ]

    with network_metric4:

        st.metric(
            "NETWORK ALERTS",
            len(recent_network_alerts),
        )

    if recent_network_events:

        st.markdown(
            "### Traffic Snapshot"
        )

        protocol_items = (
            network_protocol_counts.most_common()
        )

        if protocol_items:

            protocol_columns = st.columns(
                min(len(protocol_items), 4)
            )

            for index, (
                protocol,
                count,
            ) in enumerate(
                protocol_items[:4]
            ):

                with protocol_columns[index]:

                    st.metric(
                        protocol,
                        count,
                    )

        st.markdown(
            "### Top Communicating Hosts"
        )

        # -------------------------------------------------
        # IDENTIFY LOCAL HOST ADDRESSES
        # -------------------------------------------------

        local_addresses = {
            "127.0.0.1",
            "::1",
        }

        for interface in capture_interfaces.values():

            interface_ip_value = getattr(
                interface,
                "ip",
                None,
            )

            if interface_ip_value:

                local_addresses.add(
                    str(interface_ip_value)
                )

        # -------------------------------------------------
        # BUILD HOST ACTIVITY SUMMARY
        # -------------------------------------------------

        host_activity = {}

        for event in recent_network_events:

            source_ip = (
                event["source_ip"]
                or "—"
            )

            destination_ip = (
                event["destination_ip"]
                or "—"
            )

            event_count = 1

            # ---------------------------------------------
            # SOURCE HOST
            # ---------------------------------------------

            if source_ip != "—":

                if source_ip not in host_activity:

                    host_activity[source_ip] = {
                        "Host": source_ip,
                        "Role": (
                            "LOCAL"
                            if source_ip in local_addresses
                            else "REMOTE"
                        ),
                        "Outbound Events": 0,
                        "Inbound Events": 0,
                        "Total Events": 0,
                    }

                host_activity[source_ip][
                    "Outbound Events"
                ] += event_count

                host_activity[source_ip][
                    "Total Events"
                ] += event_count

            # ---------------------------------------------
            # DESTINATION HOST
            # ---------------------------------------------

            if destination_ip != "—":

                if destination_ip not in host_activity:

                    host_activity[destination_ip] = {
                        "Host": destination_ip,
                        "Role": (
                            "LOCAL"
                            if destination_ip in local_addresses
                            else "REMOTE"
                        ),
                        "Outbound Events": 0,
                        "Inbound Events": 0,
                        "Total Events": 0,
                    }

                host_activity[destination_ip][
                    "Inbound Events"
                ] += event_count

                host_activity[destination_ip][
                    "Total Events"
                ] += event_count

        host_rows = sorted(
            host_activity.values(),
            key=lambda row: row["Total Events"],
            reverse=True,
        )[:10]

        # -------------------------------------------------
        # DISPLAY HOST ACTIVITY
        # -------------------------------------------------

        st.dataframe(
            host_rows,
            width="stretch",
            hide_index=True,
            column_config={
                "Host": st.column_config.TextColumn(
                    "Host",
                    width="large",
                ),
                "Role": st.column_config.TextColumn(
                    "Role",
                    width="small",
                ),
                "Outbound Events": st.column_config.NumberColumn(
                    "Outbound",
                    width="small",
                ),
                "Inbound Events": st.column_config.NumberColumn(
                    "Inbound",
                    width="small",
                ),
                "Total Events": st.column_config.NumberColumn(
                    "Total Events",
                    width="small",
                ),
            },
        )

        st.caption(
            "LOCAL hosts are addresses assigned to this system. "
            "REMOTE hosts are external systems observed in captured traffic."
        )

        with st.expander(
            "🔎 Detailed Network Telemetry"
        ):

            detail_col1, detail_col2 = (
                st.columns(2)
            )

            with detail_col1:

                st.markdown(
                    "### Top Destination Ports"
                )

                port_rows = [
                    {
                        "Destination Port": port,
                        "Events": count,
                    }
                    for port, count
                    in network_port_counts.most_common(10)
                ]

                st.dataframe(
                    port_rows,
                    width="stretch",
                    hide_index=True,
                )

            with detail_col2:

                st.markdown(
                    "### Protocol Distribution"
                )

                protocol_rows = [
                    {
                        "Protocol": protocol,
                        "Events": count,
                    }
                    for protocol, count
                    in network_protocol_counts.most_common()
                ]

                st.dataframe(
                    protocol_rows,
                    width="stretch",
                    hide_index=True,
                )

            # =================================================
            # RECENT NETWORK EVENTS
            # =================================================

            st.markdown(
                "### Recent Network Evidence"
            )

            # ---------------------------------------------
            # EVENT FILTERS
            # ---------------------------------------------

            (
                network_filter_col1,
                network_filter_col2,
                network_filter_col3,
                network_filter_col4,
            ) = st.columns(4)

            with network_filter_col1:

                direction_filter = st.selectbox(
                    "Direction",
                    [
                        "All",
                        "Inbound",
                        "Outbound",
                        "Local",
                        "Unknown",
                    ],
                    key="network_direction_filter",
                )

            with network_filter_col2:

                initiation_filter = st.selectbox(
                    "Connection Initiated",
                    [
                        "All",
                        "Initiated",
                        "Not Initiated",
                        "Unknown",
                    ],
                    key="network_initiation_filter",
                )

            with network_filter_col3:

                protocol_filter = st.selectbox(
                    "Protocol",
                    [
                        "All",
                        "TCP",
                        "UDP",
                        "IP",
                    ],
                    key="network_protocol_filter",
                )

            with network_filter_col4:

                display_limit = st.selectbox(
                    "Events Shown",
                    [15, 50, 100, 250, 500],
                    key="network_event_limit",
                )

            filtered_network_events = [
                event
                for event in recent_network_events
                if network_event_matches_filters(
                    event,
                    direction_filter,
                    initiation_filter,
                    protocol_filter,
                )
            ]

            visible_network_events = (
                filtered_network_events[:display_limit]
            )

            st.caption(
                f"Showing {len(visible_network_events)} of "
                f"{len(recent_network_events)} recent network "
                f"events. Filters: {direction_filter} direction · "
                f"{initiation_filter} connection · "
                f"{protocol_filter} protocol."
            )

            if not visible_network_events:

                st.info(
                    "No network events match the selected filters."
                )

            recent_event_rows = []

            for event in visible_network_events:

                timestamp = event["timestamp"]

                if timestamp is not None:

                    timestamp = str(
                        timestamp
                    ).replace(
                        "T",
                        " ",
                    )

                    # Keep the dashboard display compact
                    # while preserving the original database
                    # timestamp.
                    if "." in timestamp:

                        timestamp = (
                            timestamp.split(".")[0]
                        )

                source_ip = (
                    event["source_ip"]
                    or "—"
                )

                destination_ip = (
                    event["destination_ip"]
                    or "—"
                )

                recent_event_rows.append(
                    {
                        "Time": (
                            timestamp
                            or "—"
                        ),
                        "Direction": (
                            describe_event_direction(
                                event
                            )
                        ),
                        "Initiated": (
                            describe_connection_initiation(
                                event
                            )
                        ),
                        "Source IP": source_ip,
                        "Source Port": (
                            _port_display(
                                _event_value(
                                    event,
                                    "source_port",
                                )
                            )
                        ),
                        "Destination IP": destination_ip,
                        "Destination Port": (
                            _port_display(
                                _event_value(
                                    event,
                                    "destination_port",
                                )
                            )
                        ),
                        "Protocol": (
                            event["protocol"]
                            or "—"
                        ),
                        "Event Type": (
                            event["event_type"]
                            or "—"
                        ),
                    }
                )

            st.dataframe(
                recent_event_rows,
                width="stretch",
                hide_index=True,
                column_config={
                    "Time": st.column_config.TextColumn(
                        "Time",
                        width="medium",
                    ),
                    "Direction": st.column_config.TextColumn(
                        "Direction",
                        width="small",
                        help=(
                            "Direction of this packet relative to "
                            "this host, recorded at capture time. "
                            "Historical events show Unknown."
                        ),
                    ),
                    "Initiated": st.column_config.TextColumn(
                        "Initiated",
                        width="small",
                        help=(
                            "Yes = TCP SYN without ACK or first UDP "
                            "packet (connection initiation). "
                            "No = reply or mid-stream packet. "
                            "Unknown = historical event or a protocol "
                            "without connection setup."
                        ),
                    ),
                    "Source IP": st.column_config.TextColumn(
                        "Source IP",
                        width="large",
                    ),
                    "Source Port": st.column_config.TextColumn(
                        "Source Port",
                        width="small",
                    ),
                    "Destination IP": st.column_config.TextColumn(
                        "Destination IP",
                        width="large",
                    ),
                    "Destination Port": st.column_config.TextColumn(
                        "Destination Port",
                        width="small",
                    ),
                    "Protocol": st.column_config.TextColumn(
                        "Protocol",
                        width="small",
                    ),
                    "Event Type": st.column_config.TextColumn(
                        "Event Type",
                        width="medium",
                    ),
                },
            )

            st.caption(
                "Direction and initiation come from capture-time "
                "metadata. A ✅ Yes marks a connection initiation; "
                "a ❌ No marks a reply or mid-stream packet. "
                "Events captured before this metadata existed show "
                "❔ Unknown."
            )

            # =================================================
            # NETWORK FLOW SUMMARY
            # =================================================

            st.markdown(
                "### Network Flow Summary"
            )

            flow_groups = {}

            for event in recent_network_events:

                source_ip = (
                    event["source_ip"]
                    or "—"
                )

                destination_ip = (
                    event["destination_ip"]
                    or "—"
                )

                protocol = (
                    event["protocol"]
                    or "—"
                )

                destination_port = (
                    event["destination_port"]
                )

                flow_key = (
                    source_ip,
                    destination_ip,
                    protocol,
                    destination_port,
                )

                timestamp = event["timestamp"]

                if timestamp is not None:

                    timestamp = str(
                        timestamp
                    ).replace(
                        "T",
                        " ",
                    )

                if flow_key not in flow_groups:

                    flow_groups[flow_key] = {
                        "Source IP": source_ip,
                        "Destination IP": destination_ip,
                        "Protocol": protocol,
                        "Destination Port": (
                            str(destination_port)
                            if destination_port is not None
                            else "—"
                        ),
                        "Event Count": 0,
                        "First Seen": timestamp or "—",
                        "Last Seen": timestamp or "—",
                    }

                flow_groups[flow_key]["Event Count"] += 1

                current_first = (
                    flow_groups[flow_key]["First Seen"]
                )

                current_last = (
                    flow_groups[flow_key]["Last Seen"]
                )

                if timestamp:

                    if (
                        current_first == "—"
                        or timestamp < current_first
                    ):

                        flow_groups[flow_key][
                            "First Seen"
                        ] = timestamp

                    if (
                        current_last == "—"
                        or timestamp > current_last
                    ):

                        flow_groups[flow_key][
                            "Last Seen"
                        ] = timestamp

            flow_rows = sorted(
                flow_groups.values(),
                key=lambda row: row["Event Count"],
                reverse=True,
            )[:15]

            st.dataframe(
                flow_rows,
                width="stretch",
                hide_index=True,
                column_config={
                    "Source IP": st.column_config.TextColumn(
                        "Source IP",
                        width="large",
                    ),
                    "Destination IP": st.column_config.TextColumn(
                        "Destination IP",
                        width="large",
                    ),
                    "Protocol": st.column_config.TextColumn(
                        "Protocol",
                        width="small",
                    ),
                    "Destination Port": st.column_config.TextColumn(
                        "Destination Port",
                        width="small",
                    ),
                    "Event Count": st.column_config.NumberColumn(
                        "Event Count",
                        width="small",
                    ),
                    "First Seen": st.column_config.TextColumn(
                        "First Seen",
                        width="medium",
                    ),
                    "Last Seen": st.column_config.TextColumn(
                        "Last Seen",
                        width="medium",
                    ),
                },
            )

    else:

        st.info(
            "No network activity has been captured yet. "
            "Start live monitoring to begin collecting network events."
        )

    # =====================================================
    # SYSTEM STATUS
    # =====================================================

    st.markdown(
        "## SYSTEM STATUS"
    )

    status1, status2, status3 = st.columns(3)

    with status1:

        st.success(
            "🟢 Detection Engine Online"
        )

    with status2:

        st.success(
            "🟢 Database Connected"
        )

    with status3:

        if _network_monitor_running():

            st.success(
                "🟢 Live Monitoring Active"
            )

        else:

            st.info(
                "⚪ Live Monitoring Standby"
            )

    # =====================================================
    # SECURITY OVERVIEW
    # =====================================================

    st.markdown(
        '<div id="security-overview"></div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        "## SECURITY OVERVIEW"
    )

    metric1, metric2, metric3, metric4, metric5 = (
        st.columns(5)
    )

    with metric1:

        st.metric(
            "EVENTS PROCESSED",
            total_events,
        )

    with metric2:

        st.metric(
            "ALERTS GENERATED",
            total_alerts,
        )

    with metric3:

        st.metric(
            "OPEN ALERTS",
            open_alerts,
        )

    with metric4:

        st.metric(
            "INVESTIGATING",
            investigating_alerts,
        )

    with metric5:

        st.metric(
            "RESOLVED",
            resolved_alerts,
        )

    # =====================================================
    # ALERT LIFECYCLE
    # =====================================================

    st.markdown(
        "## 🚨 ALERT LIFECYCLE"
    )

    lifecycle1, lifecycle2, lifecycle3, lifecycle4 = (
        st.columns(4)
    )

    with lifecycle1:

        st.metric(
            "OPEN",
            open_alerts,
        )

    with lifecycle2:

        st.metric(
            "INVESTIGATING",
            investigating_alerts,
        )

    with lifecycle3:

        st.metric(
            "RESOLVED",
            resolved_alerts,
        )

    with lifecycle4:

        st.metric(
            "FALSE POSITIVE",
            false_positive_alerts,
        )

    # =====================================================
    # ALERT SEVERITY
    # =====================================================

    st.markdown(
        "## ⚠️ ALERT SEVERITY"
    )

    severity1, severity2, severity3, severity4 = (
        st.columns(4)
    )

    with severity1:

        st.metric(
            "CRITICAL",
            critical_count,
        )

    with severity2:

        st.metric(
            "HIGH",
            high_count,
        )

    with severity3:

        st.metric(
            "MEDIUM",
            medium_count,
        )

    with severity4:

        st.metric(
            "LOW",
            low_count,
        )

    # =====================================================
    # LOAD RECENT ALERTS
    # =====================================================

    recent_alerts = database.get_recent_alerts(
        limit=50
    )

    # =====================================================
    # RECENT SECURITY ALERTS
    # =====================================================

    st.markdown(
        '<div id="recent-security-alerts"></div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        "## 🚨 RECENT SECURITY ALERTS"
    )

    if not recent_alerts:

        st.info(
            "No security alerts have been recorded yet."
        )

    else:

        # -------------------------------------------------
        # FILTERS
        # -------------------------------------------------

        filter1, filter2, filter3 = (
            st.columns(3)
        )

        with filter1:

            severity_filter = st.selectbox(
                "Severity",
                [
                    "All",
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                ],
                key="alert_severity_filter",
            )

        with filter2:

            status_filter = st.selectbox(
                "Alert Status",
                [
                    "All",
                    "OPEN",
                    "INVESTIGATING",
                    "RESOLVED",
                    "FALSE_POSITIVE",
                ],
                key="alert_status_filter",
            )

        with filter3:

            detection_types = sorted(
                set(
                    alert["alert_type"]
                    for alert in recent_alerts
                )
            )

            detection_filter = st.selectbox(
                "Detection",
                ["All"] + detection_types,
                key="alert_detection_filter",
            )

        # -------------------------------------------------
        # SEARCH
        # -------------------------------------------------

        alert_search = st.text_input(
            "Search alerts (source IP, rule, type, detail)",
            key="alert_search",
        ).strip().lower()

        # -------------------------------------------------
        # APPLY FILTERS
        # -------------------------------------------------

        filtered_alerts = []

        for alert in recent_alerts:

            if (
                severity_filter != "All"
                and alert["severity"]
                != severity_filter
            ):

                continue

            if (
                status_filter != "All"
                and alert["status"]
                != status_filter
            ):

                continue

            if (
                detection_filter != "All"
                and alert["alert_type"]
                != detection_filter
            ):

                continue

            if alert_search:

                searchable = " ".join(
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

                if alert_search not in searchable:

                    continue

            filtered_alerts.append(
                alert
            )

        st.caption(
            f"Showing {len(filtered_alerts)} "
            f"of {len(recent_alerts)} recent alerts"
        )

        # -------------------------------------------------
        # DISPLAY ALERTS
        # -------------------------------------------------

        for alert in filtered_alerts:

            severity = alert["severity"]

            status = alert["status"]

            # ---------------------------------------------
            # SEVERITY ICON
            # ---------------------------------------------

            if severity == "CRITICAL":

                severity_icon = "🔴"

            elif severity == "HIGH":

                severity_icon = "🟠"

            elif severity == "MEDIUM":

                severity_icon = "🟡"

            else:

                severity_icon = "🟢"

            # ---------------------------------------------
            # STATUS ICON
            # ---------------------------------------------

            if status == "OPEN":

                status_icon = "🔓"

            elif status == "INVESTIGATING":

                status_icon = "🔎"

            elif status == "RESOLVED":

                status_icon = "✅"

            else:

                status_icon = "⚪"

            # ---------------------------------------------
            # ALERT EXPANDER
            # ---------------------------------------------

            with st.expander(
                f"{severity_icon} "
                f"{alert['alert_type']} "
                f"— {severity} "
                f"— {status_icon} {status}"
            ):

                # -----------------------------------------
                # ALERT INFORMATION
                # -----------------------------------------

                col1, col2 = st.columns(2)

                with col1:

                    st.write(
                        f"**Source IP:** "
                        f"{alert['source_ip']}"
                    )

                    st.write(
                        f"**Rule ID:** "
                        f"{alert['rule_id']}"
                    )

                    confidence_value = (
                        alert["confidence"]
                    )

                    confidence_display = (
                        f"{confidence_value:.0%}"
                        if isinstance(
                            confidence_value,
                            (int, float),
                        )
                        else "unknown"
                    )

                    st.write(
                        f"**Confidence:** "
                        f"{confidence_display}"
                    )

                with col2:

                    st.write(
                        f"**Timestamp:** "
                        f"{alert['timestamp']}"
                    )

                    st.write(
                        f"**Alert ID:** "
                        f"{alert['id']}"
                    )

                    st.write(
                        f"**Current Status:** "
                        f"`{status}`"
                    )

                # -----------------------------------------
                # DETECTION DETAILS
                # -----------------------------------------

                st.markdown(
                    "**Detection Details**"
                )

                st.code(
                    alert["detail"]
                )

                # -----------------------------------------
                # DETECTION EVIDENCE
                # -----------------------------------------

                st.markdown(
                    "**🧾 WHY SENTRY DETECTED THIS**"
                )

                evidence = None

                evidence_raw = alert["evidence_json"]

                if evidence_raw:

                    try:

                        evidence = json.loads(
                            evidence_raw
                        )

                    except (TypeError, ValueError):

                        evidence = None

                if not isinstance(evidence, dict):

                    st.info(
                        "Detection evidence is not available for "
                        "this historical alert."
                    )

                else:

                    evidence_mitre = (
                        evidence.get("mitre") or {}
                    )

                    st.write(
                        f"**Detection rule:** "
                        f"`{evidence.get('rule_id', alert['rule_id'])}`"
                        f" — "
                        f"{evidence.get('rule_name', alert['alert_type'])}"
                    )

                    if evidence.get("rule_description"):

                        st.write(
                            f"**Rule description:** "
                            f"{evidence['rule_description']}"
                        )

                    if evidence_mitre:

                        st.caption(
                            f"MITRE ATT&CK: "
                            f"{evidence_mitre.get('technique_id', '—')} "
                            f"{evidence_mitre.get('technique', '')} "
                            f"({evidence_mitre.get('tactic', '—')})"
                        )

                    if evidence.get("explanation"):

                        st.markdown(
                            "**Why this indicates suspicious activity:** "
                            f"{evidence['explanation']}"
                        )

                    evidence_conditions = (
                        evidence.get("conditions") or []
                    )

                    if evidence_conditions:

                        st.write(
                            "**Triggering conditions**"
                        )

                        st.dataframe(
                            [
                                {
                                    "Condition": (
                                        condition.get(
                                            "condition",
                                            "—",
                                        )
                                    ),
                                    "Expected": (
                                        condition.get(
                                            "expected",
                                            "—",
                                        )
                                    ),
                                    "Observed": (
                                        condition.get(
                                            "observed",
                                            "—",
                                        )
                                    ),
                                    "Result": (
                                        condition.get(
                                            "result",
                                            "—",
                                        )
                                    ),
                                }
                                for condition in evidence_conditions
                            ],
                            width="stretch",
                            hide_index=True,
                        )

                    evidence_window = (
                        evidence.get("window") or {}
                    )

                    if evidence_window:

                        st.caption(
                            f"Detection window: "
                            f"{evidence_window.get('start', '—')} "
                            f"→ "
                            f"{evidence_window.get('end', '—')} "
                            f"({evidence_window.get('seconds', '—')}s)"
                        )

                    evidence_threshold = (
                        evidence.get("threshold")
                    )

                    if evidence_threshold is not None:

                        st.caption(
                            f"Rule threshold: {evidence_threshold}"
                        )

                    triggering_events = (
                        evidence.get("triggering_events") or []
                    )

                    if triggering_events:

                        st.write(
                            "**Matching events that triggered this "
                            "alert**"
                        )

                        triggering_rows = []

                        for triggering_event in triggering_events:

                            event_time = (
                                triggering_event.get(
                                    "timestamp"
                                )
                                or "—"
                            )

                            event_time = (
                                str(event_time)
                                .replace("T", " ")
                                .split(".")[0]
                            )

                            destination_port = (
                                triggering_event.get(
                                    "destination_port"
                                )
                            )

                            triggering_rows.append(
                                {
                                    "Time": event_time,
                                    "Source": (
                                        triggering_event.get(
                                            "source",
                                            "—",
                                        )
                                    ),
                                    "Event Type": (
                                        triggering_event.get(
                                            "event_type",
                                            "—",
                                        )
                                    ),
                                    "Source IP": (
                                        triggering_event.get(
                                            "source_ip"
                                        )
                                        or "—"
                                    ),
                                    "Destination IP": (
                                        triggering_event.get(
                                            "destination_ip"
                                        )
                                        or "—"
                                    ),
                                    "Destination Port": (
                                        str(destination_port)
                                        if destination_port
                                        is not None
                                        else "—"
                                    ),
                                    "User": (
                                        triggering_event.get(
                                            "username"
                                        )
                                        or "—"
                                    ),
                                    "Detail": (
                                        triggering_event.get(
                                            "path"
                                        )
                                        or triggering_event.get(
                                            "raw"
                                        )
                                        or "—"
                                    ),
                                }
                            )

                        st.dataframe(
                            triggering_rows,
                            width="stretch",
                            hide_index=True,
                        )

                        total_triggering = (
                            evidence.get(
                                "triggering_event_count"
                            )
                        )

                        if (
                            isinstance(total_triggering, int)
                            and total_triggering
                            > len(triggering_rows)
                        ):

                            st.caption(
                                f"Showing first "
                                f"{len(triggering_rows)} of "
                                f"{total_triggering} matching events."
                            )

                    matched_pattern = (
                        evidence.get("matched_pattern")
                    )

                    if matched_pattern:

                        st.caption(
                            f"Matched pattern: `{matched_pattern}`"
                        )

                    unique_ports = (
                        evidence.get(
                            "unique_destination_ports"
                        )
                        or []
                    )

                    if unique_ports:

                        st.caption(
                            "Unique destination ports: "
                            + ", ".join(
                                str(port)
                                for port in unique_ports
                            )
                        )

                    evidence_confidence = (
                        evidence.get("confidence") or {}
                    )

                    confidence_score = (
                        evidence_confidence.get("score")
                    )

                    if isinstance(
                        confidence_score,
                        (int, float),
                    ):

                        st.caption(
                            f"Rule confidence "
                            f"{confidence_score:.0%} — "
                            f"{evidence_confidence.get('basis', '')}"
                        )

                    evidence_actions = (
                        evidence.get(
                            "recommended_actions"
                        )
                        or []
                    )

                    if evidence_actions:

                        st.write(
                            "**Recommended actions**"
                        )

                        for evidence_action in evidence_actions:

                            st.write(
                                f"- {evidence_action}"
                            )

                # -----------------------------------------
                # THREAT INTELLIGENCE
                # -----------------------------------------

                st.markdown(
                    "**🌍 Threat Intelligence**"
                )

                intel = None

                intel_raw = alert["threat_intel_json"]

                if intel_raw:

                    try:

                        intel = json.loads(
                            intel_raw
                        )

                    except (TypeError, ValueError):

                        intel = None

                if not isinstance(intel, dict):

                    st.caption(
                        "No threat intelligence enrichment is "
                        "stored for this alert."
                    )

                else:

                    intel_status = str(
                        intel.get("status", "unknown")
                    ).upper()

                    intel_col1, intel_col2 = (
                        st.columns(2)
                    )

                    with intel_col1:

                        st.write(
                            f"**IP:** `{intel.get('ip') or '—'}`"
                        )

                        st.write(
                            f"**Reputation:** `{intel_status}`"
                        )

                    with intel_col2:

                        st.write(
                            f"**Source:** "
                            f"{intel.get('source') or '—'}"
                        )

                        st.write(
                            f"**Last checked:** "
                            f"{intel.get('last_checked') or '—'}"
                        )

                    if intel.get("details"):

                        st.caption(
                            str(intel["details"])
                        )

                    st.caption(
                        "Unknown means no configured source has "
                        "data for this address; it is not proof of "
                        "benign activity."
                    )

                # -----------------------------------------
                # RELATED EVENTS
                # -----------------------------------------

                st.markdown(
                    "**🔎 Investigation Context — Related Events**"
                )

                st.caption(
                    "Surrounding events from the same source within "
                    "±120 seconds. This is investigation context and "
                    "may include activity that did not trigger the "
                    "rule; the triggering evidence is listed above."
                )

                related_events = (
                    database.get_related_events(
                        alert["source_ip"],
                        alert["timestamp"],
                        window_seconds=120,
                    )
                )

                if not related_events:

                    st.info(
                        "No related events found within "
                        "the investigation window."
                    )

                else:

                    st.caption(
                        f"Found {len(related_events)} "
                        f"related events within ±120 seconds."
                    )

                    # -----------------------------------------
                    # NETWORK CORRELATION
                    # -----------------------------------------

                    network_events = [
                        event
                        for event in related_events
                        if event["source"] == "network"
                    ]

                    if network_events:

                        source_ips = {
                            event["source_ip"]
                            for event in network_events
                            if event["source_ip"]
                        }

                        destination_ips = {
                            event["destination_ip"]
                            for event in network_events
                            if event["destination_ip"]
                        }

                        destination_ports = {
                            event["destination_port"]
                            for event in network_events
                            if event["destination_port"] is not None
                        }

                        protocols = {
                            event["protocol"]
                            for event in network_events
                            if event["protocol"]
                        }

                        timestamps = [
                            str(event["timestamp"])
                            for event in network_events
                            if event["timestamp"]
                        ]

                        timestamps.sort()

                        first_seen = (
                            timestamps[0]
                            if timestamps
                            else "—"
                        )

                        last_seen = (
                            timestamps[-1]
                            if timestamps
                            else "—"
                        )

                        first_seen = (
                            first_seen
                            .replace("T", " ")
                            .split(".")[0]
                        )

                        last_seen = (
                            last_seen
                            .replace("T", " ")
                            .split(".")[0]
                        )

                        st.markdown(
                            "**📊 Network Correlation**"
                        )

                        correlation_col1, correlation_col2, correlation_col3 = (
                            st.columns(3)
                        )

                        with correlation_col1:

                            st.metric(
                                "Network Events",
                                len(network_events),
                            )

                            st.metric(
                                "Unique Destinations",
                                len(destination_ips),
                            )

                        with correlation_col2:

                            st.metric(
                                "Unique Ports",
                                len(destination_ports),
                            )

                            st.metric(
                                "Protocols",
                                len(protocols),
                            )

                        with correlation_col3:

                            st.metric(
                                "Source IPs",
                                len(source_ips),
                            )

                            st.metric(
                                "Time Window",
                                "±120 sec",
                            )

                        correlation_rows = [
                            {
                                "Source IP": (
                                    ", ".join(
                                        sorted(
                                            source_ips
                                        )
                                    )
                                    if source_ips
                                    else "—"
                                ),
                                "Protocols": (
                                    ", ".join(
                                        sorted(
                                            protocols
                                        )
                                    )
                                    if protocols
                                    else "—"
                                ),
                                "First Seen": first_seen,
                                "Last Seen": last_seen,
                            }
                        ]

                        st.dataframe(
                            correlation_rows,
                            width="stretch",
                            hide_index=True,
                        )

                    # -----------------------------------------
                    # NETWORK EVIDENCE
                    # -----------------------------------------

                    network_events = [
                        event
                        for event in related_events
                        if event["source"] == "network"
                    ]

                    if network_events:

                        st.markdown(
                            "**🌐 Network Evidence**"
                        )

                        network_evidence_rows = []

                        for event in network_events:

                            event_timestamp = (
                                event["timestamp"]
                            )

                            if event_timestamp is not None:

                                event_timestamp = str(
                                    event_timestamp
                                ).replace(
                                    "T",
                                    " ",
                                )

                                if "." in event_timestamp:

                                    event_timestamp = (
                                        event_timestamp.split(
                                            "."
                                        )[0]
                                    )

                            network_evidence_rows.append(
                                {
                                    "Time": (
                                        event_timestamp
                                        or "—"
                                    ),
                                    "Direction": (
                                        describe_event_direction(
                                            event
                                        )
                                    ),
                                    "Initiated": (
                                        describe_connection_initiation(
                                            event
                                        )
                                    ),
                                    "Source IP": (
                                        event["source_ip"]
                                        or "—"
                                    ),
                                    "Source Port": (
                                        _port_display(
                                            _event_value(
                                                event,
                                                "source_port",
                                            )
                                        )
                                    ),
                                    "Destination IP": (
                                        event["destination_ip"]
                                        or "—"
                                    ),
                                    "Destination Port": (
                                        _port_display(
                                            _event_value(
                                                event,
                                                "destination_port",
                                            )
                                        )
                                    ),
                                    "Protocol": (
                                        event["protocol"]
                                        or "—"
                                    ),
                                    "Event Type": (
                                        event["event_type"]
                                        or "—"
                                    ),
                                }
                            )

                        st.dataframe(
                            network_evidence_rows,
                            width="stretch",
                            hide_index=True,
                            column_config={
                                "Time": st.column_config.TextColumn(
                                    "Time",
                                    width="medium",
                                ),
                                "Direction": st.column_config.TextColumn(
                                    "Direction",
                                    width="small",
                                    help=(
                                        "Direction relative to this "
                                        "host, recorded at capture "
                                        "time."
                                    ),
                                ),
                                "Initiated": st.column_config.TextColumn(
                                    "Initiated",
                                    width="small",
                                    help=(
                                        "Yes = connection initiation. "
                                        "No = reply or mid-stream "
                                        "packet. Unknown = historical "
                                        "event or protocol without "
                                        "connection setup."
                                    ),
                                ),
                                "Source IP": st.column_config.TextColumn(
                                    "Source IP",
                                    width="large",
                                ),
                                "Source Port": st.column_config.TextColumn(
                                    "Source Port",
                                    width="small",
                                ),
                                "Destination IP": st.column_config.TextColumn(
                                    "Destination IP",
                                    width="large",
                                ),
                                "Destination Port": st.column_config.TextColumn(
                                    "Destination Port",
                                    width="small",
                                ),
                                "Protocol": st.column_config.TextColumn(
                                    "Protocol",
                                    width="small",
                                ),
                                "Event Type": st.column_config.TextColumn(
                                    "Event Type",
                                    width="medium",
                                ),
                            },
                        )

                    for event in related_events:

                        event_timestamp = (
                            event["timestamp"]
                        )

                        event_source = (
                            event["source"].upper()
                        )

                        event_type = (
                            event["event_type"]
                        )

                        event_line = (
                            f"`{event_timestamp}` "
                            f"**{event_source}** "
                            f"`{event_type}`"
                        )

                        if event["source_ip"]:

                            event_line += (
                                f" — `{event['source_ip']}`"
                            )

                        if event["username"]:

                            event_line += (
                                f" — user "
                                f"`{event['username']}`"
                            )

                        if event["path"]:

                            event_line += (
                                f" — `{event['method']} "
                                f"{event['path']}`"
                            )

                        st.write(
                            event_line
                        )

                # -----------------------------------------
                # ALERT INVESTIGATION
                # -----------------------------------------

                st.markdown(
                    "**🔍 Alert Investigation**"
                )

                investigation = (
                    database.get_investigation(
                        alert["id"]
                    )
                )

                if investigation:

                    existing_notes = (
                        investigation[
                            "analyst_notes"
                        ]
                        or ""
                    )

                    existing_action = (
                        investigation[
                            "recommended_action"
                        ]
                        or ""
                    )

                else:

                    existing_notes = ""

                    existing_action = ""

                # -----------------------------------------
                # INVESTIGATION SUMMARY
                # -----------------------------------------

                st.markdown(
                    "**📊 Investigation Summary**"
                )

                network_events = [
                    event
                    for event in related_events
                    if event["source"] == "network"
                ]

                investigation_event_count = len(
                    related_events
                )

                investigation_network_count = len(
                    network_events
                )

                investigation_sources = {
                    event["source_ip"]
                    for event in network_events
                    if event["source_ip"]
                }

                investigation_destinations = {
                    event["destination_ip"]
                    for event in network_events
                    if event["destination_ip"]
                }

                investigation_ports = {
                    event["destination_port"]
                    for event in network_events
                    if event["destination_port"] is not None
                }

                investigation_protocols = {
                    event["protocol"]
                    for event in network_events
                    if event["protocol"]
                }

                investigation_timestamps = [
                    str(event["timestamp"])
                    for event in network_events
                    if event["timestamp"]
                ]

                investigation_timestamps.sort()

                investigation_first_seen = (
                    investigation_timestamps[0]
                    if investigation_timestamps
                    else "—"
                )

                investigation_last_seen = (
                    investigation_timestamps[-1]
                    if investigation_timestamps
                    else "—"
                )

                investigation_first_seen = (
                    investigation_first_seen
                    .replace("T", " ")
                    .split(".")[0]
                )

                investigation_last_seen = (
                    investigation_last_seen
                    .replace("T", " ")
                    .split(".")[0]
                )

                summary_col1, summary_col2, summary_col3 = (
                    st.columns(3)
                )

                with summary_col1:

                    st.metric(
                        "Related Events",
                        investigation_event_count,
                    )

                    st.metric(
                        "Network Events",
                        investigation_network_count,
                    )

                with summary_col2:

                    st.metric(
                        "Unique Sources",
                        len(investigation_sources),
                    )

                    st.metric(
                        "Unique Destinations",
                        len(investigation_destinations),
                    )

                with summary_col3:

                    st.metric(
                        "Unique Ports",
                        len(investigation_ports),
                    )

                    st.metric(
                        "Protocols",
                        len(investigation_protocols),
                    )

                if investigation_network_count:

                    st.caption(
                        f"Network activity observed from "
                        f"{investigation_first_seen} to "
                        f"{investigation_last_seen} "
                        f"within the ±120 second correlation window."
                    )

                # -----------------------------------------
                # ANALYST NOTES
                # -----------------------------------------

                analyst_notes = st.text_area(
                    "Analyst Notes",
                    value=existing_notes,
                    height=140,
                    placeholder=(
                        "Document what you observed "
                        "during the investigation..."
                    ),
                    key=f"notes_{alert['id']}",
                )

                # -----------------------------------------
                # RECOMMENDED ACTION
                # -----------------------------------------

                recommended_action = st.text_area(
                    "Recommended Action",
                    value=existing_action,
                    height=120,
                    placeholder=(
                        "Describe the recommended response "
                        "or next investigation step..."
                    ),
                    key=f"action_{alert['id']}",
                )

                # -----------------------------------------
                # SAVE INVESTIGATION
                # -----------------------------------------

                if st.button(
                    "💾 Save Investigation",
                    key=(
                        f"save_investigation_"
                        f"{alert['id']}"
                    ),
                    width="stretch",
                ):

                    database.update_investigation(
                        alert["id"],
                        analyst_notes,
                        recommended_action,
                    )

                    st.success(
                        f"Investigation for Alert "
                        f"#{alert['id']} saved successfully."
                    )

                    st.rerun()

                # -----------------------------------------
                # INVESTIGATION STATUS
                # -----------------------------------------

                st.markdown(
                    "**Investigation Status**"
                )

                st.caption(
                    f"Current status: `{status}`"
                )

                status_options = [
                    "OPEN",
                    "INVESTIGATING",
                    "RESOLVED",
                    "FALSE_POSITIVE",
                ]

                new_status = st.selectbox(
                    "Change alert status",
                    status_options,
                    index=status_options.index(
                        status
                    ),
                    key=f"status_{alert['id']}",
                )

                # -----------------------------------------
                # UPDATE STATUS
                # -----------------------------------------

                if st.button(
                    "Update Alert Status",
                    key=f"update_{alert['id']}",
                    width="stretch",
                ):

                    if new_status == status:

                        st.info(
                            f"Alert #{alert['id']} is already "
                            f"`{new_status}`."
                        )

                    else:

                        database.update_alert_status(
                            alert["id"],
                            new_status,
                        )

                        st.success(
                            f"Alert #{alert['id']} updated to "
                            f"`{new_status}`."
                        )

                        st.rerun()

    # =====================================================
    # ATTACK ANALYSIS
    # =====================================================

    st.markdown(
        '<div id="attack-analysis"></div>',
        unsafe_allow_html=True,
    )

    with st.expander(
        "📊 ATTACK ANALYSIS",
        expanded=False,
    ):

        if recent_alerts:

            detection_counts = Counter(
                alert["alert_type"]
                for alert in recent_alerts
            )

            st.write(
                "Detections by attack type"
            )

            st.bar_chart(
                detection_counts
            )

            severity_counts = Counter(
                alert["severity"]
                for alert in recent_alerts
            )

            st.write(
                "Alert severity distribution"
            )

            st.bar_chart(
                severity_counts
            )

        else:

            st.info(
                "No alert data available for analysis."
            )

    # =====================================================
    # EVENT STREAM
    # =====================================================

    st.markdown(
        '<div id="recent-event-stream"></div>',
        unsafe_allow_html=True,
    )

    with st.expander(
        "📡 RECENT EVENT STREAM",
        expanded=False,
    ):

        recent_events = (
            database.get_recent_events(
                limit=50
            )
        )

        if not recent_events:

            st.info(
                "No security events have been recorded yet."
            )

        else:

            for event in recent_events:

                timestamp = event["timestamp"]

                source = (
                    event["source"].upper()
                )

                event_type = (
                    event["event_type"]
                )

                line = (
                    f"`{timestamp}` "
                    f"**{source}** "
                    f"`{event_type}`"
                )

                if event["source_ip"]:

                    line += (
                        f" — `{event['source_ip']}`"
                    )

                if event["username"]:

                    line += (
                        f" — user "
                        f"`{event['username']}`"
                    )

                if event["path"]:

                    line += (
                        f" — `{event['method']} "
                        f"{event['path']}`"
                    )

                st.write(
                    line
                )

    # =====================================================
    # FOOTER
    # =====================================================

    st.markdown("---")

    st.markdown(
        '<div class="sentry-footer">'
        'SENTRY v1.0.0 — Persistent Security Monitoring'
        '</div>',
        unsafe_allow_html=True,
    )


# =========================================================
# RUN DASHBOARD
# =========================================================

dashboard()