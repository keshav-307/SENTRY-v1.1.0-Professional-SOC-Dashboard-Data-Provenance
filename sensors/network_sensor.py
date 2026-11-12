import threading
import time
from datetime import datetime
from typing import Optional

from scapy.all import DNS, IP, IPv6, TCP, UDP, sniff

from core.models import SecurityEvent


class NetworkSensor:
    """
    SENTRY live network sensor.

    Captures real network packets using Scapy/Npcap and converts packet
    metadata into SENTRY SecurityEvent objects.

    Payload contents are intentionally not stored.

    Events are buffered and sent to the detection pipeline in batches so
    a live capture does not perform one SQLite transaction per packet.
    """

    def __init__(
        self,
        pipeline=None,
        interface=None,
        batch_size=25,
        flush_interval=1.0,
    ):
        self.pipeline = pipeline
        self.interface = interface

        self.batch_size = max(1, int(batch_size))
        self.flush_interval = max(0.1, float(flush_interval))

        self.running = False
        self.packet_count = 0
        self.event_count = 0
        self.alert_count = 0

        # Last capture error, shown in the dashboard instead of being
        # swallowed by the capture thread.
        self.last_error = None

        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._pending_events = []
        self._last_flush = time.monotonic()

        # Addresses that belong to this host, used to tell outbound
        # connection initiations from inbound replies. Resolved when
        # capture starts and lazily on first packet conversion.
        self._local_addresses = set()

        # Recently seen UDP conversations. The first packet of a flow
        # is an initiation; later packets and replies are not.
        self._udp_flows = {}
        self._udp_flow_window = 120.0
        self._udp_flow_limit = 10000

    # ---------------------------------------------------------
    # DIRECTION AND INITIATION AWARENESS
    # ---------------------------------------------------------

    def _resolve_local_addresses(self):
        """
        Return the set of addresses that belong to this host.

        The selected interface exposes IPv4 and IPv6 addresses through
        Scapy's ``ips`` mapping. ``ip`` is used as a fallback for
        older Scapy versions. Loopback is always local.
        """

        addresses = {"127.0.0.1", "::1"}

        interface = self.interface

        if interface is None:
            return addresses

        ip_map = getattr(interface, "ips", None)

        if isinstance(ip_map, dict):
            for version in (4, 6):
                for address in ip_map.get(version, []) or []:
                    addresses.add(str(address))

        ip_address = getattr(interface, "ip", None)

        if ip_address:
            addresses.add(str(ip_address))

        return addresses

    def _direction_for(self, source_ip, destination_ip):
        """Classify one packet relative to this host."""

        source_local = source_ip in self._local_addresses
        destination_local = destination_ip in self._local_addresses

        if source_local and destination_local:
            return "local"

        if source_local:
            return "outbound"

        if destination_local:
            return "inbound"

        return "unknown"

    @staticmethod
    def _tcp_initiates_connection(packet):
        """True for a TCP SYN that is not a SYN-ACK reply."""

        flags = int(packet[TCP].flags)

        return bool(flags & 0x02) and not bool(flags & 0x10)

    @staticmethod
    def _udp_flow_key(
        source_ip,
        source_port,
        destination_ip,
        destination_port,
    ):
        """Direction-independent key for a UDP conversation."""

        return tuple(
            sorted(
                (
                    (str(source_ip), int(source_port or -1)),
                    (str(destination_ip), int(destination_port or -1)),
                )
            )
        )

    def _udp_initiates_flow(
        self,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
    ):
        """
        True only for the first packet seen of a UDP conversation.

        Replies share the same flow key, so a reply is never treated as
        a new initiation.
        """

        now = time.monotonic()

        for key, seen_at in list(self._udp_flows.items()):
            if now - seen_at > self._udp_flow_window:
                self._udp_flows.pop(key, None)

        key = self._udp_flow_key(
            source_ip,
            source_port,
            destination_ip,
            destination_port,
        )

        if key in self._udp_flows:
            return False

        self._udp_flows[key] = now

        if len(self._udp_flows) > self._udp_flow_limit:
            oldest_key = min(
                self._udp_flows,
                key=self._udp_flows.get,
            )

            self._udp_flows.pop(oldest_key, None)

        return True

    # ---------------------------------------------------------
    # PACKET CONVERSION
    # ---------------------------------------------------------

    def packet_to_event(self, packet) -> Optional[SecurityEvent]:
        """
        Convert one captured Scapy packet into a SENTRY SecurityEvent.

        Only network metadata is extracted. DNS queries become
        dns_query events; other IP traffic becomes connection events.
        """

        source_ip = None
        destination_ip = None

        # IPv4
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        # IPv6
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        # Ignore packets that are not IP traffic.
        if source_ip is None or destination_ip is None:
            return None

        protocol = "IP"
        source_port = None
        destination_port = None

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        # -----------------------------------------------------
        # DIRECTION AND CONNECTION INITIATION
        # -----------------------------------------------------

        if not self._local_addresses:
            self._local_addresses = (
                self._resolve_local_addresses()
            )

        direction = self._direction_for(
            source_ip,
            destination_ip,
        )

        initiated = None

        if TCP in packet:
            initiated = self._tcp_initiates_connection(
                packet
            )

        elif UDP in packet:
            initiated = self._udp_initiates_flow(
                source_ip,
                source_port,
                destination_ip,
                destination_port,
            )

        # -----------------------------------------------------
        # DNS QUERIES
        # -----------------------------------------------------

        if (
            DNS in packet
            and packet[DNS].qr == 0
            and packet[DNS].qd is not None
        ):
            query_name = packet[DNS].qd.qname

            if isinstance(query_name, bytes):
                query_name = query_name.decode(
                    "utf-8",
                    errors="replace",
                )

            query_name = str(query_name).rstrip(".")

            if not query_name:
                return None

            return SecurityEvent(
                timestamp=datetime.now(),
                source="network",
                event_type="dns_query",
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=(
                    destination_port
                    if destination_port is not None
                    else 53
                ),
                protocol=protocol,
                path=query_name,
                status=packet[DNS].rcode,
                direction=direction,
                initiated=initiated,
                raw=None,
            )

        return SecurityEvent(
            timestamp=datetime.now(),
            source="network",
            event_type="connection",
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            direction=direction,
            initiated=initiated,
            raw=None,
        )

    # ---------------------------------------------------------
    # BATCHED PROCESSING
    # ---------------------------------------------------------

    def _flush_pending(self):
        """
        Send buffered events to the pipeline.

        Returns the number of alerts generated by this batch.
        """

        with self._lock:
            events = self._pending_events
            self._pending_events = []
            self._last_flush = time.monotonic()

        if not events:
            return 0

        if self.pipeline is None:
            return 0

        try:
            alerts = self.pipeline.process_events(events)
        except Exception as error:
            self.last_error = (
                f"{type(error).__name__}: {error}"
            )
            return 0

        generated = len(alerts or [])

        self.alert_count += generated

        return generated

    def packet_handler(self, packet):
        """
        Process one captured packet.

        Converts the packet into a SENTRY event and buffers it. The
        buffer is flushed on a size or time threshold.
        """

        self.packet_count += 1

        event = self.packet_to_event(packet)

        if event is None:
            return None

        self.event_count += 1

        with self._lock:
            self._pending_events.append(event)
            pending_count = len(self._pending_events)

        elapsed = time.monotonic() - self._last_flush

        if (
            pending_count >= self.batch_size
            or elapsed >= self.flush_interval
        ):
            self._flush_pending()

        return event

    # ---------------------------------------------------------
    # CAPTURE
    # ---------------------------------------------------------

    def capture_packets(self, count=10, timeout=None):
        """
        Capture packets from the configured interface.

        Returns:
            list[SecurityEvent]
        """

        packets = sniff(
            iface=self.interface,
            count=count,
            timeout=timeout,
            prn=None,
            store=True,
        )

        events = []

        for packet in packets:
            event = self.packet_to_event(packet)

            if event is not None:
                events.append(event)

        return events

    def process_events(self, events):
        """
        Send SENTRY events into the detection pipeline.

        Returns generated alerts.
        """

        if self.pipeline is None:
            raise RuntimeError(
                "NetworkSensor has no pipeline configured."
            )

        return self.pipeline.process_events(events)

    def capture_and_process(self, count=10, timeout=None):
        """
        Capture real network traffic and send the resulting SENTRY
        events into the detection pipeline.

        Returns:
            events, alerts
        """

        events = self.capture_packets(
            count=count,
            timeout=timeout,
        )

        alerts = self.process_events(events)

        return events, alerts

    def start(self, duration=None):
        """
        Start controlled live network monitoring.

        Args:
            duration:
                Capture duration in seconds.
                None means capture until stop() is called.
        """

        if self.running:
            return

        self.running = True
        self.packet_count = 0
        self.event_count = 0
        self.alert_count = 0
        self.last_error = None
        self._stop_event.clear()
        self._last_flush = time.monotonic()

        # Refresh local addresses for every capture session so DHCP or
        # IPv6 privacy-address changes are picked up.
        self._local_addresses = (
            self._resolve_local_addresses()
        )

        self._udp_flows = {}

        with self._lock:
            self._pending_events = []

        deadline = (
            time.monotonic() + float(duration)
            if duration is not None
            else None
        )

        try:
            # Short sniff windows keep STOP responsive even on an idle
            # link, where stop_filter alone would never be evaluated
            # because no packets arrive.
            while not self._stop_event.is_set():
                timeout = 1.0

                if deadline is not None:

                    remaining = deadline - time.monotonic()

                    if remaining <= 0:
                        break

                    timeout = min(1.0, remaining)

                sniff(
                    iface=self.interface,
                    timeout=timeout,
                    prn=self.packet_handler,
                    store=False,
                    stop_filter=(
                        lambda packet: self._stop_event.is_set()
                    ),
                )

        except Exception as error:
            self.last_error = (
                f"{type(error).__name__}: {error}"
            )

        finally:
            self._flush_pending()
            self.running = False

    def stop(self):
        """
        Request the current live capture to stop.

        The capture loop exits after at most one short sniff window.
        """

        self._stop_event.set()

    def status(self):
        """
        Return a snapshot of sensor state for the dashboard.
        """

        with self._lock:
            pending = len(self._pending_events)

        return {
            "running": self.running,
            "interface": getattr(
                self.interface,
                "name",
                None,
            ),
            "packet_count": self.packet_count,
            "event_count": self.event_count,
            "alert_count": self.alert_count,
            "pending_events": pending,
            "last_error": self.last_error,
        }
