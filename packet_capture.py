"""
packet_capture.py — Thread-safe packet capture for TCP, UDP, and ICMP traffic.

Runs a background daemon thread using Scapy's sniff(). Packets are placed into
a thread-safe queue for consumption by the detection pipeline. Flow records
are expired after FLOW_TIMEOUT seconds to prevent unbounded memory growth.
"""

import queue
import threading
import time
from collections import defaultdict
from typing import Optional

from scapy.all import IP, TCP, UDP, ICMP, sniff

FLOW_TIMEOUT = 60  # seconds before an idle flow is evicted


class FlowStats:
    """Mutable statistics for a single network flow."""

    __slots__ = (
        "packet_count", "byte_count", "start_time",
        "last_time", "syn_count", "fin_count", "rst_count",
        "dest_ports",
    )

    def __init__(self, first_time: float, pkt_len: int):
        self.packet_count = 1
        self.byte_count = pkt_len
        self.start_time = first_time
        self.last_time = first_time
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.dest_ports: set = set()

    def update(self, pkt_time: float, pkt_len: int, flags: int, dst_port: int):
        self.packet_count += 1
        self.byte_count += pkt_len
        self.last_time = pkt_time
        if flags & 0x02:
            self.syn_count += 1
        if flags & 0x01:
            self.fin_count += 1
        if flags & 0x04:
            self.rst_count += 1
        self.dest_ports.add(dst_port)

    @property
    def duration(self) -> float:
        d = self.last_time - self.start_time
        return d if d > 0 else 1e-6

    def to_features(self, packet_size: int, tcp_flags: int, window_size: int) -> dict:
        return {
            "packet_size": packet_size,
            "flow_duration": self.duration,
            "packet_rate": self.packet_count / self.duration,
            "byte_rate": self.byte_count / self.duration,
            "tcp_flags": tcp_flags,
            "window_size": window_size,
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "unique_dest_ports": len(self.dest_ports),
        }


class PacketCapture:
    """
    Captures IP/TCP, IP/UDP, and IP/ICMP packets on a given interface.

    Packets are queued for downstream consumption. A background cleanup
    thread evicts flows idle for longer than FLOW_TIMEOUT seconds so
    memory usage stays bounded even under sustained traffic.
    """

    def __init__(self, interface: Optional[str] = None, maxqueue: int = 10_000):
        self.interface = interface
        self.packet_queue: queue.Queue = queue.Queue(maxsize=maxqueue)
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._flow_stats: dict = {}  # flow_key -> FlowStats
        self._capture_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Start background capture and flow-cleanup threads."""
        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="ids-capture"
        )
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="ids-cleanup"
        )
        self._capture_thread.start()
        self._cleanup_thread.start()

    def stop(self):
        """Signal threads to stop and wait for them."""
        self._stop_event.set()
        if self._capture_thread:
            self._capture_thread.join(timeout=5)
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)

    def get_packet(self, timeout: float = 1.0) -> Optional[dict]:
        """
        Return the next processed packet dict, or None on timeout.
        Non-blocking callers should catch queue.Empty themselves.
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def flow_count(self) -> int:
        with self._lock:
            return len(self._flow_stats)

    # ------------------------------------------------------------------
    # Internal threads
    # ------------------------------------------------------------------

    def _capture_loop(self):
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _cleanup_loop(self):
        """Periodically evict flows that haven't seen traffic recently."""
        while not self._stop_event.is_set():
            cutoff = time.time() - FLOW_TIMEOUT
            with self._lock:
                expired = [k for k, v in self._flow_stats.items() if v.last_time < cutoff]
                for k in expired:
                    del self._flow_stats[k]
            time.sleep(FLOW_TIMEOUT / 2)

    def _handle_packet(self, packet):
        if IP not in packet:
            return

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        pkt_len = len(packet)
        pkt_time = float(packet.time)

        if TCP in packet:
            flags = int(packet[TCP].flags)
            sport, dport = packet[TCP].sport, packet[TCP].dport
            window = packet[TCP].window
            proto_name = "TCP"
        elif UDP in packet:
            flags, window = 0, 0
            sport, dport = packet[UDP].sport, packet[UDP].dport
            proto_name = "UDP"
        elif ICMP in packet:
            flags, window = 0, 0
            sport, dport = 0, 0
            proto_name = "ICMP"
        else:
            return  # skip non-IP protocols we don't handle

        flow_key = (ip_src, ip_dst, sport, dport, proto_name)

        with self._lock:
            if flow_key not in self._flow_stats:
                self._flow_stats[flow_key] = FlowStats(pkt_time, pkt_len)
            else:
                self._flow_stats[flow_key].update(pkt_time, pkt_len, flags, dport)
            stats = self._flow_stats[flow_key]
            features = stats.to_features(pkt_len, flags, window)

        pkt_dict = {
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto_name,
            "features": features,
        }

        try:
            self.packet_queue.put_nowait(pkt_dict)
        except queue.Full:
            pass  # drop packet rather than block the capture thread
