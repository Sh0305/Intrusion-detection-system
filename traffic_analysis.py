"""
traffic_analysis.py — Flow-based feature extraction for the IDS pipeline.

This module is intentionally kept stateless: it operates purely on the
pre-computed feature dict produced by PacketCapture, making it easy to
unit-test without raw packets.
"""

from typing import Optional


# CICIDS2017-inspired feature names (subset we compute in real-time)
FEATURE_NAMES = [
    "packet_size",
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "tcp_flags",
    "window_size",
    "syn_count",
    "fin_count",
    "rst_count",
    "unique_dest_ports",
]


def features_to_vector(features: dict) -> list:
    """Convert a feature dict into an ordered numeric vector for the ML model."""
    return [features.get(f, 0) for f in FEATURE_NAMES]


def classify_traffic_type(features: dict) -> str:
    """
    Heuristic classification of traffic type for display/logging purposes.
    Not used by the ML model — purely informational.
    """
    flags = features.get("tcp_flags", 0)
    rate = features.get("packet_rate", 0)
    size = features.get("packet_size", 0)
    ports = features.get("unique_dest_ports", 0)

    if flags & 0x02 and rate > 100:
        return "potential_syn_flood"
    if ports > 20 and size < 100:
        return "potential_port_scan"
    if rate > 500:
        return "high_rate_traffic"
    return "normal"
