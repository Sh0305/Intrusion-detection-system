"""
intrusion.py — Main IDS orchestrator.

Wires together PacketCapture → DetectionEngine → AlertSystem.
Run directly:

    sudo python -m ids.intrusion --interface eth0

Or import IntrusionDetectionSystem and call .start() / .stop() programmatically.
"""

import argparse
import logging
import signal
import sys
import time
from typing import Optional

from ids.alerts import AlertSystem
from ids.detection_engine import DetectionEngine
from ids.packet_capture import PacketCapture

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class IntrusionDetectionSystem:
    """
    Top-level IDS controller.

    Parameters
    ----------
    interface   Network interface to sniff on (None = let Scapy choose).
    on_alert    Optional callback forwarded to AlertSystem for live feeds.
    """

    def __init__(self, interface: Optional[str] = None, on_alert=None):
        self.capture = PacketCapture(interface=interface)
        self.engine = DetectionEngine()
        self.alerts = AlertSystem(on_alert=on_alert)
        self._running = False

        logger.info(
            "IDS initialised — %d signature rules loaded, model trained: %s",
            self.engine.rule_count(),
            self.engine.is_trained(),
        )

    def start(self):
        """Begin packet capture and detection loop (blocks until stop())."""
        self._running = True
        self.capture.start()
        logger.info("Packet capture started. Press Ctrl-C to stop.")

        try:
            while self._running:
                pkt = self.capture.get_packet(timeout=1.0)
                if pkt is None:
                    continue
                self._process(pkt)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self._running = False
        self.capture.stop()
        stats = self.alerts.stats()
        logger.info("IDS stopped. Alert summary: %s", stats)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _process(self, pkt: dict):
        features = pkt["features"]
        context = {
            "src_ip": pkt["src_ip"],
            "dst_ip": pkt["dst_ip"],
            "src_port": pkt["src_port"],
            "dst_port": pkt["dst_port"],
            "protocol": pkt["protocol"],
        }
        threats = self.engine.detect(features, **context)
        for threat in threats:
            self.alerts.emit(threat, context)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cli():
    parser = argparse.ArgumentParser(description="Python Hybrid IDS")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff")
    args = parser.parse_args()

    ids = IntrusionDetectionSystem(interface=args.interface)

    def _sigterm(sig, frame):
        ids.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm)
    ids.start()


if __name__ == "__main__":
    _cli()
