"""
alerts.py — Structured alert logging and notification routing.

Alerts are written as JSON lines to ids_alerts.log. High/critical alerts
also emit to stderr so they're visible in any monitoring setup.
An optional callback hook lets downstream consumers (e.g. the dashboard)
react to alerts in real time.
"""

import json
import logging
import logging.handlers
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

LOG_PATH = Path("ids_alerts.log")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class AlertSystem:
    """
    Thread-safe alert generator and logger.

    Parameters
    ----------
    log_path        Path for the JSON-lines alert log file.
    on_alert        Optional callback invoked with each alert dict on a
                    separate thread. Use this to feed a live dashboard.
    min_severity    Minimum severity to log (default "low" = log everything).
    """

    def __init__(
        self,
        log_path: Path = LOG_PATH,
        on_alert: Optional[Callable[[dict], None]] = None,
        min_severity: str = "low",
    ):
        self._lock = threading.Lock()
        self._on_alert = on_alert
        self._min_level = SEVERITY_ORDER.get(min_severity, 0)
        self._alert_count: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        # Ensure log directory exists
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Rotating file handler — keeps last 5 × 10 MB files
        self._logger = logging.getLogger(f"ids.alerts.{id(self)}")
        self._logger.setLevel(logging.DEBUG)
        if not self._logger.handlers:
            handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
            self._logger.propagate = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def emit(self, threat: dict, packet_info: dict) -> Optional[dict]:
        """
        Build and log a structured alert from *threat* + *packet_info*.
        Returns the alert dict, or None if severity is below minimum.
        """
        severity = threat.get("severity", "medium")
        if SEVERITY_ORDER.get(severity, 1) < self._min_level:
            return None

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "type": threat.get("type"),
            "rule": threat.get("rule"),
            "src_ip": packet_info.get("src_ip"),
            "dst_ip": packet_info.get("dst_ip"),
            "src_port": packet_info.get("src_port"),
            "dst_port": packet_info.get("dst_port"),
            "protocol": packet_info.get("protocol"),
            "confidence": threat.get("confidence", 0.0),
            "details": {
                k: v for k, v in threat.items()
                if k not in {"severity", "type", "rule", "confidence",
                             "src_ip", "dst_ip", "src_port", "dst_port", "protocol"}
            },
        }

        with self._lock:
            self._alert_count[severity] = self._alert_count.get(severity, 0) + 1
            self._logger.info(json.dumps(alert))

        if severity in ("high", "critical"):
            print(f"[{severity.upper()}] {alert['rule']} — {alert['src_ip']} → {alert['dst_ip']}")

        if self._on_alert:
            threading.Thread(target=self._on_alert, args=(alert,), daemon=True).start()

        return alert

    def stats(self) -> dict:
        """Return cumulative alert counts per severity level."""
        with self._lock:
            return dict(self._alert_count)

    def total(self) -> int:
        with self._lock:
            return sum(self._alert_count.values())
