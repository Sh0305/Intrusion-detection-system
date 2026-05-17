"""
tests/test_alerts.py — Unit tests for the AlertSystem.
"""

import json
import threading
from pathlib import Path

import pytest

from ids.alerts import AlertSystem


SAMPLE_THREAT = {
    "type": "signature",
    "rule": "syn_flood",
    "severity": "critical",
    "confidence": 1.0,
}

SAMPLE_PKT = {
    "src_ip": "192.168.1.10",
    "dst_ip": "10.0.0.1",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": "TCP",
}


class TestAlertSystem:
    @pytest.fixture
    def alert_sys(self, tmp_path):
        return AlertSystem(log_path=tmp_path / "alerts.log")

    def test_emit_returns_alert_dict(self, alert_sys):
        alert = alert_sys.emit(SAMPLE_THREAT, SAMPLE_PKT)
        assert isinstance(alert, dict)

    def test_alert_has_timestamp(self, alert_sys):
        alert = alert_sys.emit(SAMPLE_THREAT, SAMPLE_PKT)
        assert "timestamp" in alert

    def test_alert_has_src_ip(self, alert_sys):
        alert = alert_sys.emit(SAMPLE_THREAT, SAMPLE_PKT)
        assert alert["src_ip"] == "192.168.1.10"

    def test_alert_written_to_log(self, tmp_path):
        log_path = tmp_path / "alerts.log"
        sys = AlertSystem(log_path=log_path)
        sys.emit(SAMPLE_THREAT, SAMPLE_PKT)
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["rule"] == "syn_flood"

    def test_stats_incremented(self, alert_sys):
        alert_sys.emit(SAMPLE_THREAT, SAMPLE_PKT)
        stats = alert_sys.stats()
        assert stats.get("critical", 0) == 1

    def test_total(self, alert_sys):
        alert_sys.emit(SAMPLE_THREAT, SAMPLE_PKT)
        alert_sys.emit({**SAMPLE_THREAT, "severity": "medium"}, SAMPLE_PKT)
        assert alert_sys.total() == 2

    def test_min_severity_filters(self, tmp_path):
        sys = AlertSystem(log_path=tmp_path / "a.log", min_severity="high")
        result = sys.emit({**SAMPLE_THREAT, "severity": "low"}, SAMPLE_PKT)
        assert result is None

    def test_on_alert_callback_called(self, tmp_path):
        received = []
        lock = threading.Event()

        def cb(alert):
            received.append(alert)
            lock.set()

        sys = AlertSystem(log_path=tmp_path / "a.log", on_alert=cb)
        sys.emit(SAMPLE_THREAT, SAMPLE_PKT)
        lock.wait(timeout=2)
        assert len(received) == 1

    def test_thread_safe_emit(self, alert_sys):
        errors = []

        def emit():
            try:
                alert_sys.emit(SAMPLE_THREAT, SAMPLE_PKT)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=emit) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert alert_sys.total() == 50
