"""
tests/test_detection_engine.py — Unit tests for the hybrid detection engine.

These tests use synthetic feature dicts and do NOT require a network
interface, root privileges, or a pre-trained model. They run in CI with
a simple `pytest tests/`.
"""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from ids.detection_engine import DetectionEngine, _eval_condition
from ids.traffic_analysis import features_to_vector, FEATURE_NAMES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_normal_features(**overrides) -> dict:
    """Baseline benign traffic feature dict."""
    base = {
        "packet_size": 500,
        "flow_duration": 1.0,
        "packet_rate": 5.0,
        "byte_rate": 2500.0,
        "tcp_flags": 0x18,   # PSH + ACK (normal data transfer)
        "window_size": 65535,
        "syn_count": 1,
        "fin_count": 1,
        "rst_count": 0,
        "unique_dest_ports": 1,
    }
    base.update(overrides)
    return base


def syn_flood_features() -> dict:
    return make_normal_features(
        tcp_flags=0x02,   # SYN only
        packet_rate=200,
        syn_count=200,
    )


def port_scan_features() -> dict:
    return make_normal_features(
        packet_size=60,
        packet_rate=80,
        unique_dest_ports=50,
    )


def xmas_scan_features() -> dict:
    return make_normal_features(
        tcp_flags=0x29,   # FIN + PSH + URG
        packet_rate=10,
    )


def null_scan_features() -> dict:
    return make_normal_features(
        tcp_flags=0x00,
        packet_rate=10,
    )


def udp_flood_features() -> dict:
    return make_normal_features(
        byte_rate=2_000_000,   # 2 MB/s
        tcp_flags=0,
    )


# ---------------------------------------------------------------------------
# _eval_condition unit tests
# ---------------------------------------------------------------------------

class TestEvalCondition:
    def test_gt_pass(self):
        assert _eval_condition({"packet_rate": 200}, {"field": "packet_rate", "op": "gt", "value": 100})

    def test_gt_fail(self):
        assert not _eval_condition({"packet_rate": 50}, {"field": "packet_rate", "op": "gt", "value": 100})

    def test_lt_pass(self):
        assert _eval_condition({"packet_size": 60}, {"field": "packet_size", "op": "lt", "value": 100})

    def test_eq_pass(self):
        assert _eval_condition({"tcp_flags": 0}, {"field": "tcp_flags", "op": "eq", "value": 0})

    def test_band_syn(self):
        assert _eval_condition({"tcp_flags": 0x02}, {"field": "tcp_flags", "op": "band", "value": 0x02})

    def test_band_no_syn(self):
        assert not _eval_condition({"tcp_flags": 0x18}, {"field": "tcp_flags", "op": "band", "value": 0x02})

    def test_missing_field_defaults_zero(self):
        # missing field should default to 0 without raising
        result = _eval_condition({}, {"field": "nonexistent", "op": "gt", "value": 5})
        assert result is False

    def test_unknown_op_returns_false(self):
        assert not _eval_condition({"x": 1}, {"field": "x", "op": "INVALID", "value": 0})


# ---------------------------------------------------------------------------
# DetectionEngine — signature rules
# ---------------------------------------------------------------------------

class TestSignatureDetection:
    @pytest.fixture
    def engine(self, tmp_path):
        # Write a minimal rules file so tests don't depend on the repo's rules/
        rules_yaml = tmp_path / "sigs.yaml"
        rules_yaml.write_text(
            "rules:\n"
            "  - name: syn_flood\n"
            "    severity: critical\n"
            "    description: SYN flood\n"
            "    conditions:\n"
            "      - field: tcp_flags\n"
            "        op: band\n"
            "        value: 0x02\n"
            "      - field: packet_rate\n"
            "        op: gt\n"
            "        value: 100\n"
            "  - name: port_scan\n"
            "    severity: high\n"
            "    description: Port scan\n"
            "    conditions:\n"
            "      - field: unique_dest_ports\n"
            "        op: gt\n"
            "        value: 20\n"
            "      - field: packet_size\n"
            "        op: lt\n"
            "        value: 100\n"
            "  - name: xmas_scan\n"
            "    severity: medium\n"
            "    description: XMAS scan\n"
            "    conditions:\n"
            "      - field: tcp_flags\n"
            "        op: band\n"
            "        value: 0x29\n"
            "      - field: packet_rate\n"
            "        op: gt\n"
            "        value: 5\n"
            "  - name: null_scan\n"
            "    severity: medium\n"
            "    description: NULL scan\n"
            "    conditions:\n"
            "      - field: tcp_flags\n"
            "        op: eq\n"
            "        value: 0\n"
            "      - field: packet_rate\n"
            "        op: gt\n"
            "        value: 5\n"
        )
        return DetectionEngine(rules_path=rules_yaml)

    def test_normal_traffic_no_alerts(self, engine):
        threats = engine.detect(make_normal_features())
        sig_threats = [t for t in threats if t["type"] == "signature"]
        assert sig_threats == [], f"Expected no signature threats, got {sig_threats}"

    def test_syn_flood_detected(self, engine):
        threats = engine.detect(syn_flood_features())
        rules = {t["rule"] for t in threats if t["type"] == "signature"}
        assert "syn_flood" in rules

    def test_syn_flood_severity_critical(self, engine):
        threats = engine.detect(syn_flood_features())
        for t in threats:
            if t.get("rule") == "syn_flood":
                assert t["severity"] == "critical"

    def test_port_scan_detected(self, engine):
        threats = engine.detect(port_scan_features())
        rules = {t["rule"] for t in threats if t["type"] == "signature"}
        assert "port_scan" in rules

    def test_xmas_scan_detected(self, engine):
        threats = engine.detect(xmas_scan_features())
        rules = {t["rule"] for t in threats if t["type"] == "signature"}
        assert "xmas_scan" in rules

    def test_null_scan_detected(self, engine):
        threats = engine.detect(null_scan_features())
        rules = {t["rule"] for t in threats if t["type"] == "signature"}
        assert "null_scan" in rules

    def test_threat_has_required_keys(self, engine):
        threats = engine.detect(syn_flood_features())
        for t in threats:
            assert "type" in t
            assert "rule" in t
            assert "severity" in t
            assert "confidence" in t

    def test_context_attached_to_threat(self, engine):
        threats = engine.detect(syn_flood_features(), src_ip="1.2.3.4", dst_ip="5.6.7.8")
        for t in threats:
            assert t.get("src_ip") == "1.2.3.4"
            assert t.get("dst_ip") == "5.6.7.8"

    def test_rule_count(self, engine):
        assert engine.rule_count() == 4

    def test_detect_is_thread_safe(self, engine):
        """Calling detect() from multiple threads must not raise."""
        import threading
        errors = []

        def run():
            try:
                engine.detect(syn_flood_features())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=run) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


# ---------------------------------------------------------------------------
# DetectionEngine — anomaly detection
# ---------------------------------------------------------------------------

class TestAnomalyDetection:
    @pytest.fixture
    def trained_engine(self, tmp_path):
        rules_yaml = tmp_path / "sigs.yaml"
        rules_yaml.write_text("rules: []\n")
        engine = DetectionEngine(rules_path=rules_yaml)

        # Build training data aligned to FEATURE_NAMES order
        rng = np.random.default_rng(42)
        n = 1000
        base = np.array([500, 1.0, 5.0, 2500.0, 0x18, 65535, 1, 1, 0, 1], dtype=float)
        X = rng.normal(loc=base, scale=[10, 0.01, 0.1, 50, 0, 100, 0, 0, 0, 0], size=(n, 10))
        X = np.abs(X)
        engine.train(X, contamination=0.05,
                     model_path=tmp_path / "model.pkl",
                     scaler_path=tmp_path / "scaler.pkl")
        return engine

    def test_not_trained_by_default(self, tmp_path, monkeypatch):
        # No model files exist in tmp_path, so engine should not be trained
        monkeypatch.setattr("ids.detection_engine.MODEL_PATH", tmp_path / "no_model.pkl")
        monkeypatch.setattr("ids.detection_engine.SCALER_PATH", tmp_path / "no_scaler.pkl")
        rules_yaml = tmp_path / "sigs.yaml"
        rules_yaml.write_text("rules: []\n")
        engine = DetectionEngine(rules_path=rules_yaml)
        assert not engine.is_trained()

    def test_trained_after_train(self, trained_engine):
        assert trained_engine.is_trained()

    def test_anomaly_score_ordering(self, trained_engine):
        """
        Extreme outlier traffic must score lower (more anomalous) than
        in-distribution normal traffic. This verifies the model discriminates
        correctly regardless of the absolute threshold.
        """
        base = np.array([500, 1.0, 5.0, 2500.0, 0x18, 65535, 1, 1, 0, 1], dtype=float)
        normal_fd = dict(zip(FEATURE_NAMES, base))
        extreme_fd = dict(zip(FEATURE_NAMES, [99999, 0.001, 99999, 9999999, 0, 0, 999, 0, 999, 999]))

        vec_normal = np.array([[normal_fd.get(f, 0) for f in FEATURE_NAMES]])
        vec_extreme = np.array([[extreme_fd.get(f, 0) for f in FEATURE_NAMES]])

        score_normal = float(trained_engine._model.score_samples(
            trained_engine._scaler.transform(vec_normal))[0])
        score_extreme = float(trained_engine._model.score_samples(
            trained_engine._scaler.transform(vec_extreme))[0])

        assert score_extreme < score_normal, (
            f"Expected extreme traffic (score={score_extreme:.3f}) to be more "
            f"anomalous than normal (score={score_normal:.3f})"
        )

    def test_anomaly_threat_has_score(self, trained_engine):
        """Inject a wildly abnormal feature vector and expect an anomaly threat."""
        extreme = make_normal_features(packet_rate=99999, byte_rate=99999999)
        threats = trained_engine.detect(extreme)
        anomaly_threats = [t for t in threats if t["type"] == "anomaly"]
        if anomaly_threats:
            assert "score" in anomaly_threats[0]
            assert "confidence" in anomaly_threats[0]


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------

class TestFeatureVector:
    def test_vector_length_matches_feature_names(self):
        vec = features_to_vector(make_normal_features())
        assert len(vec) == len(FEATURE_NAMES)

    def test_missing_features_default_to_zero(self):
        vec = features_to_vector({})
        assert all(v == 0 for v in vec)

    def test_values_correct(self):
        f = make_normal_features(packet_size=1234)
        vec = features_to_vector(f)
        idx = FEATURE_NAMES.index("packet_size")
        assert vec[idx] == 1234
