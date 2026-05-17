"""
detection_engine.py — Hybrid signature + anomaly detection engine.

Signature engine
    Loads rules from rules/signatures.yaml. Each rule specifies a list of
    field/operator/value conditions that are all evaluated against the feature
    dict. Any matching rule generates a threat dict.

Anomaly engine
    Uses an Isolation Forest trained on a labelled dataset (NSL-KDD or CICIDS
    features). The model file is persisted to disk so it survives restarts.
    If no pre-trained model exists, a warning is emitted and anomaly detection
    is disabled until train() is called.

Both engines are protected by a threading.Lock so detect() is safe to call
from multiple threads simultaneously.
"""

import logging
import os
import pickle
import threading
from pathlib import Path
from typing import Optional

import numpy as np
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ids.traffic_analysis import FEATURE_NAMES, features_to_vector

logger = logging.getLogger(__name__)

RULES_PATH = Path(__file__).parent.parent / "rules" / "signatures.yaml"
MODEL_PATH = Path(__file__).parent.parent / "model" / "isolation_forest.pkl"
SCALER_PATH = Path(__file__).parent.parent / "model" / "scaler.pkl"

ANOMALY_THRESHOLD = -0.3  # lower = more anomalous; calibrated on CICIDS2017


# ---------------------------------------------------------------------------
# Operator helpers
# ---------------------------------------------------------------------------

_OPS = {
    "gt":   lambda a, b: a > b,
    "lt":   lambda a, b: a < b,
    "gte":  lambda a, b: a >= b,
    "lte":  lambda a, b: a <= b,
    "eq":   lambda a, b: a == b,
    "band": lambda a, b: bool(a & int(b)),
}


def _eval_condition(features: dict, condition: dict) -> bool:
    field = condition["field"]
    op = condition["op"]
    value = condition["value"]
    actual = features.get(field, 0)
    fn = _OPS.get(op)
    if fn is None:
        logger.warning("Unknown operator '%s' in rule condition — skipping.", op)
        return False
    return fn(actual, value)


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Thread-safe hybrid IDS detection engine.

    Usage
    -----
    engine = DetectionEngine()
    threats = engine.detect(features_dict, src_ip="1.2.3.4", dst_port=22)
    """

    def __init__(self, rules_path: Path = RULES_PATH):
        self._lock = threading.Lock()
        self._rules: list = []
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._model_trained = False

        self._load_rules(rules_path)
        self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, features: dict, **context) -> list[dict]:
        """
        Run both engines against *features* and return a list of threat dicts.
        *context* kwargs (src_ip, dst_ip, dst_port, protocol …) are attached
        to every threat for downstream logging.
        """
        threats = []
        with self._lock:
            threats.extend(self._signature_detect(features, context))
            threats.extend(self._anomaly_detect(features, context))
        return threats

    def train(self, X: np.ndarray, contamination: float = 0.05,
              model_path: Path = None, scaler_path: Path = None):
        """
        Fit the Isolation Forest on *X* (shape: n_samples × n_features).
        Persists the model to disk afterward.
        """
        mp = model_path or MODEL_PATH
        sp = scaler_path or SCALER_PATH
        mp.parent.mkdir(parents=True, exist_ok=True)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_scaled)

        with self._lock:
            self._scaler = scaler
            self._model = model
            self._model_trained = True

        with open(mp, "wb") as f:
            pickle.dump(model, f)
        with open(sp, "wb") as f:
            pickle.dump(scaler, f)

        logger.info("Isolation Forest trained and saved to %s", mp)

    def is_trained(self) -> bool:
        return self._model_trained

    def rule_count(self) -> int:
        return len(self._rules)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_rules(self, path: Path):
        if not path.exists():
            logger.warning("Signature rules file not found: %s", path)
            return
        with open(path) as f:
            data = yaml.safe_load(f)
        self._rules = data.get("rules", [])
        logger.info("Loaded %d signature rules from %s", len(self._rules), path)

    def _load_model(self):
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            try:
                with open(MODEL_PATH, "rb") as f:
                    self._model = pickle.load(f)
                with open(SCALER_PATH, "rb") as f:
                    self._scaler = pickle.load(f)
                self._model_trained = True
                logger.info("Pre-trained model loaded from %s", MODEL_PATH)
            except Exception as exc:
                logger.warning("Failed to load model: %s — anomaly detection disabled.", exc)
        else:
            logger.warning(
                "No pre-trained model found at %s. "
                "Run `python scripts/train_model.py` to train one.",
                MODEL_PATH,
            )

    def _signature_detect(self, features: dict, context: dict) -> list[dict]:
        threats = []
        for rule in self._rules:
            conditions = rule.get("conditions", [])
            if all(_eval_condition(features, c) for c in conditions):
                threats.append({
                    "type": "signature",
                    "rule": rule["name"],
                    "severity": rule.get("severity", "medium"),
                    "description": rule.get("description", ""),
                    "confidence": 1.0,
                    **context,
                })
        return threats

    def _anomaly_detect(self, features: dict, context: dict) -> list[dict]:
        if not self._model_trained:
            return []

        vec = np.array([features_to_vector(features)], dtype=float)
        try:
            vec_scaled = self._scaler.transform(vec)
            score = float(self._model.score_samples(vec_scaled)[0])
        except Exception as exc:
            logger.debug("Anomaly scoring error: %s", exc)
            return []

        if score < ANOMALY_THRESHOLD:
            confidence = min(1.0, abs(score) / abs(ANOMALY_THRESHOLD))
            return [{
                "type": "anomaly",
                "rule": "isolation_forest",
                "severity": "high" if confidence > 0.8 else "medium",
                "score": round(score, 4),
                "confidence": round(confidence, 4),
                **context,
            }]
        return []
