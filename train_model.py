"""
scripts/train_model.py — Train the Isolation Forest on the NSL-KDD dataset.

Downloads NSL-KDD KDDTrain+.txt if not already present, engineers features
to match the real-time pipeline, trains the model, and prints a full
evaluation report (precision, recall, F1, confusion matrix, AUC-ROC).

Usage
-----
    python scripts/train_model.py [--data-dir data/] [--contamination 0.05]

The trained model is saved to model/isolation_forest.pkl and
model/scaler.pkl. The IDS loads these automatically at startup.
"""

import argparse
import logging
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    f1_score,
)
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# NSL-KDD column names (41 features + label + difficulty)
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

# Numeric features we'll use (skip categorical for the MVP; can add OHE later)
NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"


def download_if_missing(url: str, dest: Path):
    if dest.exists():
        logger.info("Using cached %s", dest)
        return
    logger.info("Downloading %s → %s", url, dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, dest)


def load_nslkdd(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
    # Binary label: "normal" → 0, everything else → 1
    df["is_attack"] = (df["label"] != "normal").astype(int)
    return df


def engineer_features(df: pd.DataFrame) -> np.ndarray:
    """Select and scale numeric features."""
    return df[NUMERIC_FEATURES].fillna(0).values


def evaluate(y_true, y_pred, y_scores, split: str):
    print(f"\n{'='*60}")
    print(f"  Evaluation on {split} set")
    print(f"{'='*60}")
    print(classification_report(y_true, y_pred, target_names=["normal", "attack"]))

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  Confusion matrix:")
    print(f"    TN={tn:>6}  FP={fp:>6}")
    print(f"    FN={fn:>6}  TP={tp:>6}")

    try:
        auc = roc_auc_score(y_true, y_scores)
        print(f"\n  AUC-ROC: {auc:.4f}")
    except Exception:
        pass

    f1 = f1_score(y_true, y_pred)
    print(f"  F1 (attack class): {f1:.4f}")


def main(data_dir: Path, model_dir: Path, contamination: float):
    train_path = data_dir / "KDDTrain+.txt"
    test_path  = data_dir / "KDDTest+.txt"

    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL, test_path)

    logger.info("Loading datasets ...")
    df_train = load_nslkdd(train_path)
    df_test  = load_nslkdd(test_path)

    X_train = engineer_features(df_train)
    y_train = df_train["is_attack"].values

    X_test = engineer_features(df_test)
    y_test = df_test["is_attack"].values

    logger.info(
        "Train: %d samples (%d normal, %d attack)",
        len(y_train), (y_train == 0).sum(), (y_train == 1).sum(),
    )
    logger.info(
        "Test:  %d samples (%d normal, %d attack)",
        len(y_test), (y_test == 0).sum(), (y_test == 1).sum(),
    )

    # Train only on normal traffic (unsupervised anomaly detection)
    X_normal = X_train[y_train == 0]
    logger.info("Fitting Isolation Forest on %d normal samples ...", len(X_normal))

    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_normal_scaled)

    # Evaluate on full test set
    X_test_scaled = scaler.transform(X_test)
    scores = model.score_samples(X_test_scaled)
    # IsolationForest: negative scores → anomaly; threshold from contamination
    threshold = np.percentile(scores, contamination * 100)
    y_pred = (scores < threshold).astype(int)

    evaluate(y_test, y_pred, -scores, "NSL-KDD test")

    # Persist
    import pickle
    model_dir.mkdir(parents=True, exist_ok=True)
    with open(model_dir / "isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    with open(model_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    logger.info("Model saved to %s/", model_dir)
    print("\nTraining complete. Start the IDS with: sudo python -m ids.intrusion")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--model-dir", type=Path, default=Path("model"))
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()
    main(args.data_dir, args.model_dir, args.contamination)
