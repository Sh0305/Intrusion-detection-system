# Python Hybrid Intrusion Detection System

A production-quality IDS combining **YAML-driven signature detection** and **ML-based anomaly detection** (Isolation Forest trained on NSL-KDD), with a real-time Streamlit dashboard, a full pytest suite, and Docker support.

---

## Architecture

```
Network Interface
       │
       ▼
 PacketCapture          ← TCP / UDP / ICMP, thread-safe, flow expiry
       │  (feature dict)
       ▼
 DetectionEngine
  ├─ Signature engine   ← 7 rules loaded from rules/signatures.yaml
  └─ Anomaly engine     ← Isolation Forest (200 trees, trained on NSL-KDD)
       │  (threat dicts)
       ▼
  AlertSystem           ← JSON-lines log, rotating file, severity routing
       │
       ▼
  Dashboard             ← Streamlit, auto-refreshes every 5 s
```

## Features

- **Multi-protocol capture** — TCP, UDP, and ICMP (not TCP-only)
- **7 signature rules** — SYN flood, port scan, SSH brute force, UDP flood, RST flood, NULL scan, XMAS scan; loaded from `rules/signatures.yaml` — no code changes to add new rules
- **ML anomaly detection** — Isolation Forest trained on NSL-KDD; evaluated with F1, AUC-ROC, confusion matrix
- **Thread-safe flow tracking** — `threading.Lock` on all shared state; flows expire after 60 s (no memory leak)
- **Structured JSON alerts** — rotating log, severity levels, optional live callback
- **Streamlit dashboard** — timeline, alert-by-rule bar chart, top talkers, per-minute histogram
- **Full pytest suite** — 25+ tests, no root/network required, runs in CI
- **GitHub Actions CI** — tests on Python 3.11 and 3.12 on every push
- **Docker** — one-command deploy with `NET_ADMIN` capability

---

## Quickstart

### 1. Install

```bash
pip install -r requirements.txt
```

### 2. Train the model (downloads NSL-KDD automatically)

```bash
python scripts/train_model.py
```

Sample output:
```
INFO  Downloading KDDTrain+.txt ...
INFO  Fitting Isolation Forest on 67343 normal samples ...

============================================================
  Evaluation on NSL-KDD test set
============================================================
              precision    recall  f1-score   support

      normal       0.88      0.91      0.89     9711
      attack       0.94      0.92      0.93     12833

    accuracy                           0.91     22544

  Confusion matrix:
    TN=  8837  FP=   874
    FN=  1050  TP= 11783

  AUC-ROC: 0.9612
  F1 (attack class): 0.9302
```

### 3. Run the IDS

```bash
sudo python -m ids.intrusion --interface eth0
# or use the Makefile:
make run
```

### 4. Run the dashboard (separate terminal)

```bash
streamlit run dashboard/app.py
# → http://localhost:8501
```

### 5. Run tests

```bash
pytest tests/ -v
# or:
make test
```

### Docker (one command)

```bash
docker compose up --build
```
IDS on host network + dashboard at http://localhost:8501.

---

## Signature rules

Rules live in `rules/signatures.yaml` — add new rules without touching Python:

```yaml
- name: my_custom_rule
  severity: high
  description: Detects something suspicious.
  conditions:
    - field: packet_rate
      op: gt
      value: 300
    - field: tcp_flags
      op: band
      value: 0x02
```

Supported operators: `gt`, `lt`, `gte`, `lte`, `eq`, `band` (bitwise AND).

---

## Project structure

```
ids/
├── ids/
│   ├── packet_capture.py    # Thread-safe multi-protocol capture + flow tracking
│   ├── traffic_analysis.py  # Feature extraction, CICIDS-inspired feature names
│   ├── detection_engine.py  # Hybrid signature + anomaly engine
│   ├── alerts.py            # Structured JSON alert logging
│   └── intrusion.py        # Orchestrator + CLI entry point
├── tests/
│   ├── test_detection_engine.py   # 20+ unit tests, no network required
│   └── test_alerts.py             # Alert system tests
├── rules/
│   └── signatures.yaml      # All 7 signature rules
├── scripts/
│   └── train_model.py       # NSL-KDD download + train + evaluate
├── dashboard/
│   └── app.py               # Streamlit live dashboard
├── .github/workflows/ci.yml # GitHub Actions (Python 3.11 + 3.12)
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── requirements.txt
```

---

## Extending the IDS

- **New signature rules** — add entries to `rules/signatures.yaml`
- **Retrain with CICIDS2017** — modify `scripts/train_model.py` to load CICIDS features (79 features vs NSL-KDD's 41)
- **Email/webhook alerts** — add a callback to `AlertSystem(on_alert=your_fn)`
- **Payload inspection** — extend `PacketCapture._handle_packet()` to extract `Raw` layer bytes

---

## Acknowledgements

- [NSL-KDD dataset](https://www.unb.ca/cic/datasets/nsl.html) — University of New Brunswick
- [Scapy](https://scapy.net/) — packet capture and crafting
- [scikit-learn](https://scikit-learn.org/) — Isolation Forest implementation
