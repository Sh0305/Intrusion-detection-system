"""
dashboard/app.py — Real-time IDS monitoring dashboard (Streamlit).

Start with:
    streamlit run dashboard/app.py

The dashboard reads ids_alerts.log (JSON-lines) and auto-refreshes every
5 seconds. No live connection to the IDS process is required — it can run
alongside or after the fact.
"""

import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

LOG_PATH = Path("ids_alerts.log")
REFRESH_INTERVAL = 5  # seconds

st.set_page_config(
    page_title="IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

@st.cache_data(ttl=REFRESH_INTERVAL)
def load_alerts(log_path: Path = LOG_PATH) -> pd.DataFrame:
    if not log_path.exists():
        return pd.DataFrame()
    rows = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp", ascending=False)
    return df


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

st.title("🛡️  Intrusion Detection System — Live Dashboard")

df = load_alerts()

if df.empty:
    st.info(
        "No alerts yet. Start the IDS with `sudo python -m ids.intrusion` "
        "and this dashboard will auto-refresh."
    )
    st.stop()

# --- KPI row ---
col1, col2, col3, col4, col5 = st.columns(5)
sev_counts = df["severity"].value_counts()

col1.metric("Total alerts", len(df))
col2.metric("🔴 Critical", sev_counts.get("critical", 0))
col3.metric("🟠 High", sev_counts.get("high", 0))
col4.metric("🟡 Medium", sev_counts.get("medium", 0))
col5.metric("🟢 Low", sev_counts.get("low", 0))

st.divider()

# --- Two-column layout ---
left, right = st.columns([2, 1])

with left:
    st.subheader("Alert timeline (last 200)")
    timeline = df.head(200).copy()
    timeline["time"] = timeline["timestamp"].dt.strftime("%H:%M:%S")
    timeline["src → dst"] = timeline["src_ip"].fillna("?") + " → " + timeline["dst_ip"].fillna("?")
    st.dataframe(
        timeline[["time", "severity", "type", "rule", "src → dst", "protocol", "confidence"]],
        use_container_width=True,
        hide_index=True,
    )

with right:
    st.subheader("Alerts by rule")
    rule_counts = df["rule"].value_counts().reset_index()
    rule_counts.columns = ["Rule", "Count"]
    st.bar_chart(rule_counts.set_index("Rule"))

    st.subheader("Top source IPs")
    top_src = df["src_ip"].value_counts().head(10).reset_index()
    top_src.columns = ["Source IP", "Alerts"]
    st.dataframe(top_src, use_container_width=True, hide_index=True)

st.divider()

# --- Alerts over time histogram ---
st.subheader("Alerts per minute")
if "timestamp" in df.columns:
    by_minute = (
        df.set_index("timestamp")
        .resample("1min")["rule"]
        .count()
        .reset_index()
        .rename(columns={"timestamp": "Minute", "rule": "Alerts"})
    )
    st.line_chart(by_minute.set_index("Minute"))

# --- Auto-refresh footer ---
st.caption(f"Auto-refreshes every {REFRESH_INTERVAL}s · Last loaded: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")
time.sleep(REFRESH_INTERVAL)
st.rerun()
