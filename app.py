import streamlit as st
import pandas as pd
from datetime import datetime

from core.validators import detect_type, normalize_indicator
from core.intel_simulator import simulate_intel
from core.scoring import score_indicator, risk_level
from core.storage import load_history, save_history, append_history
from core.report import make_alert_json

st.set_page_config(page_title="SOC Lite • Threat Intel (Simulated)", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC Lite — Threat Intel & Risk Scoring Dashboard (Simulated)")
st.caption("No external APIs. Everything is simulated using local intelligence datasets and scoring logic.")

# Sidebar settings
st.sidebar.header("⚙️ Settings")
max_history = st.sidebar.slider("Max history rows", 20, 500, 200, 10)
auto_save = st.sidebar.toggle("Auto-save history", value=True)

tab1, tab2, tab3 = st.tabs(["🔎 Analyzer", "📊 Dashboard", "🧾 JSON Alert"])

history = load_history()
if len(history) > max_history:
    history = history.tail(max_history)

with tab1:
    st.subheader("Analyze an indicator")
    raw = st.text_input("Enter IP / Domain / URL", placeholder="e.g. 8.8.8.8 or example.com or https://example.com/login")

    colA, colB = st.columns([1, 1])
    run = colA.button("Analyze ✅", use_container_width=True)
    clear = colB.button("Clear history 🧹", use_container_width=True)

    if clear:
        save_history(pd.DataFrame(columns=["timestamp","type","indicator","score","level","signals"]))
        st.success("History cleared.")
        st.rerun()

    if run and raw.strip():
        indicator = normalize_indicator(raw.strip())
        ind_type = detect_type(indicator)

        intel = simulate_intel(indicator, ind_type)
        score, signals = score_indicator(indicator, ind_type, intel, history)
        level = risk_level(score)

        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        st.markdown("### Result")
        c1, c2, c3 = st.columns(3)
        c1.metric("Type", ind_type)
        c2.metric("Risk Score", score)
        c3.metric("Risk Level", level)

        st.markdown("### Signals (Why this score?)")
        st.dataframe(pd.DataFrame(signals), use_container_width=True)

        st.markdown("### Simulated intel context")
        st.json(intel)

        if auto_save:
            row = {
                "timestamp": ts,
                "type": ind_type,
                "indicator": indicator,
                "score": score,
                "level": level,
                "signals": ", ".join([s["signal"] for s in signals]),
            }
            history2 = append_history(history, row, max_history=max_history)
            save_history(history2)
            history = history2

        st.session_state["last_alert"] = make_alert_json(ts, indicator, ind_type, score, level, signals, intel)

with tab2:
    st.subheader("Dashboard")
    if history.empty:
        st.info("No history yet. Run an analysis in the Analyzer tab.")
    else:
        st.dataframe(history.sort_values("timestamp", ascending=False), use_container_width=True)

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total analyzed", int(len(history)))
        col2.metric("High+", int((history["score"] >= 50).sum()))
        col3.metric("Critical", int((history["score"] >= 75).sum()))
        col4.metric("Unique indicators", int(history["indicator"].nunique()))

        st.markdown("### Risk distribution")
        dist = history["level"].value_counts().reset_index()
        dist.columns = ["level", "count"]
        st.bar_chart(dist.set_index("level"))

with tab3:
    st.subheader("SIEM-style JSON alert")
    alert = st.session_state.get("last_alert")
    if not alert:
        st.info("Run an analysis first to generate an alert.")
    else:
        st.json(alert)
        st.download_button(
            "Download alert.json",
            data=pd.Series(alert).to_json(),
            file_name="alert.json",
            mime="application/json",
        )