# dashboard.py
"""
Streamlit dashboard wrapper for the Real-time Intrusion Detection System repo.

This lightweight dashboard:
 - Loads an existing classifier from models/
 - Allows uploading or selecting a CSV of flow features (same format as your input_logs.csv/output_logs.csv)
 - Runs predictions and displays a table, simple charts, and download buttons.

Notes:
 - This avoids touching the Flask + SocketIO live server. If you later want real-time sniffing,
   see the notes at the bottom of this file for how to integrate `snif_and_detect()` / `newPacket()` from application.py.
"""

import os
import io
import pickle
import joblib
import pandas as pd
import numpy as np
import streamlit as st

# UI config
st.set_page_config(page_title="AI IDS - Streamlit Dashboard", layout="wide", page_icon="🛡️")

# Typical column list from application.py (order matters if you rely on positional features)
DEFAULT_COLS = [
    'FlowID','FlowDuration','BwdPacketLenMax','BwdPacketLenMin','BwdPacketLenMean','BwdPacketLenStd',
    'FlowIATMean','FlowIATStd','FlowIATMax','FlowIATMin','FwdIATTotal','FwdIATMean','FwdIATStd','FwdIATMax','FwdIATMin',
    'BwdIATTotal','BwdIATMean','BwdIATStd','BwdIATMax','BwdIATMin','FwdPSHFlags','FwdPackets_s','MaxPacketLen',
    'PacketLenMean','PacketLenStd','PacketLenVar','FINFlagCount','SYNFlagCount','PSHFlagCount','ACKFlagCount','URGFlagCount',
    'AvgPacketSize','AvgBwdSegmentSize','InitWinBytesFwd','InitWinBytesBwd','ActiveMin','IdleMean','IdleStd','IdleMax','IdleMin',
    'Src','SrcPort','Dest','DestPort','Protocol','FlowStartTime','FlowLastSeen','PName','PID','Classification','Probability','Risk'
]

# ---- Helper functions ----
def load_classifier(model_paths=None):
    """
    Attempt to load a classifier from one of a few likely filenames.
    Returns (clf, loader_name) or (None, None) on failure.
    """
    if model_paths is None:
        model_paths = [
            "models/model.pkl",          # older style
            "models/model.joblib",
            "models/classifier.pkl",
            "models/ids_model.pkl",
            "models/ids_model.joblib",
        ]
    for p in model_paths:
        try:
            if os.path.exists(p):
                # try joblib then pickle
                try:
                    clf = joblib.load(p)
                except Exception:
                    with open(p, "rb") as f:
                        clf = pickle.load(f)
                return clf, p
        except Exception:
            continue
    return None, None

def safe_predict(clf, X_df):
    """
    Run predict_proba/predict and return dataframe with prob & label.
    If classifier supports predict_proba, take top class probability and predicted label.
    """
    out = X_df.copy()
    if clf is None:
        out["pred"] = None
        out["prob"] = None
        return out
    try:
        # Ensure X has only numeric columns used by model. If model expects N numeric features,
        # we attempt to select the first N numeric columns. This is a pragmatic approach.
        Xnum = out.select_dtypes(include=[np.number])
        if Xnum.shape[1] == 0:
            Xnum = out.fillna(0).select_dtypes(include=[np.number])
        preds = None
        probs = None
        if hasattr(clf, "predict_proba"):
            probs_all = clf.predict_proba(Xnum)
            # if multiclass, take max probability and label; adapt as needed
            if probs_all.ndim == 2:
                probs = probs_all.max(axis=1)
                pred_ids = probs_all.argmax(axis=1)
                # map class indices to labels if available
                if hasattr(clf, "classes_"):
                    preds = [clf.classes_[i] for i in pred_ids]
                else:
                    preds = pred_ids.tolist()
            else:
                probs = probs_all
                preds = clf.predict(Xnum)
        else:
            preds = clf.predict(Xnum)
            # best-effort probability: 1 for predicted class, 0 otherwise
            probs = [1.0 if p is not None else 0.0 for p in preds]
        out["pred"] = preds
        out["prob"] = probs
    except Exception as e:
        st.warning(f"Prediction failed: {e}")
        out["pred"] = None
        out["prob"] = None
    return out

def map_risk_from_prob(prob):
    try:
        p = float(prob)
    except Exception:
        return "Unknown"
    if p >= 0.9:
        return "Very High"
    if p >= 0.7:
        return "High"
    if p >= 0.4:
        return "Medium"
    if p >= 0.2:
        return "Low"
    return "Minimal"

# ---- Sidebar controls ----
st.sidebar.title("Controls")
st.sidebar.markdown("Model & input selection")

classifier, model_path = load_classifier()
if classifier is not None:
    st.sidebar.success(f"Loaded model from: {model_path}")
else:
    st.sidebar.warning("No model found in models/*. Try placing your classifier in models/ (model.pkl or ids_model.pkl).")

use_example = st.sidebar.checkbox("Use local CSV (input_logs.csv)", value=True)
uploaded = st.sidebar.file_uploader("Or upload a CSV file with flow features", type=["csv", "txt"])

st.sidebar.markdown("---")
st.sidebar.markdown("Prediction options")
prob_filter = st.sidebar.slider("Minimum probability to show", 0.0, 1.0, 0.0, 0.01)
max_rows = st.sidebar.number_input("Max rows to show", min_value=5, max_value=5000, value=200)

# ---- Main UI ----
st.title("AI Intrusion Detection - Streamlit Dashboard")
st.markdown("Use this lightweight dashboard to run the existing trained classifier on saved flow feature CSVs. For live sniffing / real-time UI, see the notes below.")

# Data load
df = None
if uploaded is not None:
    try:
        df = pd.read_csv(uploaded)
        st.success("Loaded uploaded CSV")
    except Exception as e:
        st.error(f"Failed to parse uploaded CSV: {e}")

elif use_example:
    candidate = None
    for n in ["input_logs.csv", "output_logs.csv", "input_logs", "output_logs"]:
        if os.path.exists(n):
            candidate = n
            break
    if candidate:
        try:
            df = pd.read_csv(candidate)
            st.success(f"Loaded local file: {candidate}")
        except Exception as e:
            st.error(f"Failed to read {candidate}: {e}")
    else:
        st.info("No local `input_logs.csv`/`output_logs.csv` found. Upload a CSV or generate one using your existing pipeline.")

if df is None:
    st.info("Provide a CSV file of flow features (same columns/format as the original pipeline), or deselect the 'Use local CSV' option and upload a file.")
    st.stop()

# show basic info
st.subheader("Input preview")
st.write(f"Shape: {df.shape}")
st.dataframe(df.head(10))

# Run predictions (best-effort)
with st.spinner("Running predictions..."):
    results = safe_predict(classifier, df)
    # add risk mapping
    if "prob" in results.columns:
        results["risk"] = results["prob"].apply(map_risk_from_prob)
    else:
        results["risk"] = results.get("Risk", "Unknown")

# filter by probability
if "prob" in results.columns and prob_filter > 0:
    display = results[results["prob"] >= prob_filter].head(max_rows)
else:
    display = results.head(max_rows)

st.subheader("Predictions")
st.dataframe(display)

# Summary KPIs
st.markdown("---")
col1, col2, col3, col4 = st.columns(4)
total = len(results)
num_predicted = int(results["pred"].notnull().sum()) if "pred" in results.columns else 0
col1.metric("Total rows", total)
col2.metric("Predicted rows", num_predicted)
if "prob" in results.columns:
    avg_prob = float(pd.to_numeric(results["prob"], errors="coerce").mean())
    col3.metric("Avg probability", f"{avg_prob:.3f}")
else:
    col3.metric("Avg probability", "n/a")
# risk distribution
if "risk" in results.columns:
    risk_counts = results["risk"].value_counts().to_dict()
    col4.write("Risk counts")
    col4.json(risk_counts)

# allow downloads
st.markdown("---")
csv_bytes = results.to_csv(index=False).encode("utf-8")
st.download_button("Download results (CSV)", csv_bytes, file_name="ids_results.csv", mime="text/csv")

# simple plotting
st.subheader("Probability distribution")
if "prob" in results.columns:
    st.bar_chart(results["prob"].fillna(0).astype(float))
else:
    st.info("No probability column available to show distribution")

# optional detailed view
st.subheader("Inspect single row")
rid = st.number_input("Row index (0-based)", 0, max(0, len(results)-1), 0)
st.json(results.iloc[int(rid)].to_dict())

st.markdown("---")
st.info("Notes: this dashboard runs offline predictions from CSVs. To enable live sniffing (Scapy) you can port `snif_and_detect()` / `newPacket()` from application.py into a background thread here, but that requires running Streamlit with elevated privileges (or running on a machine with packet capture enabled). See the README notes in the repo for live-sniff instructions.")