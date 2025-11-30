import json
import os
import math

import altair as alt
import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

# curl example (replace TOKEN)
# curl.exe -X POST "http://127.0.0.1:8080/api/analyze" ^
#   -H "Content-Type: application/json" ^
#   -H "X-API-Key": <TOKEN> ^
#   -d "{\"title\":\"Invoice overdue\",\"body\":\"Click here to pay now: http://phish.example\"}"

load_dotenv()
os.environ.setdefault("PYTHONUTF8", "1")

API_BASE = os.getenv("PHISH_API_URL", "http://localhost:8080")

st.set_page_config(page_title="PhishGuard Dashboard", layout="wide")
st.title("PhishGuard Operations Dashboard")

# --- token handling -------------------------------------------------------
env_token = os.getenv("PHISH_API_TOKEN", "").strip()
ui_token = st.text_input("API Token (optional, UI overrides env)", value="")
API_TOKEN = ui_token.strip() or env_token  # UI input has priority over env
headers = {"X-API-Key": API_TOKEN} if API_TOKEN else {}
if ui_token.strip():
    st.caption(f"Using token from input (****{API_TOKEN[-4:]})")
elif env_token:
    st.caption(f"Using token from PHISH_API_TOKEN (****{env_token[-4:]})")
else:
    st.caption("No API token set; some endpoints may require it.")
if not API_TOKEN:
    st.info("Tokenless calls may return 401 if the server requires an API key.")


# --- API helpers ----------------------------------------------------------
def fetch_summary(token: str):
    """Fetch KPI summary with soft warnings; no caching to avoid stale failures."""
    fallback = {
        "phishing_today": 0,
        "false_positives": 0,
        "avg_feedback_latency_ms": 0,
        "monthly_trend": [],
    }
    headers = {"X-API-Key": token} if token else {}
    try:
        resp = requests.get(f"{API_BASE}/metrics/summary", headers=headers, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return {**fallback, **data}
    except requests.HTTPError as e:
        status = getattr(e.response, "status_code", "n/a")
        st.warning(f"Could not fetch KPI summary from API: {e} (status {status})")  # softer warning
    except requests.RequestException as e:
        st.warning("Could not fetch KPI summary from API: " + str(e))  # softer warning
    except ValueError:
        st.warning("API response was not valid JSON; using fallback KPIs.")
    return fallback


@st.cache_data(ttl=15)
def load_history_from_api(token: str, limit: int = 300):
    """Short-lived cache to pull analysis history from backend DB."""
    headers = {"X-API-Key": token} if token else {}
    try:
        resp = requests.get(f"{API_BASE}/api/history?limit={limit}", headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json().get("results", [])
    except requests.HTTPError as e:
        status = getattr(e.response, "status_code", "n/a")
        st.warning(f"Could not load history: {e} (status {status})")
    except requests.RequestException as e:
        st.warning("Could not load history: " + str(e))
    except ValueError:
        st.warning("History response was not valid JSON.")
    return []


# --- helpers ---------------------------------------------------------------
def get_column(df: pd.DataFrame, name: str, default):
    return df[name] if name in df else pd.Series([default] * len(df))


def extract_datetime_series(df: pd.DataFrame) -> pd.Series | None:
    for candidate in ("date", "timestamp", "created_at"):
        if candidate in df:
            return pd.to_datetime(df[candidate], errors="coerce")
    return None


def compute_kpis_from_results(df: pd.DataFrame):
    if df.empty:
        return None

    dt_series = extract_datetime_series(df)
    if dt_series is None:
        dt_series = pd.Series([pd.Timestamp.now()] * len(df), index=df.index)

    df_dates = df.copy()
    df_dates["__dt"] = dt_series
    today = pd.Timestamp.now().date()
    df_today = df_dates[df_dates["__dt"].dt.date == today]

    phishing_today = int((df_today.get("label", "") == "phishing").sum())
    lat_series = df_today.get("latency_ms", pd.Series(dtype=float)).dropna()
    avg_latency = lat_series.mean()
    if pd.isna(avg_latency):
        avg_latency = 0.0
    avg_latency = float(avg_latency)
    false_positives = 0  # TODO: replace when manual labeling/feedback is available
    return {
        "phishing_today": phishing_today,
        "false_positives": false_positives,
        "avg_feedback_latency_ms": avg_latency,
    }


def build_trend_chart(df: pd.DataFrame):
    if df.empty:
        return None, "No data yet. Run 'Fetch & Analyze Emails' to populate the trend."

    dt_series = extract_datetime_series(df)
    if dt_series is None or dt_series.isna().all():
        return None, "Trend chart unavailable: no date/timestamp column in results."

    df_dates = df.copy()
    df_dates["__dt"] = dt_series
    df_dates["date_only"] = df_dates["__dt"].dt.date

    total = df_dates.groupby("date_only").size().reset_index(name="total_count")
    phishing = (
        df_dates[df_dates.get("label", "") == "phishing"]
        .groupby("date_only")
        .size()
        .reset_index(name="phishing_count")
    )
    merged = total.merge(phishing, on="date_only", how="left").fillna({"phishing_count": 0})
    if merged.empty:
        return None, "No analyzed emails available to plot."

    merged["date_only"] = pd.to_datetime(merged["date_only"], errors="coerce")
    chart_data = merged.melt(
        id_vars=["date_only"],
        value_vars=["total_count", "phishing_count"],
        var_name="metric",
        value_name="count",
    )
    trend_chart = (
        alt.Chart(chart_data)
        .mark_line(point=True)
        .encode(
            x=alt.X("date_only:T", title="Date"),
            y=alt.Y("count:Q", title="Email Count"),
            color=alt.Color("metric:N", title="Metric"),
            tooltip=["date_only:T", "metric:N", "count:Q"],
        )
        .properties(height=280)
    )
    return trend_chart, None


def build_summary_table(df: pd.DataFrame):
    if df.empty:
        return df
    summary_base = df.copy()
    summary_base["confidence_pct"] = (get_column(summary_base, "confidence", 0).fillna(0) * 100).round(2)
    return summary_base.reindex(columns=["subject", "label", "confidence_pct", "feedback"])


# --- Upload single email --------------------------------------------------
st.subheader("Upload Suspicious Email")
uploaded = st.file_uploader(".eml/.txt file upload", type=["txt", "eml"])
subject = st.text_input("Subject override (optional)")
if uploaded:
    email_body = uploaded.read().decode(errors="ignore")
    payload = {"title": subject, "body": email_body}
    with st.spinner("Analyzing..."):
        try:
            resp = requests.post(f"{API_BASE}/api/analyze", json=payload, headers=headers, timeout=15)
        except requests.RequestException as e:
            st.error("API connection failed: " + str(e))
        else:
            try:
                data = resp.json()
            except ValueError:
                st.error("API response was not valid JSON.")
            else:
                if resp.status_code >= 400:
                    st.error(f"API error({resp.status_code}): {data}")
                else:
                    st.json(data)

# --- Fetch & analyze in bulk ---------------------------------------------
st.subheader("Fetch & Analyze Emails")
max_results = st.number_input("Max emails to analyze", min_value=1, max_value=50, value=5, step=1)
history_list = None
if st.button("Fetch & Analyze Emails"):
    with st.spinner("Fetching from Gmail and analyzing..."):
        try:
            resp = requests.post(
                f"{API_BASE}/api/fetch_and_analyze",
                json={"max_results": int(max_results)},
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as e:
            st.error("API connection failed: " + str(e))
        else:
            try:
                data = resp.json()
            except ValueError:
                st.error("API response was not valid JSON.")
            else:
                if resp.status_code >= 400:
                    st.error(f"API error({resp.status_code}): {data}")
                else:
                    st.success(f"Analyzed {len(data.get('results', []))} emails.")
                    st.cache_data.clear()  # clear cached history
                    history_list = load_history_from_api(API_TOKEN)  # reload fresh history

# If not refreshed in the button block, load cached/fresh history now
if history_list is None:
    history_list = load_history_from_api(API_TOKEN)

# Build result_df from DB-backed history
result_df = pd.DataFrame(history_list)

# --- KPI cards (from DB history, fallback to API summary) -----------------
summary = fetch_summary(API_TOKEN)
kpi_from_results = compute_kpis_from_results(result_df)
metric_phishing_today = (kpi_from_results or summary).get("phishing_today", 0)
metric_false_positive = (kpi_from_results or summary).get("false_positives", 0)
metric_avg_latency = (kpi_from_results or summary).get("avg_feedback_latency_ms", 0)
if metric_avg_latency is None or (isinstance(metric_avg_latency, float) and math.isnan(metric_avg_latency)):
    metric_avg_latency = 0.0

col1, col2, col3 = st.columns(3)
col1.metric("Phishing Detected (Today)", metric_phishing_today)
col2.metric("False Positives (Today)", metric_false_positive)
col3.metric("Avg GPT Latency (ms)", round(metric_avg_latency, 1))

# --- Trend chart (multi-line) ---------------------------------------------
trend_chart, trend_msg = build_trend_chart(result_df)
if trend_chart is not None:
    st.altair_chart(trend_chart, width="stretch")
else:
    st.info(trend_msg)

# --- Summary + detailed views --------------------------------------------
if not result_df.empty:
    sorted_df = result_df.sort_values(by="confidence", ascending=False)
    df_summary = build_summary_table(sorted_df)

    st.subheader("Email Analysis (Summary View)")
    st.dataframe(df_summary, use_container_width=True)  # subject/label/confidence_pct/feedback only

    st.subheader("Detailed View")
    for _, row in sorted_df.iterrows():
        subject_text = row.get("subject", "(no subject)")
        label_text = row.get("label", "")
        with st.expander(f"{subject_text} [{label_text}]"):
            st.write("ID:", row.get("id", ""))
            st.write("Confidence:", row.get("confidence", ""))
            st.write("Attachments:", row.get("attachments", ""))
            st.write("Gmail Labels:", row.get("gmail_labels", ""))
            st.write("Latency (ms):", row.get("latency_ms", ""))
            st.write("Auth Results:")
            st.json(row.get("auth_results", {}))
            st.write("Body:")
            st.text(row.get("body", ""))

    if st.checkbox("Show raw analysis data"):
        st.dataframe(sorted_df, use_container_width=True)
