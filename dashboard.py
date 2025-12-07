import json
import os
import math
import time

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
    resp = call_api_with_retry(
        "GET",
        f"{API_BASE}/api/history",
        headers=headers,
        params={"limit": limit},
        timeout=12,
        retries=2,
        backoff_sec=2,
    )
    if resp is None:
        st.warning("Could not load history (timed out). Please ensure api_service.py is running and try again.")
        return []
    try:
        resp.raise_for_status()
        return resp.json().get("results", [])
    except requests.HTTPError as e:
        status = getattr(e.response, "status_code", "n/a")
        st.warning(f"Could not load history: {e} (status {status})")
    except ValueError:
        st.warning("History response was not valid JSON.")
    return []


def call_api_with_retry(
    method: str,
    url: str,
    *,
    headers=None,
    params=None,
    json=None,
    timeout: float = 30,
    retries: int = 2,
    backoff_sec: float = 2,
):
    """Lightweight retry helper to reduce transient timeouts."""
    attempts = retries + 1
    for attempt in range(1, attempts + 1):
        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json,
                timeout=timeout,
            )
            return resp
        except requests.exceptions.Timeout:
            if attempt >= attempts:
                break
            time.sleep(backoff_sec)
        except requests.exceptions.RequestException:
            if attempt >= attempts:
                break
            time.sleep(backoff_sec)
    return None


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
        return None, "No data yet. Analyze some emails first in the 'Analyze Emails' tab."

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
# --- Tabs layout ----------------------------------------------------------
tab_analyze, tab_archive = st.tabs(["Analyze Emails", "Analysis Archive"])

with tab_analyze:
    # Upload single email
    st.subheader("Upload Suspicious Email")
    uploaded = st.file_uploader(".eml/.txt file upload", type=["txt", "eml"])
    subject = st.text_input("Subject override (optional)")
    if uploaded:
        email_body = uploaded.read().decode(errors="ignore")
        payload = {"title": subject, "body": email_body}
        with st.spinner("Analyzing..."):
            resp = call_api_with_retry(
                "POST",
                f"{API_BASE}/api/analyze",
                headers=headers,
                json=payload,
                timeout=25,
                retries=2,
                backoff_sec=2,
            )
            if resp is None:
                st.warning("API timed out after multiple retries. Please check api_service.py and try again.")
            else:
                try:
                    data = resp.json()
                except ValueError:
                    st.warning("API response was not valid JSON.")
                else:
                    if resp.status_code >= 400:
                        st.warning(f"API error({resp.status_code}): {data}")
                    else:
                        st.json(data)

    # Browse & Select Emails
    st.subheader("Browse & Select Emails")
    select_max = st.number_input("Max emails to load", min_value=1, max_value=50, value=20, step=1)
    LABEL_CHOICES = [
        "ALL",
        "INBOX",
        "UNREAD",
        "CATEGORY_PROMOTIONS",
        "CATEGORY_UPDATES",
        "CATEGORY_SOCIAL",
    ]
    label_filter = st.selectbox("Label filter", LABEL_CHOICES, index=2)

    if "email_list" not in st.session_state:
        st.session_state["email_list"] = []
    if "selected_message_ids" not in st.session_state:
        st.session_state["selected_message_ids"] = []

    hide_analyzed = st.checkbox(
        "Hide emails that have already been analyzed",
        value=True,
        help="Uses the analysis history to hide Gmail messages that are already stored in the archive.",
    )

    if st.button("Load Email List"):
        params = {"max_results": int(select_max)}
        if label_filter != "ALL":
            params["label"] = label_filter
        resp = call_api_with_retry(
            "GET",
            f"{API_BASE}/api/list_emails",
            headers=headers,
            params=params,
            timeout=25,
            retries=2,
            backoff_sec=2,
        )
        if resp is None:
            st.warning("Failed to load email list (timed out). Please ensure api_service.py is running and try again.")
        else:
            try:
                resp.raise_for_status()
                data = resp.json()
            except requests.HTTPError as e:
                status = getattr(e.response, "status_code", "n/a")
                st.warning(f"Failed to load email list: {e} (status {status})")
            except ValueError:
                st.warning("Email list response was not valid JSON.")
            else:
                results = data.get("results", [])
                if hide_analyzed:
                    history_list = load_history_from_api(API_TOKEN)
                    analyzed_ids = {row.get("gmail_id") for row in history_list if row.get("gmail_id")}
                    results = [msg for msg in results if msg.get("gmail_id") not in analyzed_ids]
                st.session_state["email_list"] = results

    email_list = st.session_state.get("email_list", [])
    selected_ids: list[str] = []
    if email_list:
        emails_df = pd.DataFrame(email_list)
        if "selected" not in emails_df:
            emails_df.insert(0, "selected", False)
        edited_df = st.data_editor(
            emails_df,
            use_container_width=True,
            num_rows="fixed",
            column_config={"selected": st.column_config.CheckboxColumn("selected")},
        )
        selected_ids = edited_df.loc[edited_df["selected"], "gmail_id"].tolist()
        st.session_state["selected_message_ids"] = selected_ids

    if st.button("Analyze Selected Emails"):
        selected_ids = st.session_state.get("selected_message_ids", [])
        if not selected_ids:
            st.warning("No emails selected.")
        else:
            with st.spinner("Analyzing selected emails..."):
                resp = call_api_with_retry(
                    "POST",
                    f"{API_BASE}/api/analyze_selected",
                    headers=headers,
                    json={"message_ids": selected_ids},
                    timeout=90,
                    retries=2,
                    backoff_sec=2,
                )
                if resp is None:
                    st.warning("API timed out after multiple retries. Please ensure api_service.py is running and try again.")
                else:
                    try:
                        data = resp.json()
                    except ValueError:
                        st.warning("API response was not valid JSON.")
                    else:
                        if resp.status_code >= 400:
                            st.warning(f"API error({resp.status_code}): {data}")
                        else:
                            st.success(f"Analyzed {len(data.get('results', []))} selected emails.")
                            st.cache_data.clear()

with tab_archive:
    history_list = load_history_from_api(API_TOKEN)
    result_df = pd.DataFrame(history_list)

    # KPI cards (from DB history, fallback to API summary)
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

    # Trend chart (multi-line)
    trend_chart, trend_msg = build_trend_chart(result_df)
    if trend_chart is not None:
        st.altair_chart(trend_chart, width="stretch")
    else:
        st.info(trend_msg)

    # Analyzed Email Archive (single unified table)
    st.subheader("Analyzed Email Archive")
    archive_label_filter = st.selectbox(
        "Filter by analysis label",
        ["ALL", "phishing", "normal"],
        index=0,
    )
    archive_subject_query = st.text_input("Subject search (contains)")
    archive_days = st.number_input(
        "Limit to recent N days",
        min_value=0,
        max_value=365,
        value=0,
        step=1,
        help="0 = no limit",
    )

    archive_df = result_df.copy()
    if archive_label_filter != "ALL":
        archive_df = archive_df[archive_df.get("label", "") == archive_label_filter]
    if archive_subject_query:
        archive_df = archive_df[archive_df.get("subject", "").str.contains(archive_subject_query, case=False, na=False)]

    if archive_days and archive_days > 0:
        dt_series = extract_datetime_series(archive_df)
        if dt_series is not None:
            cutoff = pd.Timestamp.now(tz=dt_series.dt.tz) - pd.Timedelta(days=int(archive_days))
            archive_df = archive_df[dt_series >= cutoff]

    if not archive_df.empty:
        archive_df = archive_df.copy()
        archive_df["confidence_pct"] = (archive_df.get("confidence", 0).fillna(0) * 100).round(2)
        unified_cols = ["date", "subject", "label", "confidence_pct", "feedback"]
        unified_df = archive_df.reindex(columns=unified_cols)
        unified_df.insert(0, "no", range(1, len(unified_df) + 1))
        st.dataframe(unified_df, use_container_width=True)
    else:
        st.info("No analyzed emails match the archive filters.")
