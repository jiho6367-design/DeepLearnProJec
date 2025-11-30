import json
import os

import altair as alt
import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

# 참고용 curl (토큰이 있다면 <TOKEN> 교체)
# curl.exe -X POST "http://127.0.0.1:8080/api/analyze" ^
#   -H "Content-Type: application/json" ^
#   -H "X-API-Key: <TOKEN>" ^
#   -d "{\"title\":\"Invoice overdue\",\"body\":\"Click here to pay now: http://phish.example\"}"

load_dotenv()
os.environ.setdefault("PYTHONUTF8", "1")

API_BASE = os.getenv("PHISH_API_URL", "http://localhost:8080")

st.set_page_config(page_title="PhishGuard Dashboard", layout="wide")
st.title("PhishGuard Operations Dashboard")

env_token = os.getenv("PHISH_API_TOKEN", "").strip()
ui_token = st.text_input("API 토큰 (선택, 세션 동안 사용)", value="")
API_TOKEN = ui_token.strip() or env_token  # UI 입력이 우선, 없으면 환경 변수 사용
headers = {"X-API-Key": API_TOKEN} if API_TOKEN else {}
if env_token:
    st.caption(f"환경 변수 PHISH_API_TOKEN 감지: ****{env_token[-4:]}")
if not API_TOKEN:
    st.info("토큰 없이 호출합니다. 서버가 토큰을 요구하도록 설정되어 있다면 401 응답이 날 수 있습니다.")


@st.cache_data(ttl=300)
def fetch_summary(token: str):
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
        st.error(f"API 오류: {e} (상태 {status})")
    except requests.RequestException as e:
        st.error("API 연결 실패: " + str(e))
    except ValueError:
        st.error("API 응답을 JSON으로 파싱하지 못했습니다.")
    return fallback


summary = fetch_summary(API_TOKEN)
col1, col2, col3 = st.columns(3)
col1.metric("Phishing Detected (Today)", summary.get("phishing_today", 0))
col2.metric("False Positives (Today)", summary.get("false_positives", 0))
col3.metric(
    "Avg GPT Latency (ms)",
    round(summary.get("avg_feedback_latency_ms") or 0, 1),
)

trend_data = summary.get("monthly_trend") or []
trend_df = pd.DataFrame(trend_data)
trend_chart = (
    alt.Chart(trend_df)
    .mark_line(point=True)
    .encode(
        x=alt.X("month:T", title="Month"),
        y=alt.Y("phishing:Q", title="Phishing Count"),
        tooltip=["month", "phishing"],
    )
    .properties(height=280)
)
st.altair_chart(trend_chart, width="stretch")

st.subheader("Upload Suspicious Email")
uploaded = st.file_uploader(".eml/.txt 파일 업로드", type=["txt", "eml"])
subject = st.text_input("제목 재정의 (선택)")
if uploaded:
    email_body = uploaded.read().decode(errors="ignore")
    payload = {"title": subject, "body": email_body}
    with st.spinner("Analyzing..."):
        try:
            resp = requests.post(f"{API_BASE}/api/analyze", json=payload, headers=headers, timeout=15)
        except requests.RequestException as e:
            st.error("API 연결 실패: " + str(e))
        else:
            try:
                data = resp.json()
            except ValueError:
                st.error("API 응답을 JSON으로 파싱하지 못했습니다.")
            else:
                if resp.status_code >= 400:
                    st.error(f"API 오류({resp.status_code}): {data}")
                else:
                    st.json(data)

if "fetch_results" not in st.session_state:
    st.session_state["fetch_results"] = []

st.subheader("Fetch & Analyze Emails")
max_results = st.number_input("Max emails to analyze", min_value=1, max_value=50, value=5, step=1)
if st.button("Fetch & Analyze Emails"):
    with st.spinner("Gmail에서 메일을 수집하고 분석 중..."):
        try:
            resp = requests.post(
                f"{API_BASE}/api/fetch_and_analyze",
                json={"max_results": int(max_results)},
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as e:
            st.error("API 연결 실패: " + str(e))
        else:
            try:
                data = resp.json()
            except ValueError:
                st.error("API 응답을 JSON으로 파싱하지 못했습니다.")
            else:
                if resp.status_code >= 400:
                    st.error(f"API 오류({resp.status_code}): {data}")
                else:
                    st.session_state["fetch_results"] = data.get("results", [])
                    st.success(f"{len(st.session_state['fetch_results'])}건의 이메일을 분석했습니다.")

if st.session_state["fetch_results"]:
    result_df = pd.DataFrame(st.session_state["fetch_results"])
    if not result_df.empty:
        result_df = result_df.sort_values(by="confidence", ascending=False)
        # build summary view for dashboard
        def format_gmail_labels(labels):
            if isinstance(labels, list):
                return ", ".join(labels)
            return labels or ""

        def get_column(df: pd.DataFrame, name: str, default):
            return df[name] if name in df else pd.Series([default] * len(df))

        summary_base = result_df.copy()
        summary_base["confidence_pct"] = (get_column(summary_base, "confidence", 0).fillna(0) * 100).round(2)
        summary_base["gmail_labels"] = get_column(summary_base, "gmail_labels", "").apply(format_gmail_labels)
        df_summary = summary_base.reindex(
            columns=["subject", "label", "confidence_pct", "attachments", "gmail_labels", "latency_ms"]
        )

        st.subheader("Email Analysis (Summary View)")
        st.dataframe(df_summary, use_container_width=True)

        if st.checkbox("Show raw analysis data"):
            st.dataframe(result_df, use_container_width=True)
