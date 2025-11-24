import os
import json
from datetime import datetime
import pandas as pd
import streamlit as st
import altair as alt
import requests

# PowerShell ?덉떆 (??以? - <TOKEN>??諛쒓툒諛쏆? ?좏겙?쇰줈 援먯껜?섏꽭??
# curl.exe -X POST "http://127.0.0.1:8080/api/analyze" -H "Content-Type: application/json" -H "X-API-Key: <TOKEN>" -d "{\"title\":\"Invoice overdue\",\"body\":\"Click here to pay now: http://phish.example\"}"
# $token = "<TOKEN>"
# Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/api/analyze" -Headers @{ "X-API-Key" = $token } -Body (@{title="Invoice overdue"; body="Click here to pay now: http://phish.example"} | ConvertTo-Json) -ContentType "application/json"

API_BASE = os.getenv("PHISH_API_URL", "http://localhost:8080")

st.set_page_config(page_title="PhishGuard Dashboard", layout="wide")
st.title("PhishGuard Operations Dashboard")

env_token = os.getenv("PHISH_API_TOKEN", "").strip()
ui_token = st.text_input("API token (optional) ??paste here to use for this session", value="")
API_TOKEN = ui_token.strip() or env_token  # UI ?낅젰???곗꽑 ?곸슜?섍퀬, ?놁쑝硫??섍꼍蹂???ъ슜
headers = {"X-API-Key": API_TOKEN} if API_TOKEN else {}
if not API_TOKEN:
    st.warning("API ?좏겙???ㅼ젙?섏뼱 ?덉? ?딆뒿?덈떎. billing ?쒕퉬?ㅼ뿉???좏겙??諛쒓툒諛쏆븘 ???낅젰???遺숈뿬?ｌ쑝?몄슂.")

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
        st.error(f"API ?ㅻ쪟: {e} (?곹깭 {status})")
    except requests.RequestException as e:
        st.error("API ?곌껐 ?ㅽ뙣: " + str(e))
    except ValueError:
        st.error("API ?묐떟??JSON?쇰줈 ?뚯떛?섏? 紐삵뻽?듬땲??")
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
if not trend_data:
    trend_data = [
        {"month": "2024-08-01", "phishing": 42},
        {"month": "2024-09-01", "phishing": 57},
        {"month": "2024-10-01", "phishing": 63},
    ]
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
st.altair_chart(trend_chart, use_container_width=True)

st.subheader("Upload Suspicious Email")
uploaded = st.file_uploader("Drop .eml/.txt files", type=["txt", "eml"])
subject = st.text_input("Subject override (optional)")
if uploaded:
    email_body = uploaded.read().decode(errors="ignore")
    payload = {"title": subject, "body": email_body}
    with st.spinner("Analyzing..."):
        try:
            resp = requests.post(f"{API_BASE}/api/analyze", json=payload, headers=headers, timeout=15)
        except requests.RequestException as e:
            st.error("API ?곌껐 ?ㅽ뙣: " + str(e))
        else:
            try:
                data = resp.json()
            except ValueError:
                st.error("API ?묐떟??JSON?쇰줈 ?뚯떛?섏? 紐삵뻽?듬땲??")
            else:
                if resp.status_code >= 400:
                    if data.get("error") == "missing_token":
                        st.error("API ?좏겙???꾩슂?⑸땲?? billing ?쒕퉬?ㅼ뿉??諛쒓툒諛쏆? ?좏겙???낅젰?섍굅???섍꼍蹂?섎? ?ㅼ젙?섏꽭??")
                    elif data.get("error") == "limit":
                        st.error("臾대즺 ?몄텧 ?쒕룄瑜?珥덇낵?덉뒿?덈떎. ?붽툑?쒕? ?낃렇?덉씠?쒗븯?몄슂.")
                    else:
                        st.error(f"API ?ㅻ쪟({resp.status_code}): {data}")
                else:
                    st.json(data)
if "fetch_results" not in st.session_state:
    st.session_state["fetch_results"] = []

st.subheader("Fetch & Analyze Emails")
max_results = st.number_input("Max emails to analyze", min_value=1, max_value=50, value=5, step=1)
if st.button("Fetch & Analyze Emails"):
    if not API_TOKEN:
        st.error("API 토큰이 필요합니다. billing 서비스에서 발급받은 토큰을 입력하거나 환경변수를 설정하세요.")
    else:
        with st.spinner("Gmail에서 메일을 가져오는 중..."):
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
                        st.success(f"{len(st.session_state['fetch_results'])}건의 메일을 분석했습니다.")

if st.session_state["fetch_results"]:
    result_df = pd.DataFrame(st.session_state["fetch_results"])
    if not result_df.empty:
        result_df = result_df.sort_values(by="confidence", ascending=False)
        st.dataframe(result_df, use_container_width=True)
