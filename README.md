# DeepLearnProJec

딥러닝 기반 악성코드(피싱) 메일 탐지 및 대응 시스템을 구현하는 프로젝트입니다. Streamlit/Flask 대시보드, 모델 서빙, 메일 가져오기/분석 파이프라인을 통합해 운영 자동화를 목표로 합니다.

## 최종 결과물 소개
- **제품 형태**: PhishGuard – Gmail 연동형 피싱 메일 탐지·대응 운영 툴킷으로 Flask API, Streamlit 대시보드, 배치 수집 스크립트를 묶은 일체형 스택입니다.
- **핵심 기능**: `ingestion_workflow.py`가 읽지 않은 메일을 자동 수집하고, SPF/DKIM/DMARC·링크 평판 룰 점수와 HF 분류기, LLM 정책 프롬프트를 앙상블한 `optimized_pipeline.py`로 위험도를 산출합니다.
- **API 제공**: `api_service.py`가 `/api/analyze`, `/api/analyze_selected`, `/api/list_emails`, `/api/history`, `/metrics/summary` 등 REST 엔드포인트로 단건/배치 분석, Gmail 목록 조회, 분석 이력·KPI 조회를 제공합니다.
- **대시보드**: `dashboard.py`에서 API 토큰 기반으로 업로드/선택 메일 분석, Gmail 목록 필터링·재분석, KPI 카드와 추세 차트, 분석 아카이브 검색·리뷰를 UI로 처리합니다.
- **운영 데이터**: 분석 결과와 피드백을 SQLite(`data/phishguard.db`, `data/feedback.db`)에 캐시·저장하고, `eval.py`와 `tools/eval_db.py`로 임계값 스윕 및 회귀 테스트를 수행하는 구조로 납품되었습니다.

## 교수님 피드백 반영 방향
- **메일함 신규 메일 수집 자동화**: Gmail 등 주요 웹메일 API를 통해 주기적으로 신규 메일을 가져오는 기능을 구현합니다.
- **대형 메일 서비스의 악성 메일 탐지 기준 활용**: Gmail 등에서 제시하는 스팸·피싱 판정 규칙과 신뢰 지표를 학습 데이터 전처리/특징으로 반영합니다.
- **AI 모델에 명확한 탐지 기준 제시**: 프롬프트와 분류 모델에 서비스 정책(의심 척도, 신고 기준 등)을 명시하여 일관된 탐지 지시를 내립니다.

## 메일 가져오기 및 처리 과정 (제안된 파이프라인)
1. **웹메일 API 연동**: Gmail API 등 오픈 API를 사용해 신규 메일을 읽어옵니다.
2. **데이터 적재**: 가져온 메일 원문/메타데이터를 파서로 정리해 안전한 변수/스토리지에 저장합니다.
3. **AI 분석 단계**: 정제된 메일 데이터를 악성도 분류 모델과 프롬프트 기반 LLM에 전달하여 탐지 결과를 산출합니다.
4. **응답/알림**: 악성으로 판단되면 대시보드에 표시하고, 사전 정의된 답변/격리 조치를 실행합니다.

## 차별화 및 개발 효율화 아이디어
- **기존 메일 서비스 신호 활용**: Gmail 분류 결과, SPF/DKIM/DMARC 검증 여부, 링크 평판 등 외부 신호를 피처로 결합합니다.
- **AI 툴 적극 활용**: 모델 실험, 프롬프트 버전 관리, 배치/스트리밍 분석 자동화를 통해 개발 시간을 단축합니다.
- **기획 검증**: 탐지 정책과 사용자 응답 플로우를 주기적으로 점검해 기획 적절성을 유지합니다.

## 사용자가 직접 처리해야 하는 작업
- **Gmail API/타 웹메일 자격 증명 발급 및 콘솔 설정**: OAuth 동의 화면, 리프레시 토큰, IMAP/SMTP 권한 등을 직접 구성해야 합니다.
- **API 키/시크릿 관리**: OpenAI 등 외부 모델 키를 `.env`나 비밀 관리 도구에 안전하게 저장하고 배포 파이프라인에 주입해야 합니다.
- **보안 및 개인 정보 준수 검토**: 메일 원문 저장/가공 시 법적·정책적 요구사항을 확인하고 동의/마스킹 절차를 마련해야 합니다.
- **실제 메일 박스 연결 테스트**: 사내/개인 계정으로 엔드투엔드 수집·분석·응답 테스트를 수행해 권한/쿼터 문제를 확인해야 합니다.

## 빠른 실행 가이드
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`, `OPENAI_API_KEY`를 환경 변수로 설정합니다.
- `python ingestion_workflow.py`를 실행하면 읽지 않은 메일을 가져와 SPF/DKIM/DMARC, Gmail 라벨 신호와 함께 분류/피드백을 출력합니다. 기본 정책 문구는 `PHISHING_POLICY` 환경 변수로 교체 가능합니다.

## 평가·라벨링·임계값 운영 가이드
- 샘플 수집: Gmail API로 최근/의심 메일을 CSV(`text` 또는 `subject`/`body`, `label`)로 덤프합니다. 내부 피싱 훈련 메일·스팸함·정상 업무 메일을 균형 있게 포함시킵니다.
- 라벨링 기준: `label`은 `phishing`/`normal`(또는 1/0). 멀웨어 첨부, 브랜드 스푸핑, 계정탈취/결제 요청은 `phishing`; 뉴스레터·시스템 알림 등 정상 서비스 발신은 `normal`.
- 오프라인 평가: `python eval.py samples.csv --sweep` 로 precision/recall/F1과 임계값 스윕을 출력합니다. 네트워크 없이 HuggingFace 캐시 + 룰 기반 점수만 사용합니다(피드백 LLM 호출 없음).
- 임계값 결정: `PHISH_THRESHOLD`(기본 0.30)을 조정합니다. 보수적 운영(오탐 최소) 시 0.5~0.6, 공격 탐지 우선(미탐 최소) 시 0.25~0.35를 권장합니다. 결정 후 동일 샘플셋으로 재측정하여 변화폭을 기록합니다.
- 회귀 테스트: 동일 CSV를 저장소에 보관하고 CI에서 `eval.py`를 돌려 precision/recall/F1이 감소하면 경고하도록 설정합니다.
- DB 기반 평가: `python tools/eval_db.py --db data/phishguard.db --threshold 0.25 --sweep` 로 SQLite에 저장된 예측 결과를 바로 평가합니다. base_prob+rule_score가 있으면 weight 스윕을, gt_label이 없으면 정밀도/재현율 계산을 생략하고 안내합니다. 사람이 라벨링하려면 `python tools/label_review.py --db data/phishguard.db --export --out label_candidates.csv` 로 샘플을 추출해 라벨링 후 `--import_csv` 로 반영하세요.

## .env 배치 경로와 사용법
- **위치**: 리포지토리 루트(`/workspace/DeepLearnProJec/.env`)에 `.env` 파일을 두면 됩니다. (이미 `.gitignore`에 추가되어 있으므로 커밋되지 않습니다.)
- **샘플 파일**: `.env.example`에 실제로 사용 가능한 샘플 값이 포함되어 있으니, `cp .env.example .env` 후 필요 시 값을 교체해 사용하세요.
- **예시 내용**:
  ```env
  GOOGLE_CLIENT_ID=your_google_oauth_client_id
  GOOGLE_CLIENT_SECRET=your_google_oauth_client_secret
  GOOGLE_REFRESH_TOKEN=your_google_refresh_token
  OPENAI_API_KEY=your_openai_key
  OPENAI_MODEL=gpt-4o-mini
  PHISHING_POLICY="회사 정책에 맞춘 피싱 탐지 기준"
  GMAIL_USER=your_gmail_address
  ```
- **적용 방법**: 쉘에서 `set -a; source .env; set +a`로 한번 로드하면 이후 터미널 세션에서 환경 변수가 잡힌 상태로 `python ingestion_workflow.py` 등 명령을 실행할 수 있습니다.
