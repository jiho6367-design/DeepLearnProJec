# DeepLearnProJec

딥러닝 기반 악성코드(피싱) 메일 탐지 및 대응 시스템을 구현하는 프로젝트입니다. Streamlit/Flask 대시보드, 모델 서빙, 메일 가져오기/분석 파이프라인을 통합해 운영 자동화를 목표로 합니다.

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

