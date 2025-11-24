from dotenv import load_dotenv
import os
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import traceback


def main():
    print("=== test_gmail.py 시작 ===")

    # .env 로딩
    load_dotenv()
    print("환경변수 로딩 완료")

    CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    REFRESH_TOKEN = os.getenv("GOOGLE_REFRESH_TOKEN")

    print("CLIENT_ID:", "있음" if CLIENT_ID else "없음")
    print("CLIENT_SECRET:", "있음" if CLIENT_SECRET else "없음")
    print("REFRESH_TOKEN:", "있음" if REFRESH_TOKEN else "없음")

    if not all([CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN]):
        print("❌ 환경변수 중 하나 이상이 비어 있습니다. .env 설정을 다시 확인하세요.")
        return

    try:
        creds = Credentials(
            None,
            refresh_token=REFRESH_TOKEN,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        print("Credentials 객체 생성 완료")

        service = build("gmail", "v1", credentials=creds)
        print("Gmail service 생성 완료")

        result = service.users().messages().list(userId="me", maxResults=5).execute()
        messages = result.get("messages", [])

        print(f"📩 가져온 메일 수: {len(messages)}")
        for m in messages:
            print("- message id:", m.get("id"))

        print("=== test_gmail.py 종료 ===")
        profile = service.users().getProfile(userId="me").execute()
        print(profile["emailAddress"])

    except Exception:
        print("❌ 예외 발생:")
        traceback.print_exc()


if __name__ == "__main__":
    main()
