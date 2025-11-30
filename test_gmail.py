import os
import traceback

from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


def main():
    print("=== test_gmail.py 시작 ===")

    load_dotenv()
    print("환경변수 로딩 완료")

    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    refresh_token = os.getenv("GOOGLE_REFRESH_TOKEN")

    print("CLIENT_ID:", "있음" if client_id else "없음")
    print("CLIENT_SECRET:", "있음" if client_secret else "없음")
    print("REFRESH_TOKEN:", "있음" if refresh_token else "없음")

    if not all([client_id, client_secret, refresh_token]):
        print("필수 환경변수가 비어 있습니다. .env 설정을 다시 확인하세요.")
        return

    try:
        creds = Credentials(
            None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        print("Credentials 객체 생성 완료")

        service = build("gmail", "v1", credentials=creds)
        print("Gmail service 생성 완료")

        result = service.users().messages().list(userId="me", maxResults=5).execute()
        messages = result.get("messages", [])

        print(f"불러온 메일 수: {len(messages)}")
        for msg in messages:
            print("- message id:", msg.get("id"))

        profile = service.users().getProfile(userId="me").execute()
        print(profile["emailAddress"])
        print("=== test_gmail.py 종료 ===")

    except Exception:
        print("예외 발생:")
        traceback.print_exc()


if __name__ == "__main__":
    main()
