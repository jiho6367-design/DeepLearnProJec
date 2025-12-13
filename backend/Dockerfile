FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

# 1) deps 먼저 설치
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 2) 소스 복사
COPY . /app

# 3) ★중요: 컨테이너 안에 backend 패키지 생성 (기존 코드의 backend.app.* import 호환)
RUN mkdir -p /app/backend && \
    cp -r /app/app /app/backend/app && \
    touch /app/backend/__init__.py

ENV PORT=8080
EXPOSE 8080

# 4) 이제 backend.app.main:app 로 실행 (코드 내부 import와 일치)
CMD ["bash", "-lc", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT}"]
