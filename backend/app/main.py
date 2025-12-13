from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app import models  # noqa: F401 ensures models are registered with Base metadata
from backend.app.api import auth, emails, analysis
from backend.app.config import get_settings
from backend.app.db.session import Base, SessionLocal, engine
from backend.app.security.session import clean_expired_sessions, clean_expired_states

settings = get_settings()
app = FastAPI(title="PhishGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(emails.router, prefix="/api", tags=["emails"])
app.include_router(analysis.router, prefix="/api", tags=["analysis"])


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        clean_expired_states(db)
        clean_expired_sessions(db)
    finally:
        db.close()
