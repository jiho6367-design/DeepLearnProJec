import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from backend.app.db.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    email = Column(String, unique=True, nullable=False)
    google_sub = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    tokens = relationship("OAuthToken", back_populates="user", uselist=False)


class OAuthToken(Base):
    __tablename__ = "oauth_tokens"
    __table_args__ = (UniqueConstraint("user_id", name="uq_token_user"),)

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    refresh_token_enc = Column(Text, nullable=False)
    access_token_enc = Column(Text, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="tokens")


class OAuthState(Base):
    __tablename__ = "oauth_states"

    state = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)


class Session(Base):
    __tablename__ = "sessions"

    session_id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User")


class EmailAnalysis(Base):
    __tablename__ = "email_analysis"
    __table_args__ = (UniqueConstraint("user_id", "message_id", name="uq_analysis_user_message"),)

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    message_id = Column(String, nullable=False)
    subject = Column(String, nullable=True)
    from_addr = Column(String, nullable=True)
    verdict = Column(String, nullable=True)
    score = Column(Numeric(5, 3), nullable=True)
    llm_summary = Column(Text, nullable=True)
    raw_headers = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User")


class UserFeedback(Base):
    __tablename__ = "user_feedback"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    message_id = Column(String, nullable=False)
    label = Column(String, nullable=False)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")
