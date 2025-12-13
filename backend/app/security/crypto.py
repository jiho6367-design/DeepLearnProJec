import base64
import os
from functools import lru_cache

from cryptography.fernet import Fernet

from backend.app.config import get_settings


def _load_key() -> bytes:
    settings = get_settings()
    key = settings.encryption_key
    if not key:
        key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    if isinstance(key, str):
        key = key.encode()
    return key


@lru_cache()
def get_fernet() -> Fernet:
    return Fernet(_load_key())


def encrypt_token(raw: str) -> str:
    return get_fernet().encrypt(raw.encode()).decode()


def decrypt_token(encoded: str) -> str:
    return get_fernet().decrypt(encoded.encode()).decode()
