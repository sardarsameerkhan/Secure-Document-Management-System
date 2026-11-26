from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from app.core.config import SECRET_KEY
from app.core.database import get_db
from app.models.entities import User

ph = PasswordHasher()  # Uses Argon2id by default
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="sdms-auth-session")
SESSION_COOKIE_NAME = "sdms_session"
SESSION_MAX_AGE_SECONDS = 3600 * 4  # 4-hour session lifetime


class AuthService:
    @staticmethod
    def hash_password(plain_password: str) -> str:
        return ph.hash(plain_password)

    @staticmethod
    def verify_password(plain_password: str, password_hash: str) -> bool:
        try:
            return ph.verify(password_hash, plain_password)
        except VerifyMismatchError:
            return False

    @staticmethod
    def create_session_token(user_id: str) -> str:
        return serializer.dumps({"user_id": user_id})

    @staticmethod
    def decode_session_token(token: str) -> Optional[str]:
        try:
            data = serializer.loads(token, max_age=SESSION_MAX_AGE_SECONDS)
            return data.get("user_id")
        except (BadSignature, SignatureExpired):
            return None


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
        )

    user_id = AuthService.decode_session_token(token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid signature. Please log in again.",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer exists.",
        )
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required for this operation.",
        )
    return current_user
