from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.entities import User
from app.services.auth_service import (
    AuthService,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    get_current_user,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="user")  # 'user' or 'admin'


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    if payload.role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'.")

    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Username or email already registered.")

    user = User(
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        password_hash=AuthService.hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    AuditService.log_event(
        db=db,
        action="USER_REGISTER",
        status="SUCCESS",
        details=f"Registered new user '{user.username}' with system role '{user.role}'.",
        actor_id=user.id,
        actor_username=user.username,
        resource_id=user.id,
    )
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username.strip()).first()
    if not user or not AuthService.verify_password(payload.password, user.password_hash):
        AuditService.log_event(
            db=db,
            action="LOGIN_FAILED",
            status="DENIED",
            details=f"Failed login attempt for username '{payload.username}'.",
            actor_username=payload.username,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    token = AuthService.create_session_token(user.id)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,     # Prevents XSS JavaScript from reading session token
        samesite="lax",    # Mitigates CSRF attacks
        max_age=SESSION_MAX_AGE_SECONDS,
    )

    AuditService.log_event(
        db=db,
        action="LOGIN_SUCCESS",
        status="SUCCESS",
        details=f"User '{user.username}' authenticated successfully.",
        actor_id=user.id,
        actor_username=user.username,
        resource_id=user.id,
    )
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/logout")
def logout(response: Response, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    response.delete_cookie(SESSION_COOKIE_NAME)
    AuditService.log_event(
        db=db,
        action="LOGOUT",
        status="SUCCESS",
        details=f"User '{current_user.username}' logged out.",
        actor_id=current_user.id,
        actor_username=current_user.username,
    )
    return {"message": "Logged out successfully."}


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
    }