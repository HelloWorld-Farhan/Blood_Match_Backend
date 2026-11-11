import os
import re
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel

JWT_SECRET = os.getenv("JWT_SECRET", "bloodmatch-clinical-security-key-2026")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1440)) # 24 hours

security = HTTPBearer(auto_error=False)

def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Enforces enterprise password requirements:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 numeric digit
    - At least 1 special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one numeric digit (0-9)."
    if not re.search(r"[\W_]", password):
        return False, "Password must contain at least one special character (!@#$%^&* etc)."
    return True, None

def hash_password(password: str) -> str:
    """Hashes a password using bcrypt with salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def generate_cryptographic_otp() -> str:
    """Generates a cryptographically secure 6-digit numeric OTP."""
    return f"{secrets.randbelow(1000000):06d}"

def calculate_otp_expiry() -> datetime:
    """Returns expiration time set to 10 minutes from current UTC time."""
    return datetime.utcnow() + timedelta(minutes=10)

def calculate_cooldown_remaining(last_created_at: datetime) -> int:
    """
    Evaluates 30-second cooldown rate limit.
    Returns remaining seconds if within 30-second cooldown, or 0 if cooldown elapsed.
    """
    elapsed = (datetime.utcnow() - last_created_at).total_seconds()
    if elapsed < 30.0:
        return int(30 - elapsed) + 1
    return 0

def calculate_login_cooldown_remaining(last_failed_login: Optional[datetime], cooldown_seconds: int = 5) -> int:
    """
    Requirement 4: Enforce an incremental delay (5 seconds) between password submissions
    to prevent high-frequency automated brute-force scripts.
    """
    if not last_failed_login:
        return 0
    elapsed = (datetime.utcnow() - last_failed_login).total_seconds()
    if elapsed < float(cooldown_seconds):
        return int(cooldown_seconds - elapsed) + 1
    return 0

def calculate_lockout_duration() -> datetime:
    """Requirement 2: Lock account for 1 year upon 3 consecutive failed attempts."""
    return datetime.utcnow() + timedelta(days=365)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token."
        )

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> UserModel:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required."
        )
    payload = decode_access_token(credentials.credentials)
    user_id: str = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials payload."
        )
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )
    return user

def get_current_verified_user(
    current_user: UserModel = Depends(get_current_user)
) -> UserModel:
    """
    Activation Boundary:
    Strictly verifies that the clinician's email has completed 6-digit OTP verification.
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account unverified. Please verify your 6-digit email OTP to activate full clinical access."
        )
    return current_user

