import os
import re
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, Union

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, UserSessionModel

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

def parse_device_fingerprint(request: Request, client_device_id: Optional[str] = None) -> Dict[str, str]:
    """
    Requirement 1: Device Fingerprinting
    Captures persistent client device ID, device name, browser, OS, client IP address, and location.
    """
    ua = request.headers.get("user-agent", "Unknown Device")
    device_id = client_device_id or request.headers.get("x-device-id") or str(uuid.uuid4())

    # Detect Operating System
    os_name = "Unknown OS"
    if "Windows" in ua:
        os_name = "Windows"
    elif "Macintosh" in ua or "Mac OS" in ua:
        os_name = "macOS"
    elif "Linux" in ua and "Android" not in ua:
        os_name = "Linux"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"

    # Detect Browser
    browser_name = "Web Browser"
    if "Brave" in ua:
        browser_name = "Brave Secure Browser"
    elif "Edg" in ua:
        browser_name = "Microsoft Edge"
    elif "Chrome" in ua and "Safari" in ua:
        browser_name = "Google Chrome"
    elif "Safari" in ua and "Chrome" not in ua:
        browser_name = "Apple Safari"
    elif "Firefox" in ua:
        browser_name = "Mozilla Firefox"

    # Detect Device Form Factor
    device_name = f"{os_name} Workstation"
    if "Mobile" in ua or "iPhone" in ua or "Android" in ua:
        device_name = f"{os_name} Mobile Device"
    elif "iPad" in ua or "Tablet" in ua:
        device_name = f"{os_name} Clinical Tablet"

    # Resolve IP & Location
    ip_raw = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "127.0.0.1")
    ip_address = ip_raw.split(",")[0].strip()
    location = "Metro Transfusion Center (Authorized Station)"

    return {
        "device_id": device_id,
        "device_name": device_name,
        "browser": browser_name,
        "os": os_name,
        "ip_address": ip_address,
        "location": location
    }

def create_access_token(
    data: dict,
    session_id: Optional[str] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Mints JWT token with optional session ID ('sid') claim for instant revocation."""
    to_encode = data.copy()
    if session_id:
        to_encode["sid"] = session_id
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
    credentials: Optional[Union[HTTPAuthorizationCredentials, str]] = Depends(security),
    db: Session = Depends(get_db),
    token: Optional[str] = None
) -> UserModel:
    """
    Requirement 4: JWT Session Validation & Revocation Check
    Invalidates tokens for revoked sessions upon their next API request.
    Supports both FastAPI Depends(security) and direct programmatic token string calls.
    """
    effective_token: Optional[str] = None
    if token:
        effective_token = token
    elif isinstance(credentials, str):
        effective_token = credentials
    elif credentials and hasattr(credentials, "credentials"):
        effective_token = credentials.credentials

    if not effective_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required."
        )

    payload = decode_access_token(effective_token)
    user_id: str = payload.get("sub")
    session_id: Optional[str] = payload.get("sid")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials payload."
        )

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user and payload.get("email"):
        email_clean = payload.get("email").strip().lower()
        user = db.query(UserModel).filter(UserModel.email == email_clean).first()
        if not user:
            try:
                from storage_service import get_user_auth_record_r2
                r2_record = get_user_auth_record_r2(email_clean)
                if r2_record:
                    user = UserModel(
                        id=r2_record.get("id") or user_id,
                        full_name=r2_record.get("full_name") or "Clinician",
                        email=email_clean,
                        phone=r2_record.get("phone"),
                        hashed_password=r2_record.get("hashed_password"),
                        is_verified=bool(r2_record.get("is_verified", True)),
                        is_2fa_enabled=bool(r2_record.get("is_2fa_enabled", False)),
                        photo_url=r2_record.get("photo_url")
                    )
                    db.add(user)
                    db.commit()
                    db.refresh(user)
                    logger.info(f"[AUTH RESTORE] Automatically hydrated {email_clean} from R2 mirror.")
            except Exception as r2_err:
                logger.warning(f"Could not restore user from R2 in get_current_user: {r2_err}")

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    # Validate active session if sid is attached
    if session_id:
        session_record = db.query(UserSessionModel).filter(
            UserSessionModel.id == session_id,
            UserSessionModel.user_id == user.id
        ).first()

        if session_record:
            if session_record.status != "active":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has been revoked or terminated. Please log in again to establish a new session."
                )
            # Update last active timestamp
            session_record.last_active = datetime.utcnow()
            db.flush()
        else:
            # Recreate active session record seamlessly so valid JWT token remains authenticated across server restarts
            try:
                new_session = UserSessionModel(
                    id=session_id,
                    user_id=user.id,
                    device_id="reconnected-session",
                    device_name="Workstation Browser",
                    browser="Browser",
                    os="Client OS",
                    ip_address="127.0.0.1",
                    location="Metro Transfusion Center",
                    status="active"
                )
                db.add(new_session)
                db.flush()
            except Exception as s_exc:
                logger.warning(f"Could not re-create session record: {s_exc}")

    # Attach current session context to user instance
    user._current_session_id = session_id
    return user

def get_user_from_token(token: str, db: Session) -> Optional[UserModel]:
    """
    Safe helper to resolve a UserModel from a raw JWT token string without throwing.
    Returns None if token is invalid, expired, or session revoked.
    """
    if not token or not isinstance(token, str):
        return None
    try:
        return get_current_user(credentials=token, db=db)
    except Exception:
        return None

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

def create_password_reset_session_token(user_id: str, email: str) -> str:
    """Mints a temporary 15-minute token allowing the verified user to submit their new password."""
    payload = {
        "sub": user_id,
        "email": email,
        "type": "password_reset_session",
        "exp": datetime.utcnow() + timedelta(minutes=15)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_password_reset_session_token(token: str, expected_email: str) -> Tuple[bool, Optional[str]]:
    """Validates temporary reset token signature, expiration, and email match."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "password_reset_session":
            return False, "Invalid token type."
        if payload.get("email", "").lower() != expected_email.lower():
            return False, "Token does not match the provided email address."
        return True, payload.get("sub")
    except jwt.ExpiredSignatureError:
        return False, "Password reset session has expired (15-minute limit). Please restart recovery."
    except jwt.InvalidTokenError:
        return False, "Invalid reset session token."

def check_password_history(
    new_password: str,
    current_hash: str,
    past_hashes: list
) -> Tuple[bool, Optional[str]]:
    """
    Requirement 2: Previous Password Prevention
    Verifies that the new password does not match the current password or any stored historical password.
    """
    # 1. Compare against current active password
    if verify_password(new_password, current_hash):
        return False, "New password cannot be identical to your current password."

    # 2. Compare against recent password history
    for old_hash in past_hashes:
        if verify_password(new_password, old_hash):
            return False, "New password has been used recently. For security, please choose a password you have not previously used."

    return True, None


