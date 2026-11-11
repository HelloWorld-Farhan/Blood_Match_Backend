import os
import logging
from datetime import datetime
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from database import init_db, get_db, is_sqlite_fallback
from models import (
    UserModel,
    OtpTokenModel,
    InventoryModel,
    DonorModel,
    EmergencyRequestModel,
    ClinicianProfileModel
)
from schemas import (
    UserRegisterRequest,
    OtpVerifyRequest,
    OtpResendRequest,
    UserLoginRequest,
    AccountUnlockRequest,
    AuthTokenResponse,
    InventoryUpdateRequest,
    DonorCreateRequest,
    EmergencyCreateRequest,
    ClinicianProfileRequest
)
from auth_service import (
    validate_password_strength,
    hash_password,
    verify_password,
    generate_cryptographic_otp,
    calculate_otp_expiry,
    calculate_cooldown_remaining,
    calculate_login_cooldown_remaining,
    calculate_lockout_duration,
    create_access_token,
    get_current_user,
    get_current_verified_user
)
from email_service import send_verification_email, send_lockout_alert_email

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BloodBackend.App")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database schema on startup...")
    init_db()
    logger.info(f"Database readiness verified (Fallback Active: {is_sqlite_fallback}).")
    yield
    logger.info("Application shutting down.")

app = FastAPI(
    title="BloodMatch Backend Service",
    description="Enterprise-grade clinical backend with PostgreSQL/SQLite resilience, brute-force defense, and authenticated verification lifecycle.",
    version="1.2.0",
    lifespan=lifespan
)

PORT = int(os.getenv("PORT", 8000))
CORS_ORIGINS = [orig.strip() for orig in os.getenv("CORS_ORIGINS", "*").split(",") if orig.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# SYSTEM & HEALTH ENDPOINTS
# ==========================================
@app.get("/", tags=["System"])
def read_root():
    return {
        "service": "BloodMatch Backend",
        "status": "online",
        "database_engine": "sqlite_fallback" if is_sqlite_fallback else "postgresql"
    }

@app.get("/health", tags=["System"])
def health_check(db: Session = Depends(get_db)):
    return {
        "status": "healthy",
        "database_connected": True,
        "engine": "sqlite_fallback" if is_sqlite_fallback else "postgresql"
    }

# ==========================================
# ENTERPRISE AUTHENTICATION & OTP LIFECYCLE
# ==========================================

@app.post("/api/auth/register", tags=["Authentication"], status_code=status.HTTP_201_CREATED)
def register_user(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Registers a new user:
    - Enforces password strength (8+ chars, upper, lower, number, special character)
    - Bcrypt hashes the password with salt
    - Sets is_verified = False
    - Generates cryptographically secure 6-digit OTP with 10-minute expiry
    - Renders Jinja2 HTML verification template and dispatches email
    """
    email_clean = payload.email.strip().lower()

    # 1. Enforce Password Policy
    is_valid_pw, pw_error = validate_password_strength(payload.password)
    if not is_valid_pw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=pw_error
        )

    # Check for existing account
    existing_user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please log in or verify your account."
        )

    # 2. Hash Password with Bcrypt + Salt
    hashed_pw = hash_password(payload.password)

    # 3. Create User with is_verified=False (Activation Boundary)
    new_user = UserModel(
        full_name=payload.full_name.strip(),
        email=email_clean,
        phone=payload.phone.strip() if payload.phone else None,
        hashed_password=hashed_pw,
        is_verified=False,
        failed_login_attempts=0
    )
    db.add(new_user)
    db.flush()

    # 4. Generate Cryptographically Secure 6-Digit OTP (10m expiry)
    otp_code = generate_cryptographic_otp()
    otp_record = OtpTokenModel(
        user_id=new_user.id,
        email=email_clean,
        otp_code=otp_code,
        token_type="verification",
        expires_at=calculate_otp_expiry(),
        is_used=False,
        attempts=0
    )
    db.add(otp_record)
    db.flush()

    # 5. Dispatch Jinja2 Rendered Email
    send_verification_email(
        recipient_email=email_clean,
        recipient_name=new_user.full_name,
        otp_code=otp_code
    )

    return {
        "message": "User registered successfully. A 6-digit verification code has been dispatched to your email.",
        "verification_required": True,
        "user": new_user.to_dict()
    }

@app.post("/api/auth/verify-otp", tags=["Authentication"])
def verify_otp(
    payload: OtpVerifyRequest,
    db: Session = Depends(get_db)
):
    """
    Verifies 6-digit numeric OTP token:
    - Checks token expiration (10-minute validity)
    - Validates code match
    - Marks is_verified = True and sets verified_at timestamp
    - Invalidates token (is_used = True)
    - Returns JWT access token upon successful activation
    """
    email_clean = payload.email.strip().lower()
    otp_code_clean = payload.otp_code.strip()

    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    if user.is_verified:
        token = create_access_token({"sub": user.id, "email": user.email})
        return {
            "message": "Account is already verified.",
            "access_token": token,
            "token_type": "bearer",
            "is_verified": True,
            "user": user.to_dict()
        }

    # Fetch latest active OTP record
    otp_record = (
        db.query(OtpTokenModel)
        .filter(
            OtpTokenModel.email == email_clean,
            OtpTokenModel.token_type == "verification",
            OtpTokenModel.is_used == False
        )
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active verification code found for this email address. Please request a new code."
        )

    # Check 10-Minute Expiry
    if datetime.utcnow() > otp_record.expires_at:
        otp_record.is_used = True
        db.flush()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token has expired (10-minute limit). Please request a new verification code."
        )

    # Validate OTP Code
    if otp_record.otp_code != otp_code_clean:
        otp_record.attempts += 1
        db.flush()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Please check your email and enter the correct 6-digit code."
        )

    # Successful Verification & Activation
    otp_record.is_used = True
    user.is_verified = True
    user.verified_at = datetime.utcnow()
    db.flush()

    # Mint JWT Token
    token = create_access_token({"sub": user.id, "email": user.email})

    return {
        "message": "Account email successfully verified. Activation complete.",
        "access_token": token,
        "token_type": "bearer",
        "is_verified": True,
        "user": user.to_dict()
    }

@app.post("/api/auth/resend-otp", tags=["Authentication"])
def resend_otp(
    payload: OtpResendRequest,
    db: Session = Depends(get_db)
):
    """
    Dispatches a new 6-digit OTP code subject to a strict 30-second rate-limiting cooldown.
    """
    email_clean = payload.email.strip().lower()

    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No registered account found with this email."
        )

    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is already verified. You may proceed directly to login."
        )

    # Strict 30-Second Cooldown Check
    last_otp = (
        db.query(OtpTokenModel)
        .filter(OtpTokenModel.email == email_clean, OtpTokenModel.token_type == "verification")
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )

    if last_otp:
        cooldown_remaining = calculate_cooldown_remaining(last_otp.created_at)
        if cooldown_remaining > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Resend cooldown active. Please wait {cooldown_remaining} seconds before requesting a new code."
            )

    # Invalidate previous unused OTP tokens for this email
    db.query(OtpTokenModel).filter(
        OtpTokenModel.email == email_clean,
        OtpTokenModel.token_type == "verification",
        OtpTokenModel.is_used == False
    ).update({"is_used": True})

    # Generate new 6-digit OTP with 10-minute expiry
    new_otp = generate_cryptographic_otp()
    otp_record = OtpTokenModel(
        user_id=user.id,
        email=email_clean,
        otp_code=new_otp,
        token_type="verification",
        expires_at=calculate_otp_expiry(),
        is_used=False,
        attempts=0
    )
    db.add(otp_record)
    db.flush()

    # Dispatch Jinja2 Email
    send_verification_email(
        recipient_email=email_clean,
        recipient_name=user.full_name,
        otp_code=new_otp
    )

    return {
        "message": "A new 6-digit verification code has been dispatched to your email.",
        "cooldown_seconds": 30
    }

# ==========================================
# SECURE LOGIN & BRUTE-FORCE LOCKOUT
# ==========================================

@app.post("/api/auth/login", tags=["Authentication"])
def login_user(
    payload: UserLoginRequest,
    db: Session = Depends(get_db)
):
    """
    Secure login with brute-force defense:
    1. Checks if account is locked (locked_until > now) -> Returns HTTP 423
    2. Enforces 5-second cooldown between password submissions -> Returns HTTP 429
    3. Verifies credentials with bcrypt
    4. On failed attempt:
       - 1st & 2nd attempt: Returns HTTP 401 with remaining attempts warning
       - 3rd attempt: Locks account for 1 year, resets counter, dispatches emergency 6-digit unlock code via email, returns HTTP 423
    5. On success: Clears failed attempts & locked status, issues JWT token
    """
    email_clean = payload.email.strip().lower()
    user = db.query(UserModel).filter(UserModel.email == email_clean).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email address or password."
        )

    # Requirement 2: Check if account is locked
    now = datetime.utcnow()
    if user.locked_until and user.locked_until > now:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is locked due to multiple failed login attempts. Please submit your 6-digit emergency unlock code to unlock your account."
        )

    # Requirement 4: Rate Limiting Cooldown (5 seconds between submissions)
    cooldown_remaining = calculate_login_cooldown_remaining(user.last_failed_login, cooldown_seconds=5)
    if cooldown_remaining > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Brute-force protection: Please wait {cooldown_remaining} seconds before submitting another password attempt."
        )

    # Verify Password with Bcrypt
    if verify_password(payload.password, user.hashed_password):
        # Successful login: reset failed counters and unlock
        user.failed_login_attempts = 0
        user.last_failed_login = None
        user.locked_until = None
        db.flush()

        token = create_access_token({"sub": user.id, "email": user.email})
        return {
            "access_token": token,
            "token_type": "bearer",
            "is_verified": user.is_verified,
            "user": user.to_dict()
        }

    # Failed login: increment failed attempts & timestamp
    user.failed_login_attempts += 1
    user.last_failed_login = now

    # Requirement 2: 3-Attempt Rule
    if user.failed_login_attempts < 3:
        remaining_attempts = 3 - user.failed_login_attempts
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid email address or password. Warning: {remaining_attempts} attempt{'s' if remaining_attempts > 1 else ''} remaining before account lockout."
        )

    # 3rd consecutive failed attempt: Trigger Immediate Lockout & Emergency Code Dispatch
    user.locked_until = calculate_lockout_duration() # Locked for 1 year
    user.failed_login_attempts = 0 # Counter reset

    # Invalidate prior emergency unlock tokens for this user
    db.query(OtpTokenModel).filter(
        OtpTokenModel.email == email_clean,
        OtpTokenModel.token_type == "emergency_unlock",
        OtpTokenModel.is_used == False
    ).update({"is_used": True})

    # Requirement 3: Generate 6-digit emergency unlock code with 10-minute expiry
    unlock_code = generate_cryptographic_otp()
    unlock_record = OtpTokenModel(
        user_id=user.id,
        email=email_clean,
        otp_code=unlock_code,
        token_type="emergency_unlock",
        expires_at=calculate_otp_expiry(),
        is_used=False,
        attempts=0
    )
    db.add(unlock_record)
    db.commit()

    # Dispatch urgent security alert email
    send_lockout_alert_email(
        recipient_email=user.email,
        recipient_name=user.full_name,
        unlock_code=unlock_code
    )

    raise HTTPException(
        status_code=status.HTTP_423_LOCKED,
        detail="Account locked due to 3 consecutive failed login attempts. An emergency 6-digit unlock code has been dispatched to your email (valid for 10 minutes)."
    )

@app.post("/api/auth/unlock-account", tags=["Authentication"])
def unlock_account(
    payload: AccountUnlockRequest,
    db: Session = Depends(get_db)
):
    """
    Emergency account unlock endpoint:
    - Validates 6-digit emergency unlock code
    - Checks 10-minute validity expiry
    - Clears locked_until and resets failed login counters
    """
    email_clean = payload.email.strip().lower()
    unlock_code_clean = payload.unlock_code.strip()

    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    now = datetime.utcnow()
    if not (user.locked_until and user.locked_until > now):
        return {
            "message": "Account is not locked. You may proceed directly to login.",
            "is_locked": False
        }

    # Fetch active emergency unlock token
    unlock_record = (
        db.query(OtpTokenModel)
        .filter(
            OtpTokenModel.email == email_clean,
            OtpTokenModel.token_type == "emergency_unlock",
            OtpTokenModel.is_used == False
        )
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )

    if not unlock_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active emergency unlock code found for this account."
        )

    # Check 10-minute expiry
    if now > unlock_record.expires_at:
        unlock_record.is_used = True
        db.flush()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Emergency unlock code has expired (10-minute limit). Please submit another login attempt to generate a fresh security alert."
        )

    # Verify Code
    if unlock_record.otp_code != unlock_code_clean:
        unlock_record.attempts += 1
        db.flush()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid emergency unlock code. Please check your emergency security alert email."
        )

    # Unlock account & clear lockout state
    unlock_record.is_used = True
    user.locked_until = None
    user.failed_login_attempts = 0
    user.last_failed_login = None
    db.flush()

    return {
        "message": "Account successfully unlocked. Security lockout cleared.",
        "is_locked": False,
        "user": user.to_dict()
    }

@app.get("/api/auth/me", tags=["Authentication"])
def get_current_user_profile(
    verified_user: UserModel = Depends(get_current_verified_user)
):
    """
    Protected Endpoint Boundary:
    Strictly restricted to users who have completed 6-digit OTP email verification (is_verified = True).
    """
    return {
        "status": "authenticated",
        "access_level": "verified_clinician",
        "user": verified_user.to_dict()
    }

# ==========================================
# CLINICAL INVENTORY ENDPOINTS
# ==========================================
@app.get("/api/inventory", tags=["Inventory"])
def list_inventory(db: Session = Depends(get_db)):
    items = db.query(InventoryModel).order_by(InventoryModel.blood_type).all()
    return [item.to_dict() for item in items]

@app.put("/api/inventory/{blood_type}", tags=["Inventory"])
def update_inventory_units(
    blood_type: str,
    payload: InventoryUpdateRequest,
    db: Session = Depends(get_db),
    clinician: UserModel = Depends(get_current_verified_user)
):
    item = db.query(InventoryModel).filter(InventoryModel.blood_type == blood_type.upper()).first()
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Blood inventory group {blood_type} not found."
        )
    if payload.units_available is not None:
        item.units_available = payload.units_available
    if payload.status is not None:
        item.status = payload.status
    if payload.temperature_celsius is not None:
        item.temperature_celsius = payload.temperature_celsius

    db.add(item)
    db.flush()
    return item.to_dict()

# ==========================================
# DONOR ENDPOINTS
# ==========================================
@app.get("/api/donors", tags=["Donors"])
def list_donors(
    blood_type: Optional[str] = Query(None, description="Optional blood group filter"),
    db: Session = Depends(get_db)
):
    query = db.query(DonorModel)
    if blood_type:
        query = query.filter(DonorModel.blood_type == blood_type.upper())
    donors = query.order_by(DonorModel.created_at.desc()).all()
    return [d.to_dict() for d in donors]

@app.post("/api/donors", tags=["Donors"], status_code=status.HTTP_201_CREATED)
def register_donor(
    payload: DonorCreateRequest,
    db: Session = Depends(get_db)
):
    new_donor = DonorModel(
        name=payload.name,
        blood_type=payload.blood_type.upper(),
        phone=payload.phone,
        email=payload.email,
        city=payload.city,
        hospital=payload.hospital,
        last_donation_date=payload.last_donation_date,
        is_available=payload.is_available
    )
    db.add(new_donor)
    db.flush()
    return new_donor.to_dict()

# ==========================================
# EMERGENCY REQUEST ENDPOINTS
# ==========================================
@app.get("/api/emergency", tags=["Emergency"])
def list_emergency_requests(db: Session = Depends(get_db)):
    requests = db.query(EmergencyRequestModel).order_by(EmergencyRequestModel.created_at.desc()).all()
    return [r.to_dict() for r in requests]

@app.post("/api/emergency", tags=["Emergency"], status_code=status.HTTP_201_CREATED)
def create_emergency_request(
    payload: EmergencyCreateRequest,
    db: Session = Depends(get_db)
):
    req = EmergencyRequestModel(
        patient_name=payload.patient_name,
        hospital=payload.hospital,
        blood_type=payload.blood_type.upper(),
        units_needed=payload.units_needed,
        status=payload.status,
        contact_person=payload.contact_person,
        contact_phone=payload.contact_phone
    )
    db.add(req)
    db.flush()
    return req.to_dict()

# ==========================================
# CLINICIAN PROFILE ENDPOINTS
# ==========================================
@app.get("/api/profile", tags=["Profile"])
def get_clinician_profile(
    email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    if not email:
        profile = db.query(ClinicianProfileModel).first()
    else:
        profile = db.query(ClinicianProfileModel).filter(ClinicianProfileModel.work_email == email).first()
    if not profile:
        return {}
    return profile.to_dict()

@app.post("/api/profile", tags=["Profile"])
def upsert_clinician_profile(
    payload: ClinicianProfileRequest,
    db: Session = Depends(get_db)
):
    profile = db.query(ClinicianProfileModel).filter(ClinicianProfileModel.work_email == payload.work_email).first()
    if not profile:
        profile = ClinicianProfileModel(
            full_name=payload.full_name,
            work_email=payload.work_email,
            phone=payload.phone,
            facility=payload.facility,
            department=payload.department,
            license_id=payload.license_id,
            avatar_url=payload.avatar_url
        )
        db.add(profile)
    else:
        profile.full_name = payload.full_name
        profile.phone = payload.phone
        profile.facility = payload.facility
        profile.department = payload.department
        profile.license_id = payload.license_id
        profile.avatar_url = payload.avatar_url
        db.add(profile)
    db.flush()
    return profile.to_dict()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
