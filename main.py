import os
import re
import json
import uuid
import base64
import logging
from datetime import datetime
from contextlib import asynccontextmanager
from typing import List, Optional

import boto3
from fastapi import FastAPI, Depends, HTTPException, Query, Request, status, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from database import init_db, get_db, is_sqlite_fallback
from models import (
    UserModel,
    OtpTokenModel,
    PasswordHistoryModel,
    UserSessionModel,
    TrustedDeviceModel,
    InventoryModel,
    DonorModel,
    EmergencyRequestModel,
    ClinicianProfileModel,
    ClinicalCheckModel,
    ClinicalAuditLogModel,
    ClinicalDocumentModel
)
from schemas import (
    UserRegisterRequest,
    OtpVerifyRequest,
    OtpResendRequest,
    UserLoginRequest,
    AccountUnlockRequest,
    TwoFactorVerifyRequest,
    TwoFactorToggleRequest,
    PasswordResetRequest,
    PasswordResetVerifyRequest,
    PasswordResetConfirmRequest,
    AuthTokenResponse,
    InventoryUpdateRequest,
    DonorCreateRequest,
    EmergencyCreateRequest,
    ClinicianProfileRequest,
    ClinicalCheckCreateRequest,
    ClinicalDocumentCreateRequest,
    ClinicalAuditLogCreateRequest
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
    parse_device_fingerprint,
    create_access_token,
    get_current_user,
    get_current_verified_user,
    get_user_from_token,
    decode_access_token,
    create_password_reset_session_token,
    verify_password_reset_session_token,
    check_password_history
)
from email_service import (
    send_verification_email,
    send_lockout_alert_email,
    send_password_reset_email,
    send_password_changed_notification,
    send_2fa_login_email,
    send_welcome_email,
    send_new_login_session_alert
)
from storage_service import (
    process_avatar_image,
    upload_user_asset,
    delete_user_asset,
    list_user_assets,
    validate_tenant_access,
    sanitize_user_email,
    build_scoped_path,
    MAX_FILE_SIZE_BYTES
)

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
CORS_ORIGINS_RAW = os.getenv("CORS_ORIGINS", "").strip()
explicit_origins = [orig.strip() for orig in CORS_ORIGINS_RAW.split(",") if orig.strip()] if CORS_ORIGINS_RAW else []

# Requirement 1: Fallback regex for modern hosting providers (Vercel, Cloudflare Pages/Workers, Netlify, localhost)
ORIGIN_REGEX = r"^https?:\/\/(.*\.vercel\.app|.*\.pages\.dev|.*\.workers\.dev|.*\.netlify\.app|localhost|127\.0\.0\.1)(:\d+)?$"

# Cloudflare R2 Object Storage Configuration (Strictly from Environment Variables)
R2_ENDPOINT = os.getenv("R2_ENDPOINT", "")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "")
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "bloodmatch-storage")
R2_PUBLIC_URL = os.getenv("R2_PUBLIC_URL", "").rstrip("/")

def get_r2_client():
    if not (R2_ENDPOINT and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY):
        return None
    try:
        return boto3.client(
            "s3",
            endpoint_url=R2_ENDPOINT,
            aws_access_key_id=R2_ACCESS_KEY_ID,
            aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            region_name="auto"
        )
    except Exception as exc:
        logger.warning(f"R2 client connection error: {exc}")
        return None

def sync_user_state_to_r2(user_email: str, db: Session) -> Optional[dict]:
    """
    Requirement 2 & 4: Master Sync File Serialization & Deletion Persistence
    Whenever a user creates, updates, or deletes any record (checks, audit logs,
    documents, profile data, emergency requests, donors), automatically serialize the
    user's complete state to users/{user_email}/clinical_sync_data.json in Cloudflare R2.
    """
    if not user_email:
        return None
    email_clean = user_email.strip().lower()
    r2 = get_r2_client()
    if not r2:
        logger.info(f"R2 client not configured; local DB is source of truth for {email_clean}")
        return None

    try:
        user = db.query(UserModel).filter(UserModel.email == email_clean).first()
        profile = db.query(ClinicianProfileModel).filter(ClinicianProfileModel.work_email == email_clean).first()
        checks = db.query(ClinicalCheckModel).filter(ClinicalCheckModel.user_email == email_clean).order_by(ClinicalCheckModel.created_at.desc()).all()
        audit_logs = db.query(ClinicalAuditLogModel).filter(ClinicalAuditLogModel.user_email == email_clean).order_by(ClinicalAuditLogModel.timestamp.desc()).all()
        documents = db.query(ClinicalDocumentModel).filter(ClinicalDocumentModel.user_email == email_clean).order_by(ClinicalDocumentModel.created_at.desc()).all()
        donors = db.query(DonorModel).filter((DonorModel.user_email == email_clean) | (DonorModel.user_email.is_(None))).order_by(DonorModel.created_at.desc()).all()
        emergency_reqs = db.query(EmergencyRequestModel).filter((EmergencyRequestModel.user_email == email_clean) | (EmergencyRequestModel.user_email.is_(None))).order_by(EmergencyRequestModel.created_at.desc()).all()
        inventory = db.query(InventoryModel).order_by(InventoryModel.blood_type).all()

        photo_url = user.photo_url if user else (profile.avatar_url if profile else None)

        sync_key = f"users/{email_clean}/clinical_sync_data.json"
        master_payload = {
            "version": 2,
            "userEmail": email_clean,
            "userId": user.id if user else (profile.id if profile else None),
            "fullName": user.full_name if user else (profile.full_name if profile else "Clinician"),
            "photoUrl": photo_url,
            "profile": profile.to_dict() if profile else {
                "full_name": user.full_name if user else "",
                "work_email": email_clean,
                "phone": user.phone if user else "",
                "facility": "Central Cryo-Vault 01",
                "department": "Hematology & Transfusion",
                "license_id": "MD-CLINICAL",
                "avatar_url": photo_url,
                "updated_at": datetime.utcnow().isoformat()
            },
            "checks": [c.to_dict() for c in checks],
            "auditLogs": [a.to_dict() for a in audit_logs],
            "documents": [d.to_dict() for d in documents],
            "donors": [d.to_dict() for d in donors],
            "emergencyRequests": [r.to_dict() for r in emergency_reqs],
            "inventory": [i.to_dict() for i in inventory],
            "lastSyncedAt": datetime.utcnow().isoformat()
        }

        r2.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=sync_key,
            Body=json.dumps(master_payload, indent=2).encode("utf-8"),
            ContentType="application/json"
        )
        logger.info(f"Disaster-proof cloud master sync file successfully updated in R2: {sync_key}")
        return master_payload
    except Exception as exc:
        logger.error(f"Failed to synchronize master cloud state to R2 for {email_clean}: {exc}")
        return None

def reconcile_user_from_r2(user_email: str, db: Session) -> Optional[dict]:
    """
    Requirement 3: Startup Auto-Reconciliation
    When the client calls the sync pull endpoint, if the local database has 0 records
    for that user, automatically fetch and parse clinical_sync_data.json from Cloudflare R2,
    re-populate the local database tables, and return the complete hydrated data.
    """
    if not user_email:
        return None
    email_clean = user_email.strip().lower()
    r2 = get_r2_client()
    if not r2:
        return None

    try:
        sync_key = f"users/{email_clean}/clinical_sync_data.json"
        obj = r2.get_object(Bucket=R2_BUCKET_NAME, Key=sync_key)
        raw_body = obj["Body"].read().decode("utf-8")
        sync_data = json.loads(raw_body)
    except Exception as exc:
        logger.info(f"No R2 master state found for {email_clean} ({exc})")
        return None

    try:
        # 1. User & Avatar Hydration
        user = db.query(UserModel).filter(UserModel.email == email_clean).first()
        if not user:
            user = UserModel(
                id=sync_data.get("userId") or str(uuid.uuid4()),
                email=email_clean,
                full_name=sync_data.get("fullName") or "Clinician",
                photo_url=sync_data.get("photoUrl"),
                is_verified=True,
                hashed_password=hash_password("HydratedClinical@2026#")
            )
            db.add(user)
        elif sync_data.get("photoUrl") and not user.photo_url:
            user.photo_url = sync_data.get("photoUrl")
            db.add(user)

        # 2. Profile Hydration
        p_data = sync_data.get("profile") or {}
        existing_profile = db.query(ClinicianProfileModel).filter(ClinicianProfileModel.work_email == email_clean).first()
        if not existing_profile and p_data:
            new_profile = ClinicianProfileModel(
                id=p_data.get("id") or str(uuid.uuid4()),
                full_name=p_data.get("full_name") or sync_data.get("fullName") or "Clinician",
                work_email=email_clean,
                phone=p_data.get("phone"),
                facility=p_data.get("facility") or "Central Cryo-Vault 01",
                department=p_data.get("department") or "Hematology & Transfusion",
                license_id=p_data.get("license_id") or "MD-CLINICAL",
                avatar_url=sync_data.get("photoUrl") or p_data.get("avatar_url")
            )
            db.add(new_profile)

        # 3. Clinical Checks Hydration
        for chk in sync_data.get("checks", []):
            chk_id = chk.get("id")
            if not db.query(ClinicalCheckModel).filter(ClinicalCheckModel.id == chk_id).first():
                db.add(ClinicalCheckModel(
                    id=chk_id or str(uuid.uuid4()),
                    user_email=email_clean,
                    patient_name=chk.get("patient_name") or chk.get("patientName") or "Unknown Patient",
                    patient_id=chk.get("patient_id") or chk.get("patientId"),
                    blood_type=chk.get("blood_type") or chk.get("bloodType") or "O+",
                    check_type=chk.get("check_type") or chk.get("checkType") or "compatibility",
                    status=chk.get("status") or "passed",
                    notes=chk.get("notes")
                ))

        # 4. Clinical Audit Logs Hydration
        for log in sync_data.get("auditLogs", []):
            log_id = log.get("id")
            if not db.query(ClinicalAuditLogModel).filter(ClinicalAuditLogModel.id == log_id).first():
                db.add(ClinicalAuditLogModel(
                    id=log_id or str(uuid.uuid4()),
                    user_email=email_clean,
                    action=log.get("action") or "UNKNOWN_ACTION",
                    entity_type=log.get("entity_type") or log.get("entityType") or "clinical",
                    entity_id=log.get("entity_id") or log.get("entityId"),
                    details=log.get("details"),
                    ip_address=log.get("ip_address") or log.get("ipAddress")
                ))

        # 5. Clinical Documents Hydration
        for doc in sync_data.get("documents", []):
            doc_id = doc.get("id")
            if not db.query(ClinicalDocumentModel).filter(ClinicalDocumentModel.id == doc_id).first():
                db.add(ClinicalDocumentModel(
                    id=doc_id or str(uuid.uuid4()),
                    user_email=email_clean,
                    title=doc.get("title") or "Clinical Document",
                    doc_type=doc.get("doc_type") or doc.get("docType") or "lab_report",
                    file_url=doc.get("file_url") or doc.get("fileUrl") or "",
                    file_size_kb=float(doc.get("file_size_kb") or doc.get("fileSizeKb") or 0.0)
                ))

        # 6. Donors Hydration
        for donor in sync_data.get("donors", []):
            d_id = donor.get("id")
            if not db.query(DonorModel).filter(DonorModel.id == d_id).first():
                db.add(DonorModel(
                    id=d_id or str(uuid.uuid4()),
                    user_email=email_clean,
                    name=donor.get("name") or donor.get("fullName") or "Anonymous Donor",
                    blood_type=donor.get("blood_type") or donor.get("bloodType") or "O+",
                    phone=donor.get("phone") or "+1 555-0100",
                    email=donor.get("email") or "donor@bloodmatch.io",
                    city=donor.get("city") or "Metro City",
                    hospital=donor.get("hospital") or "Metro Central Hospital",
                    last_donation_date=donor.get("last_donation_date") or donor.get("lastDonationDate"),
                    is_available=bool(donor.get("is_available") if donor.get("is_available") is not None else donor.get("available", True))
                ))

        # 7. Emergency Requests Hydration
        for req in sync_data.get("emergencyRequests", []):
            r_id = req.get("id")
            if not db.query(EmergencyRequestModel).filter(EmergencyRequestModel.id == r_id).first():
                db.add(EmergencyRequestModel(
                    id=r_id or str(uuid.uuid4()),
                    user_email=email_clean,
                    patient_name=req.get("patient_name") or req.get("patientName") or "Urgent Patient",
                    hospital=req.get("hospital") or "Metro Trauma Wing",
                    blood_type=req.get("blood_type") or req.get("bloodType") or "O-",
                    units_needed=int(req.get("units_needed") or req.get("unitsNeeded") or 1),
                    status=req.get("status") or "urgent",
                    contact_person=req.get("contact_person") or req.get("contactName") or "Attending Nurse",
                    contact_phone=req.get("contact_phone") or req.get("contactNumber") or "+1 555-0199"
                ))

        db.commit()
        logger.info(f"Database successfully re-hydrated from Cloudflare R2 for {email_clean}")
        return sync_data
    except Exception as exc:
        db.rollback()
        logger.error(f"Error during R2 database re-population for {email_clean}: {exc}")
        return None

app.add_middleware(
    CORSMiddleware,
    allow_origins=explicit_origins,
    allow_origin_regex=ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Helper function to append CORS headers to every response
def add_cors_headers(response: JSONResponse, request: Request) -> JSONResponse:
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, Origin, X-Requested-With, Cache-Control"
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"
    return response

# Requirement 2: Global Exception Handler preserving CORS headers on uncaught 500 errors
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    response = JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "code": 500,
            "detail": "An unexpected server error occurred. Please try again shortly.",
            "path": request.url.path
        }
    )
    return add_cors_headers(response, request)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    response = JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )
    return add_cors_headers(response, request)

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
        if existing_user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists. Please log in or reset your password."
            )
        else:
            # User previously attempted registration but is pending verification.
            # Seamlessly refresh their registration, issue a fresh OTP, and dispatch immediately!
            existing_user.full_name = payload.full_name.strip()
            if payload.phone:
                existing_user.phone = payload.phone.strip()
            existing_user.hashed_password = hash_password(payload.password)
            db.flush()

            # Invalidate older pending OTP tokens
            db.query(OtpTokenModel).filter(
                OtpTokenModel.email == email_clean,
                OtpTokenModel.token_type == "verification",
                OtpTokenModel.is_used == False
            ).update({"is_used": True})

            otp_code = generate_cryptographic_otp()
            otp_record = OtpTokenModel(
                user_id=existing_user.id,
                email=email_clean,
                otp_code=otp_code,
                token_type="verification",
                expires_at=calculate_otp_expiry(),
                is_used=False,
                attempts=0
            )
            db.add(otp_record)
            db.commit()

            send_verification_email(
                recipient_email=email_clean,
                recipient_name=existing_user.full_name,
                otp_code=otp_code
            )

            return {
                "message": "A fresh 6-digit verification code has been dispatched to your email.",
                "verification_required": True,
                "user": existing_user.to_dict()
            }

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

    # 6. Initialize Cloudflare R2 user folder structure: users/{email}/
    try:
        from storage_service import initialize_user_storage
        initialize_user_storage(email_clean, new_user.full_name)
    except Exception as exc:
        logger.warning(f"Could not initialize R2 storage for {email_clean}: {exc}")

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

    # Dispatch Welcome & Profile Activation Email (Minimal & Button-Free)
    try:
        send_welcome_email(user.email, user.full_name)
    except Exception as exc:
        logger.warning(f"Welcome email dispatch failed: {exc}")

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
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Secure login with brute-force defense and multi-device session registry:
    1. Checks if account is locked (locked_until > now) -> Returns HTTP 423
    2. Enforces 5-second cooldown between password submissions -> Returns HTTP 429
    3. Verifies credentials with bcrypt
    4. On failed attempt:
       - 1st & 2nd attempt: Returns HTTP 401 with remaining attempts warning
       - 3rd attempt: Locks account for 1 year, resets counter, dispatches emergency 6-digit unlock code via email, returns HTTP 423
    5. On success: Clears failed attempts, registers device session in user_sessions, mints JWT token with sid claim
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
        # Successful password verification: reset failed counters and unlock
        user.failed_login_attempts = 0
        user.last_failed_login = None
        user.locked_until = None
        db.flush()

        # Parse Device Fingerprint
        fp = parse_device_fingerprint(request, client_device_id=payload.device_id)

        # Requirement 2: Check if current device fingerprint is recognized/trusted
        trusted_device = db.query(TrustedDeviceModel).filter(
            TrustedDeviceModel.user_id == user.id,
            TrustedDeviceModel.device_id == fp["device_id"]
        ).first()

        if trusted_device:
            trusted_device.last_used_at = datetime.utcnow()
            db.flush()

        # Requirement 2: Adaptive Step-Up Auth Rule
        # If 2FA is enabled OR if the current device is unrecognized, require a 6-digit email OTP
        requires_step_up = user.is_2fa_enabled or (trusted_device is None)

        if requires_step_up:
            # Invalidate prior unused 2FA tokens for this email
            db.query(OtpTokenModel).filter(
                OtpTokenModel.email == email_clean,
                OtpTokenModel.token_type == "2fa_login",
                OtpTokenModel.is_used == False
            ).update({"is_used": True})

            otp_2fa = generate_cryptographic_otp()
            otp_record = OtpTokenModel(
                user_id=user.id,
                email=user.email,
                otp_code=otp_2fa,
                token_type="2fa_login",
                expires_at=calculate_otp_expiry(),
                is_used=False,
                attempts=0
            )
            db.add(otp_record)
            db.commit()

            send_2fa_login_email(
                recipient_email=user.email,
                recipient_name=user.full_name,
                otp_code=otp_2fa,
                device_name=fp["device_name"],
                ip_address=fp["ip_address"]
            )

            return {
                "two_factor_required": True,
                "message": "Two-factor authentication required. A 6-digit security code has been sent to your email.",
                "email": user.email,
                "device_id": fp["device_id"],
                "remember_device": payload.remember_device
            }

        # Device is recognized and user.is_2fa_enabled is False -> Issue JWT directly
        session_record = UserSessionModel(
            user_id=user.id,
            device_id=fp["device_id"],
            device_name=fp["device_name"],
            browser=fp["browser"],
            os=fp["os"],
            ip_address=fp["ip_address"],
            location=fp["location"],
            status="active"
        )
        db.add(session_record)
        db.flush()

        token = create_access_token(
            {"sub": user.id, "email": user.email},
            session_id=session_record.id
        )
        db.commit()

        # Security advisory for new workstation session
        try:
            send_new_login_session_alert(
                recipient_email=user.email,
                recipient_name=user.full_name,
                device_name=fp["device_name"],
                ip_address=fp["ip_address"],
                location=fp["location"],
                timestamp=now.strftime("%Y-%m-%d %H:%M:%S UTC")
            )
        except Exception as alert_err:
            logger.warning(f"Could not dispatch new session alert email: {alert_err}")

        return {
            "access_token": token,
            "token_type": "bearer",
            "session_id": session_record.id,
            "device_id": fp["device_id"],
            "two_factor_required": False,
            "device_trusted": True,
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

# ==========================================
# ADAPTIVE 2FA & TRUSTED DEVICE MANAGEMENT
# ==========================================

@app.post("/api/auth/2fa/verify", tags=["Two-Factor Authentication"])
def verify_2fa_login(
    payload: TwoFactorVerifyRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Requirement 2: Adaptive Step-Up Auth Verification
    - Validates 6-digit email 2FA OTP code
    - If user selected "Remember This Device", whitelists device ID in trusted_devices (max 20 capacity LRU)
    - Registers session in user_sessions
    - Mints and returns JWT access token with sid claim
    """
    email_clean = payload.email.strip().lower()
    otp_code_clean = payload.otp_code.strip()

    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    # Fetch active 2fa_login token
    token_record = (
        db.query(OtpTokenModel)
        .filter(
            OtpTokenModel.email == email_clean,
            OtpTokenModel.token_type == "2fa_login",
            OtpTokenModel.is_used == False
        )
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active two-factor verification code found. Please log in again."
        )

    now = datetime.utcnow()
    if now > token_record.expires_at:
        token_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor verification code has expired (10-minute limit). Please log in again to generate a new code."
        )

    if token_record.otp_code != otp_code_clean:
        token_record.attempts += 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid two-factor verification code. Please check your email."
        )

    # Invalidate used OTP
    token_record.is_used = True

    # Parse Device Fingerprint
    fp = parse_device_fingerprint(request, client_device_id=payload.device_id)

    # Requirement 1: If "Remember This Device" is checked, whitelist device (up to 20 devices LRU)
    if payload.remember_device:
        existing_trusted = db.query(TrustedDeviceModel).filter(
            TrustedDeviceModel.user_id == user.id,
            TrustedDeviceModel.device_id == fp["device_id"]
        ).first()

        if existing_trusted:
            existing_trusted.last_used_at = now
        else:
            # Check 20-device capacity cap
            trusted_count = db.query(TrustedDeviceModel).filter(TrustedDeviceModel.user_id == user.id).count()
            if trusted_count >= 20:
                # Evict oldest by last_used_at
                oldest_device = (
                    db.query(TrustedDeviceModel)
                    .filter(TrustedDeviceModel.user_id == user.id)
                    .order_by(TrustedDeviceModel.last_used_at.asc())
                    .first()
                )
                if oldest_device:
                    db.delete(oldest_device)
                    db.flush()

            new_trusted = TrustedDeviceModel(
                user_id=user.id,
                device_id=fp["device_id"],
                device_name=fp["device_name"],
                browser=fp["browser"],
                os=fp["os"],
                ip_address=fp["ip_address"],
                trusted_at=now,
                last_used_at=now
            )
            db.add(new_trusted)

    # Register active session in user_sessions
    session_record = UserSessionModel(
        user_id=user.id,
        device_id=fp["device_id"],
        device_name=fp["device_name"],
        browser=fp["browser"],
        os=fp["os"],
        ip_address=fp["ip_address"],
        location=fp["location"],
        status="active"
    )
    db.add(session_record)
    db.flush()

    # Mint JWT access token
    token = create_access_token(
        {"sub": user.id, "email": user.email},
        session_id=session_record.id
    )
    db.commit()

    # Security advisory for step-up authorized session
    try:
        send_new_login_session_alert(
            recipient_email=user.email,
            recipient_name=user.full_name,
            device_name=fp["device_name"],
            ip_address=fp["ip_address"],
            location=fp["location"],
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        )
    except Exception as alert_err:
        logger.warning(f"Could not dispatch 2FA session alert email: {alert_err}")

    return {
        "message": "Two-factor authentication verified successfully.",
        "access_token": token,
        "token_type": "bearer",
        "session_id": session_record.id,
        "device_id": fp["device_id"],
        "device_trusted": payload.remember_device,
        "is_verified": user.is_verified,
        "user": user.to_dict()
    }

@app.put("/api/auth/2fa/toggle", tags=["Two-Factor Authentication"])
def toggle_2fa(
    payload: TwoFactorToggleRequest,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 3: 2FA Management
    Allows user to enable or disable 2FA with password re-authentication.
    """
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security verification failed: Incorrect password."
        )

    current_user.is_2fa_enabled = payload.enable_2fa
    db.commit()

    return {
        "message": f"Two-factor authentication has been successfully {'enabled' if payload.enable_2fa else 'disabled'}.",
        "is_2fa_enabled": current_user.is_2fa_enabled
    }

@app.get("/api/auth/trusted-devices", tags=["Two-Factor Authentication"])
def list_trusted_devices(
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists all remembered/trusted devices for the authenticated user."""
    devices = (
        db.query(TrustedDeviceModel)
        .filter(TrustedDeviceModel.user_id == current_user.id)
        .order_by(TrustedDeviceModel.last_used_at.desc())
        .all()
    )
    return [d.to_dict() for d in devices]

@app.delete("/api/auth/trusted-devices/{device_id}", tags=["Two-Factor Authentication"])
def remove_trusted_device(
    device_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Removes a device from the trusted whitelist."""
    device = (
        db.query(TrustedDeviceModel)
        .filter(
            TrustedDeviceModel.device_id == device_id,
            TrustedDeviceModel.user_id == current_user.id
        )
        .first()
    )
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Trusted device not found."
        )

    db.delete(device)
    db.commit()
    return {
        "message": f"Device {device.device_name} has been removed from your trusted whitelist.",
        "device_id": device_id
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
# MULTI-STEP PASSWORD RESET WORKFLOW
# ==========================================

@app.post("/api/auth/password-reset/request", tags=["Password Reset"])
def request_password_reset(
    payload: PasswordResetRequest,
    db: Session = Depends(get_db)
):
    """
    Step 1: Request Password Reset
    - Submits email address
    - Enforces 30-second resend cooldown on reset tokens
    - Generates 6-digit cryptographic OTP (valid for 10 minutes)
    - Dispatches password reset email
    """
    email_clean = payload.email.strip().lower()
    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account registered with this email address."
        )

    # Enforce 30-second cooldown rate limit
    last_reset_otp = (
        db.query(OtpTokenModel)
        .filter(OtpTokenModel.email == email_clean, OtpTokenModel.token_type == "password_reset")
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )
    if last_reset_otp:
        cooldown_remaining = calculate_cooldown_remaining(last_reset_otp.created_at)
        if cooldown_remaining > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Reset cooldown active. Please wait {cooldown_remaining} seconds before requesting a new code."
            )

    # Invalidate previous unused reset OTPs
    db.query(OtpTokenModel).filter(
        OtpTokenModel.email == email_clean,
        OtpTokenModel.token_type == "password_reset",
        OtpTokenModel.is_used == False
    ).update({"is_used": True})

    # Generate 6-digit OTP (10m expiry)
    reset_otp = generate_cryptographic_otp()
    otp_record = OtpTokenModel(
        user_id=user.id,
        email=email_clean,
        otp_code=reset_otp,
        token_type="password_reset",
        expires_at=calculate_otp_expiry(),
        is_used=False,
        attempts=0
    )
    db.add(otp_record)
    db.commit()

    # Dispatch email
    send_password_reset_email(
        recipient_email=user.email,
        recipient_name=user.full_name,
        otp_code=reset_otp
    )

    return {
        "message": "A 6-digit password reset verification code has been dispatched to your email.",
        "cooldown_seconds": 30
    }

@app.post("/api/auth/password-reset/verify", tags=["Password Reset"])
def verify_password_reset_otp(
    payload: PasswordResetVerifyRequest,
    db: Session = Depends(get_db)
):
    """
    Step 2: Verify 6-digit reset OTP
    - Validates code within 10-minute expiry
    - Invalidates OTP upon match
    - Mints temporary 15-minute reset session token
    """
    email_clean = payload.email.strip().lower()
    otp_code_clean = payload.otp_code.strip()

    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    # Query latest active reset token
    token_record = (
        db.query(OtpTokenModel)
        .filter(
            OtpTokenModel.email == email_clean,
            OtpTokenModel.token_type == "password_reset",
            OtpTokenModel.is_used == False
        )
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active password reset verification code found. Please request a new code."
        )

    now = datetime.utcnow()
    if now > token_record.expires_at:
        token_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset verification code has expired (10-minute limit). Please request a new code."
        )

    if token_record.otp_code != otp_code_clean:
        token_record.attempts += 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Please check your reset email."
        )

    # Code accepted
    token_record.is_used = True
    db.commit()

    # Mint temporary reset session token (15m validity)
    reset_token = create_password_reset_session_token(user.id, user.email)

    return {
        "message": "Verification code verified successfully. You may now set your new password.",
        "reset_token": reset_token
    }

@app.post("/api/auth/password-reset/confirm", tags=["Password Reset"])
def confirm_password_reset(
    payload: PasswordResetConfirmRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Step 3: Set New Password with Security Audit Controls
    1. Validates reset_token
    2. Validates password strength policy
    3. Requirement 2: Previous Password Prevention (checks current and recent password history)
    4. Requirement 3: Automatic Account Unlock (clears locked_until, resets failed attempts)
    5. Requirement 4: Security Notification Email (sends audit confirmation with timestamp, device/user-agent, and IP)
    """
    email_clean = payload.email.strip().lower()

    # 1. Validate reset session token
    is_valid_token, token_user_id = verify_password_reset_session_token(payload.reset_token, email_clean)
    if not is_valid_token or not token_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=token_user_id or "Invalid or expired password reset session."
        )

    user = db.query(UserModel).filter(UserModel.id == token_user_id, UserModel.email == email_clean).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    # 2. Enforce Password Strength Policy
    is_valid_pw, pw_err = validate_password_strength(payload.new_password)
    if not is_valid_pw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=pw_err
        )

    # 3. Requirement 2: Previous Password Prevention
    # Fetch recent password history for this user
    history_records = (
        db.query(PasswordHistoryModel)
        .filter(PasswordHistoryModel.user_id == user.id)
        .order_by(PasswordHistoryModel.created_at.desc())
        .limit(5)
        .all()
    )
    past_hashes = [rec.hashed_password for rec in history_records]

    is_novel_pw, history_err = check_password_history(
        new_password=payload.new_password,
        current_hash=user.hashed_password,
        past_hashes=past_hashes
    )
    if not is_novel_pw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=history_err
        )

    # Save current password to history before updating
    old_history_entry = PasswordHistoryModel(
        user_id=user.id,
        hashed_password=user.hashed_password
    )
    db.add(old_history_entry)

    # Hash and update new password
    new_hashed = hash_password(payload.new_password)
    user.hashed_password = new_hashed

    # 4. Requirement 3: Automatic Account Unlock
    user.locked_until = None
    user.failed_login_attempts = 0
    user.last_failed_login = None

    db.commit()

    # 5. Requirement 4: Security Notification Email with audit details
    audit_timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    device_info = request.headers.get("user-agent", "Unknown Device / Web Browser")
    ip_address = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "Unknown IP")

    send_password_changed_notification(
        recipient_email=user.email,
        recipient_name=user.full_name,
        timestamp=audit_timestamp,
        device_info=device_info[:150],
        ip_address=ip_address.split(",")[0].strip()
    )

    return {
        "message": "Password successfully updated and account unlocked. You may now log in with your new credentials.",
        "is_locked": False,
        "audit_timestamp": audit_timestamp
    }

# ==========================================
# MULTI-DEVICE SESSION MANAGEMENT ENDPOINTS
# ==========================================

@app.get("/api/sessions", tags=["Session Security"])
def list_active_sessions(
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 3: Return all currently active device sessions for authenticated user.
    Flags is_current = True for the caller's workstation session.
    """
    current_sid = getattr(current_user, "_current_session_id", None)
    active_sessions = (
        db.query(UserSessionModel)
        .filter(
            UserSessionModel.user_id == current_user.id,
            UserSessionModel.status == "active"
        )
        .order_by(UserSessionModel.last_active.desc())
        .all()
    )
    return [s.to_dict(current_session_id=current_sid) for s in active_sessions]

@app.delete("/api/sessions/others", tags=["Session Security"])
def revoke_other_sessions(
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 3: Invalidate all active sessions except the current workstation.
    """
    current_sid = getattr(current_user, "_current_session_id", None)
    query = db.query(UserSessionModel).filter(
        UserSessionModel.user_id == current_user.id,
        UserSessionModel.status == "active"
    )
    if current_sid:
        query = query.filter(UserSessionModel.id != current_sid)

    revoked_count = query.update({"status": "revoked"}, synchronize_session=False)
    db.commit()

    return {
        "message": "All other active device sessions have been terminated.",
        "terminated_count": revoked_count
    }

@app.delete("/api/sessions/{session_id}", tags=["Session Security"])
def revoke_session(
    session_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 3: Remotely revoke and invalidate a specific device session.
    """
    session_record = (
        db.query(UserSessionModel)
        .filter(
            UserSessionModel.id == session_id,
            UserSessionModel.user_id == current_user.id
        )
        .first()
    )
    if not session_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or belongs to another account."
        )

    session_record.status = "revoked"
    db.commit()
    return {
        "message": f"Device session ({session_record.device_name}) has been revoked.",
        "session_id": session_id,
        "status": "revoked"
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
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(DonorModel)
    if blood_type:
        query = query.filter(DonorModel.blood_type == blood_type.upper())
    if user_email:
        query = query.filter((DonorModel.user_email == user_email.strip().lower()) | (DonorModel.user_email.is_(None)))
    donors = query.order_by(DonorModel.created_at.desc()).all()
    return [d.to_dict() for d in donors]

@app.post("/api/donors", tags=["Donors"], status_code=status.HTTP_201_CREATED)
def register_donor(
    payload: DonorCreateRequest,
    db: Session = Depends(get_db)
):
    email_clean = payload.user_email.strip().lower() if payload.user_email else None
    new_donor = DonorModel(
        user_email=email_clean,
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
    db.commit()

    if email_clean:
        sync_user_state_to_r2(email_clean, db)

    return new_donor.to_dict()

@app.delete("/api/donors/{donor_id}", tags=["Donors"])
def delete_donor(
    donor_id: str,
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Requirement 4: Deletion Persistence in Database & R2
    """
    donor = db.query(DonorModel).filter(DonorModel.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Donor not found.")

    target_email = user_email.strip().lower() if user_email else donor.user_email
    db.delete(donor)
    db.commit()

    if target_email:
        sync_user_state_to_r2(target_email, db)

    return {"message": "Donor deleted successfully.", "deleted_id": donor_id}

# ==========================================
# EMERGENCY REQUEST ENDPOINTS
# ==========================================
@app.get("/api/emergency", tags=["Emergency"])
def list_emergency_requests(
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(EmergencyRequestModel)
    if user_email:
        query = query.filter((EmergencyRequestModel.user_email == user_email.strip().lower()) | (EmergencyRequestModel.user_email.is_(None)))
    requests = query.order_by(EmergencyRequestModel.created_at.desc()).all()
    return [r.to_dict() for r in requests]

@app.post("/api/emergency", tags=["Emergency"], status_code=status.HTTP_201_CREATED)
def create_emergency_request(
    payload: EmergencyCreateRequest,
    db: Session = Depends(get_db)
):
    email_clean = payload.user_email.strip().lower() if payload.user_email else None
    req = EmergencyRequestModel(
        user_email=email_clean,
        patient_name=payload.patient_name,
        hospital=payload.hospital,
        blood_type=payload.blood_type.upper(),
        units_needed=payload.units_needed,
        status=payload.status,
        contact_person=payload.contact_person,
        contact_phone=payload.contact_phone
    )
    db.add(req)
    db.commit()

    if email_clean:
        sync_user_state_to_r2(email_clean, db)

    return req.to_dict()

@app.delete("/api/emergency/{request_id}", tags=["Emergency"])
def delete_emergency_request(
    request_id: str,
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Requirement 4: Deletion Persistence in Database & R2
    """
    req = db.query(EmergencyRequestModel).filter(EmergencyRequestModel.id == request_id).first()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Emergency request not found.")

    target_email = user_email.strip().lower() if user_email else req.user_email
    db.delete(req)
    db.commit()

    if target_email:
        sync_user_state_to_r2(target_email, db)

    return {"message": "Emergency request deleted successfully.", "deleted_id": request_id}

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
    email_clean = payload.work_email.strip().lower()
    profile = db.query(ClinicianProfileModel).filter(ClinicianProfileModel.work_email == email_clean).first()
    if not profile:
        profile = ClinicianProfileModel(
            full_name=payload.full_name,
            work_email=email_clean,
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
    db.commit()

    sync_user_state_to_r2(email_clean, db)
    return profile.to_dict()

# ==========================================
# CLINICAL CHECKS & SCREENING CONSULTATIONS
# ==========================================
@app.get("/api/v1/clinical/checks", tags=["Clinical Checks"])
def list_clinical_checks(
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    email = user_email
    if not email and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email = u.email
    query = db.query(ClinicalCheckModel)
    if email:
        query = query.filter(ClinicalCheckModel.user_email == email.strip().lower())
    checks = query.order_by(ClinicalCheckModel.created_at.desc()).all()
    return [c.to_dict() for c in checks]

@app.post("/api/v1/clinical/checks", tags=["Clinical Checks"], status_code=status.HTTP_201_CREATED)
def create_clinical_check(
    payload: ClinicalCheckCreateRequest,
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    email = user_email
    if not email and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email = u.email
    if not email:
        u = db.query(UserModel).first()
        email = u.email if u else "clinician@bloodmatch.io"

    email_clean = email.strip().lower()
    new_check = ClinicalCheckModel(
        user_email=email_clean,
        patient_name=payload.patient_name,
        patient_id=payload.patient_id,
        blood_type=payload.blood_type.upper(),
        check_type=payload.check_type,
        status=payload.status,
        notes=payload.notes
    )
    db.add(new_check)

    # Automatic Audit Log
    audit = ClinicalAuditLogModel(
        user_email=email_clean,
        action=f"CLINICAL_CHECK_{payload.check_type.upper()}",
        entity_type="check",
        entity_id=new_check.id,
        details=f"Patient {payload.patient_name} ({payload.blood_type}): {payload.status}",
        ip_address=request.client.host if request and request.client else "127.0.0.1"
    )
    db.add(audit)
    db.commit()

    sync_user_state_to_r2(email_clean, db)
    return new_check.to_dict()

@app.delete("/api/v1/clinical/checks/{check_id}", tags=["Clinical Checks"])
def delete_clinical_check(
    check_id: str,
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Requirement 4: Deletion Persistence
    Reflects deletion in both the database and R2 master JSON so deleted data stays deleted.
    """
    check = db.query(ClinicalCheckModel).filter(ClinicalCheckModel.id == check_id).first()
    if not check:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Clinical check not found.")

    target_email = user_email.strip().lower() if user_email else check.user_email
    db.delete(check)
    db.commit()

    if target_email:
        sync_user_state_to_r2(target_email, db)

    return {"message": "Clinical check record deleted and purged from R2 cloud master sync.", "deleted_id": check_id}

# ==========================================
# CLINICAL DOCUMENTS & LAB REPORTS
# ==========================================
@app.get("/api/v1/clinical/documents", tags=["Clinical Documents"])
def list_clinical_documents(
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    email = user_email
    if not email and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email = u.email
    query = db.query(ClinicalDocumentModel)
    if email:
        query = query.filter(ClinicalDocumentModel.user_email == email.strip().lower())
    docs = query.order_by(ClinicalDocumentModel.created_at.desc()).all()
    return [d.to_dict() for d in docs]

@app.post("/api/v1/clinical/documents", tags=["Clinical Documents"], status_code=status.HTTP_201_CREATED)
def create_clinical_document(
    payload: ClinicalDocumentCreateRequest,
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    email = user_email
    if not email and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email = u.email
    if not email:
        u = db.query(UserModel).first()
        email = u.email if u else "clinician@bloodmatch.io"

    email_clean = email.strip().lower()
    new_doc = ClinicalDocumentModel(
        user_email=email_clean,
        title=payload.title,
        doc_type=payload.doc_type,
        file_url=payload.file_url,
        file_size_kb=payload.file_size_kb or 0.0
    )
    db.add(new_doc)
    db.commit()

    sync_user_state_to_r2(email_clean, db)
    return new_doc.to_dict()

@app.delete("/api/v1/clinical/documents/{doc_id}", tags=["Clinical Documents"])
def delete_clinical_document(
    doc_id: str,
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Requirement 4: Deletion Persistence in Database & R2
    """
    doc = db.query(ClinicalDocumentModel).filter(ClinicalDocumentModel.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Clinical document not found.")

    target_email = user_email.strip().lower() if user_email else doc.user_email
    db.delete(doc)
    db.commit()

    if target_email:
        sync_user_state_to_r2(target_email, db)

    return {"message": "Clinical document deleted and purged from R2 master state.", "deleted_id": doc_id}

# ==========================================
# CLINICAL AUDIT LOGS
# ==========================================
@app.get("/api/v1/clinical/audit-logs", tags=["Clinical Audit Logs"])
def list_clinical_audit_logs(
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    email = user_email
    if not email and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email = u.email
    query = db.query(ClinicalAuditLogModel)
    if email:
        query = query.filter(ClinicalAuditLogModel.user_email == email.strip().lower())
    logs = query.order_by(ClinicalAuditLogModel.timestamp.desc()).all()
    return [l.to_dict() for l in logs]

@app.post("/api/v1/clinical/audit-logs", tags=["Clinical Audit Logs"], status_code=status.HTTP_201_CREATED)
def create_clinical_audit_log(
    payload: ClinicalAuditLogCreateRequest,
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    email = user_email
    if not email and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email = u.email
    if not email:
        u = db.query(UserModel).first()
        email = u.email if u else "clinician@bloodmatch.io"

    email_clean = email.strip().lower()
    new_log = ClinicalAuditLogModel(
        user_email=email_clean,
        action=payload.action,
        entity_type=payload.entity_type,
        entity_id=payload.entity_id,
        details=payload.details,
        ip_address=request.client.host if request and request.client else "127.0.0.1"
    )
    db.add(new_log)
    db.commit()

    sync_user_state_to_r2(email_clean, db)
    return new_log.to_dict()

# ==========================================
# CLOUDFLARE R2 USER-SCOPED STORAGE SERVICE
# ==========================================
@app.post("/api/v1/storage/avatar", tags=["Cloud Storage Service"])
@app.post("/api/v1/auth/avatar", tags=["Cloud Storage Service"])
async def upload_user_avatar(
    file: UploadFile = File(...),
    user_email: Optional[str] = Form(None),
    crop_x: Optional[int] = Form(None),
    crop_y: Optional[int] = Form(None),
    crop_width: Optional[int] = Form(None),
    crop_height: Optional[int] = Form(None),
    target_format: Optional[str] = Form("WEBP"),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 3: Avatar Upload & Processing (Pillow Crop, WebP/JPEG Conversion, < 5MB)
    Requirement 4: Multi-Tenant Protection (users can only modify within their user-scoped path prefix)
    """
    # Multi-Tenant Protection: Verify user is not impersonating or writing to another tenant's prefix
    if user_email and not validate_tenant_access(current_user.email, user_email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Multi-tenant violation: Access denied to upload avatar for tenant {user_email}."
        )

    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed 5MB limit ({len(raw_bytes)} bytes)."
        )

    # Process and crop image using Pillow
    try:
        processed_bytes, mime_type, ext = process_avatar_image(
            raw_bytes,
            crop_x=crop_x,
            crop_y=crop_y,
            crop_width=crop_width,
            crop_height=crop_height,
            target_format=target_format or "WEBP"
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    filename = f"avatar.{ext}"
    try:
        upload_meta = upload_user_asset(
            content=processed_bytes,
            authenticated_email=current_user.email,
            category="profile",
            filename=filename,
            content_type=mime_type
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Storage upload failed: {exc}")

    current_user.photo_url = upload_meta["public_url"]
    db.commit()

    # Continuous disaster recovery master mirror update
    sync_user_state_to_r2(current_user.email, db)

    return {
        "photoUrl": upload_meta["public_url"],
        "s3_key": upload_meta["s3_key"],
        "size_bytes": upload_meta["size_bytes"],
        "content_type": upload_meta["content_type"],
        "message": "Avatar cropped, converted to WebP, and stored in user-scoped R2 directory."
    }

@app.post("/api/v1/storage/upload", tags=["Cloud Storage Service"])
async def upload_scoped_asset(
    file: UploadFile = File(...),
    category: str = Form("documents"),
    user_email: Optional[str] = Form(None),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 2 & 4: General Scoped Asset Upload with Multi-Tenant Guard
    Path: users/{sanitized_user_email}/{category}/{timestamp}_{filename}
    """
    if user_email and not validate_tenant_access(current_user.email, user_email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Multi-tenant violation: Cannot store assets under another tenant prefix."
        )

    content = await file.read()
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded asset exceeds 5MB limit ({len(content)} bytes)."
        )

    filename = file.filename or "asset.bin"
    content_type = file.content_type or "application/octet-stream"

    upload_result = upload_user_asset(
        content=content,
        authenticated_email=current_user.email,
        category=category,
        filename=filename,
        content_type=content_type
    )

    return upload_result

@app.get("/api/v1/storage/files", tags=["Cloud Storage Service"])
def list_user_scoped_files(
    category: Optional[str] = Query(None),
    user_email: Optional[str] = Query(None),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists files inside the authenticated user's isolated R2 path prefix.
    """
    if user_email and not validate_tenant_access(current_user.email, user_email):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to list another tenant's assets.")

    return list_user_assets(current_user.email, category)

@app.delete("/api/v1/storage/files", tags=["Cloud Storage Service"])
def delete_user_scoped_file(
    s3_key: str = Query(..., description="Full S3 key to delete"),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 4: Multi-Tenant Deletion Guard
    Validates that users can only delete files inside their own user email path prefix.
    """
    if not validate_tenant_access(current_user.email, s3_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Multi-tenant violation: Access denied. Cannot delete asset outside prefix users/{sanitize_user_email(current_user.email)}/."
        )

    deleted = delete_user_asset(s3_key, current_user.email)
    return {
        "success": deleted,
        "deleted_key": s3_key,
        "message": "Asset deleted from user-scoped Cloudflare R2 path."
    }

@app.delete("/api/v1/auth/avatar", tags=["Cloud Storage Service"])
def delete_user_avatar(
    user_email: Optional[str] = Query(None),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 4: Deletion & Remote Reset
    """
    if user_email and not validate_tenant_access(current_user.email, user_email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Multi-tenant violation: Cannot delete another tenant's avatar."
        )

    current_user.photo_url = None
    db.commit()

    # Master Cloud Mirror update on deletion
    sync_user_state_to_r2(current_user.email, db)

    return {
        "photoUrl": None,
        "message": "Avatar removed successfully. Reset to clinical initials."
    }

@app.get("/api/v1/sync/all", tags=["Cloud State Sync"])
def get_user_sync_telemetry(
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Requirement 3: Startup Auto-Reconciliation & Cross-Device Cloud Sync
    When the client calls the sync pull endpoint, if the local database has 0 records
    for that user, automatically fetch and parse clinical_sync_data.json from Cloudflare R2,
    re-populate the local database tables, and return the complete hydrated data.
    """
    email_clean = None
    auth_header = request.headers.get("Authorization") if request else None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        u = get_user_from_token(token, db)
        if u:
            email_clean = u.email

    if not email_clean and user_email:
        email_clean = user_email.strip().lower()

    if not email_clean:
        first_user = db.query(UserModel).first()
        if first_user:
            email_clean = first_user.email

    if not email_clean:
        return {
            "authenticated": False,
            "reconciled_from_r2": False,
            "photoUrl": None,
            "synced_at": datetime.utcnow().isoformat()
        }

    # Count local records for this user
    checks_count = db.query(ClinicalCheckModel).filter(ClinicalCheckModel.user_email == email_clean).count()
    docs_count = db.query(ClinicalDocumentModel).filter(ClinicalDocumentModel.user_email == email_clean).count()
    audit_count = db.query(ClinicalAuditLogModel).filter(ClinicalAuditLogModel.user_email == email_clean).count()
    total_local_records = checks_count + docs_count + audit_count

    reconciled = False
    # Requirement 3: If 0 records in database for this user, auto-reconcile from Cloudflare R2
    if total_local_records == 0:
        logger.info(f"Local database has 0 clinical records for {email_clean}. Triggering R2 startup auto-reconciliation...")
        reconciled_data = reconcile_user_from_r2(email_clean, db)
        if reconciled_data:
            reconciled = True
            logger.info(f"Successfully auto-reconciled user state from R2 for {email_clean}.")

    # Fetch live state after reconciliation
    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    profile = db.query(ClinicianProfileModel).filter(ClinicianProfileModel.work_email == email_clean).first()
    checks = db.query(ClinicalCheckModel).filter(ClinicalCheckModel.user_email == email_clean).order_by(ClinicalCheckModel.created_at.desc()).all()
    audit_logs = db.query(ClinicalAuditLogModel).filter(ClinicalAuditLogModel.user_email == email_clean).order_by(ClinicalAuditLogModel.timestamp.desc()).all()
    documents = db.query(ClinicalDocumentModel).filter(ClinicalDocumentModel.user_email == email_clean).order_by(ClinicalDocumentModel.created_at.desc()).all()
    donors = db.query(DonorModel).filter((DonorModel.user_email == email_clean) | (DonorModel.user_email.is_(None))).order_by(DonorModel.created_at.desc()).all()
    emergency_reqs = db.query(EmergencyRequestModel).filter((EmergencyRequestModel.user_email == email_clean) | (EmergencyRequestModel.user_email.is_(None))).order_by(EmergencyRequestModel.created_at.desc()).all()
    inventory = db.query(InventoryModel).order_by(InventoryModel.blood_type).all()

    photo_url = user.photo_url if user else (profile.avatar_url if profile else None)

    return {
        "authenticated": bool(user is not None),
        "reconciled_from_r2": reconciled,
        "userEmail": email_clean,
        "user": user.to_dict() if user else None,
        "photoUrl": photo_url,
        "profile": profile.to_dict() if profile else None,
        "checks": [c.to_dict() for c in checks],
        "auditLogs": [a.to_dict() for a in audit_logs],
        "documents": [d.to_dict() for d in documents],
        "donors": [d.to_dict() for d in donors],
        "emergencyRequests": [r.to_dict() for r in emergency_reqs],
        "inventory": [i.to_dict() for i in inventory],
        "synced_at": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/sync/push", tags=["Cloud State Sync"])
def push_user_sync_state(
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Explicitly forces a manual serialization and push of local state to Cloudflare R2.
    """
    email_clean = user_email.strip().lower() if user_email else None
    if not email_clean and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email_clean = u.email
    if not email_clean:
        u = db.query(UserModel).first()
        email_clean = u.email if u else None

    if not email_clean:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User email required for cloud state sync.")

    synced_payload = sync_user_state_to_r2(email_clean, db)
    return {
        "status": "synchronized",
        "message": f"Successfully serialized state to users/{email_clean}/clinical_sync_data.json in Cloudflare R2.",
        "data": synced_payload
    }

@app.post("/api/v1/sync/pull", tags=["Cloud State Sync"])
def pull_user_sync_state(
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Explicitly forces a manual pull and re-population from Cloudflare R2 into the local database.
    """
    email_clean = user_email.strip().lower() if user_email else None
    if not email_clean and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email_clean = u.email
    if not email_clean:
        u = db.query(UserModel).first()
        email_clean = u.email if u else None

    if not email_clean:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User email required for cloud state reconciliation.")

    reconciled_data = reconcile_user_from_r2(email_clean, db)
    if not reconciled_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No R2 master state found for {email_clean}.")

    return {
        "status": "reconciled",
        "message": f"Successfully re-hydrated local database from Cloudflare R2 for {email_clean}.",
        "data": reconciled_data
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
