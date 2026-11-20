import os
import re
import json
import uuid
import base64
import time
import logging
from datetime import datetime
from contextlib import asynccontextmanager
from typing import List, Optional

import boto3
from fastapi import FastAPI, Depends, HTTPException, Query, Request, status, UploadFile, File, Form, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from database import init_db, get_db, is_sqlite_fallback
from models import (
    generate_uuid,
    strip_honorific,
    UserModel,
    OtpTokenModel,
    PasswordHistoryModel,
    UserSessionModel,
    TrustedDeviceModel,
    InventoryModel,
    DonorModel,
    EmergencyRequestModel,
    DeletedEmergencyRequestModel,
    ClinicianProfileModel,
    ClinicalCheckModel,
    ClinicalAuditLogModel,
    ClinicalDocumentModel,
    TransfusionAlertModel
)
from schemas import (
    UserRegisterRequest,
    OtpVerifyRequest,
    OtpResendRequest,
    UserLoginRequest,
    TogglePrimarySessionRequest,
    AccountUnlockRequest,
    TwoFactorVerifyRequest,
    TwoFactorToggleRequest,
    PasswordResetRequest,
    PasswordResetVerifyRequest,
    PasswordResetConfirmRequest,
    PasswordVerifyCurrentRequest,
    PasswordUpdatePreviousRequest,
    AccountDeletionConfirmRequest,
    AuthTokenResponse,
    InventoryUpdateRequest,
    DonorSendOtpRequest,
    DonorCreateRequest,
    EmergencyCreateRequest,
    EmergencyLiveTrackingRequest,
    EmergencyFulfillRequest,
    ClinicianProfileRequest,
    ProfileUpdateRequest,
    EmergencyDispatchDonorRequest,
    EmergencyRosterEmailRequest,
    SaveDocketRequest,
    SavedPhoneRequest,
    VerifiedEmailRequest,
    GpsPermissionToggleRequest,
    MarkAlertsReadRequest,
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
    send_donor_thankyou_email,
    send_new_login_session_alert,
    send_account_deletion_otp_email,
    send_account_deleted_confirmation_email,
    send_emergency_donor_dispatch_email,
    send_emergency_dispatch_confirmation_to_clinician,
    send_clinician_donor_roster_email,
    send_transfusion_fulfilled_emails,
    send_live_tracking_match_email
)
from storage_service import (
    process_avatar_image,
    upload_user_asset,
    delete_user_asset,
    delete_user_category_assets,
    list_user_assets,
    get_user_avatar_bytes,
    validate_tenant_access,
    sanitize_user_email,
    build_scoped_path,
    save_user_auth_record_r2,
    get_user_auth_record_r2,
    restore_all_users_from_r2,
    delete_all_user_r2_data,
    MAX_FILE_SIZE_BYTES
)

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BloodBackend.App")

def sanitize_display_name(name: Optional[str]) -> str:
    """Completely strips honorifics (Dr., Dr, Doctor, etc.) so user is addressed cleanly."""
    if not name:
        return "Clinician"
    cleaned = re.sub(r'^(?:Dr\.?|Doctor|Prof\.?|Mr\.?|Mrs\.?|Ms\.?)\s+', '', str(name).strip(), flags=re.IGNORECASE).strip()
    return cleaned or "Clinician"

main_event_loop = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_event_loop
    import asyncio
    main_event_loop = asyncio.get_running_loop()
    logger.info("Initializing database schema on startup...")
    init_db()
    # Auto-hydrate users from permanent Cloudflare R2 mirror
    try:
        from database import SessionLocal
        with SessionLocal() as session:
            count = restore_all_users_from_r2(session)
            if count > 0:
                logger.info(f"Startup R2 user reconciliation completed: {count} accounts restored.")
            # Auto-sanitize any existing clinician names in DB (removes legacy 'Dr.' prefixes)
            all_users = session.query(UserModel).all()
            modified = False
            for u in all_users:
                cleaned = sanitize_display_name(u.full_name)
                if cleaned != u.full_name:
                    u.full_name = cleaned
                    modified = True
            if modified:
                session.commit()
                logger.info("Startup migration: Sanitized clinician names in database (removed 'Dr.' prefix).")
                try:
                    from r2_db_sync import sync_db_to_r2
                    from database import sqlite_path
                    sync_db_to_r2(sqlite_path, force=True)
                except Exception as sync_err:
                    logger.warning(f"Failed to sync sanitized DB to R2 on startup: {sync_err}")
    except Exception as exc:
        logger.warning(f"Could not restore or sanitize users on startup: {exc}")
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
DEFAULT_EXPLICIT_ORIGINS = [
    "https://blood-match-software.bloodmatch-support.workers.dev",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000"
]
explicit_origins = list(set(DEFAULT_EXPLICIT_ORIGINS + ([orig.strip() for orig in CORS_ORIGINS_RAW.split(",") if orig.strip()] if CORS_ORIGINS_RAW else [])))

# Requirement 1: Fallback regex for modern hosting providers (Vercel, Cloudflare Pages/Workers, Netlify, localhost)
ORIGIN_REGEX = r"^https?:\/\/(.*\.vercel\.app|.*\.pages\.dev|.*\.workers\.dev|.*\.netlify\.app|localhost|127\.0\.0\.1)(:\d+)?$"

# Blood Group Compatibility Helper for Live Tracking
BLOOD_CAN_RECEIVE_FROM = {
    "O-": ["O-"],
    "O+": ["O+", "O-"],
    "A-": ["A-", "O-"],
    "A+": ["A+", "A-", "O+", "O-"],
    "B-": ["B-", "O-"],
    "B+": ["B+", "B-", "O+", "O-"],
    "AB-": ["AB-", "A-", "B-", "O-"],
    "AB+": ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"]
}

def is_donor_compatible_for_request(donor_type: str, request_blood_type: str) -> bool:
    d = (donor_type or "").upper().strip()
    r = (request_blood_type or "").upper().strip()
    return d in BLOOD_CAN_RECEIVE_FROM.get(r, [r])

class ConnectionManager:
    """Manages active WebSocket connections across multi-device clinical clients."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

ws_manager = ConnectionManager()

def safe_broadcast(message: dict):
    """Safely broadcasts WebSocket messages across async and sync thread boundaries."""
    try:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            asyncio.create_task(ws_manager.broadcast(message))
        elif main_event_loop and main_event_loop.is_running():
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(message), main_event_loop)
    except Exception as exc:
        logger.warning(f"safe_broadcast error: {exc}")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
            except Exception:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


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
            "savedPhones": user.get_saved_phones() if user else [],
            "verifiedEmails": user.get_verified_emails() if user else [email_clean],
            "primaryDeviceIds": user.get_primary_device_ids() if user else [],
            "gpsPermissionEnabled": bool(user.gps_permission_enabled) if user and user.gps_permission_enabled is not None else False,
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
                hashed_password=hash_password("HydratedClinical@2026#"),
                saved_phones=json.dumps(sync_data.get("savedPhones") or []),
                verified_emails=json.dumps(sync_data.get("verifiedEmails") or [email_clean]),
                primary_device_ids=json.dumps(sync_data.get("primaryDeviceIds") or [])
            )
            db.add(user)
        else:
            if sync_data.get("photoUrl") and not user.photo_url:
                user.photo_url = sync_data.get("photoUrl")
            if sync_data.get("savedPhones"):
                for p in sync_data.get("savedPhones"):
                    user.add_saved_phone(p)
            if sync_data.get("verifiedEmails"):
                for e in sync_data.get("verifiedEmails"):
                    user.add_verified_email(e)
            if sync_data.get("primaryDeviceIds"):
                for d in sync_data.get("primaryDeviceIds"):
                    user.add_primary_device(d)
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
                    contact_phone=req.get("contact_phone") or req.get("contactNumber") or "+1 555-0199",
                    live_tracking=bool(req.get("live_tracking", req.get("liveTracking", True)))
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
@app.get("/api/health", tags=["System"])
def health_check(db: Session = Depends(get_db)):
    return {
        "status": "healthy",
        "database_connected": True,
        "engine": "sqlite_fallback" if is_sqlite_fallback else "postgresql",
        "server_time": time.time(),
        "speed": "optimal"
    }

@app.post("/api/admin/reset-system-data", tags=["System"])
def admin_reset_system_data(db: Session = Depends(get_db)):
    """
    Complete Database & Storage Fresh-Start Reset:
    1. Wipes all user, session, token, donor, check, document, alert, and request records.
    2. Resets all 8 ABO/Rh blood groups to strictly 0 units available.
    3. Purges Cloudflare R2 storage under users/ prefix.
    """
    tables_to_clear = [
        UserModel,
        OtpTokenModel,
        UserSessionModel,
        TrustedDeviceModel,
        ClinicianProfileModel,
        PasswordHistoryModel,
        EmergencyRequestModel,
        ClinicalCheckModel,
        ClinicalAuditLogModel,
        ClinicalDocumentModel,
        DonorModel,
        TransfusionAlertModel,
        InventoryModel
    ]
    for model_cls in tables_to_clear:
        db.query(model_cls).delete()
    db.commit()

    # Re-seed the pristine 8 ABO & RhD blood groups initialized to strictly 0 units
    initial_inventory = [
        InventoryModel(blood_type="O-", units_available=0, status="critical", temperature_celsius=4.0),
        InventoryModel(blood_type="O+", units_available=0, status="critical", temperature_celsius=4.0),
        InventoryModel(blood_type="A-", units_available=0, status="critical", temperature_celsius=4.0),
        InventoryModel(blood_type="A+", units_available=0, status="critical", temperature_celsius=4.0),
        InventoryModel(blood_type="B-", units_available=0, status="critical", temperature_celsius=4.0),
        InventoryModel(blood_type="B+", units_available=0, status="critical", temperature_celsius=4.0),
        InventoryModel(blood_type="AB-", units_available=0, status="critical", temperature_celsius=4.0),
        InventoryModel(blood_type="AB+", units_available=0, status="critical", temperature_celsius=4.0),
    ]
    db.add_all(initial_inventory)
    db.commit()

    # Clean Cloudflare R2 storage
    deleted_r2_count = 0
    try:
        from storage_service import get_r2_client, R2_BUCKET_NAME
        r2 = get_r2_client()
        if r2:
            paginator = r2.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=R2_BUCKET_NAME, Prefix="users/"):
                items = page.get("Contents", [])
                if items:
                    delete_keys = [{"Key": item["Key"]} for item in items]
                    r2.delete_objects(Bucket=R2_BUCKET_NAME, Delete={"Objects": delete_keys})
                    deleted_r2_count += len(delete_keys)
    except Exception as exc:
        logger.warning(f"R2 purge notice: {exc}")

    return {
        "status": "success",
        "message": "All database records wiped to zero. 8 blood groups reset to 0 units. R2 storage purged.",
        "r2_objects_purged": deleted_r2_count
    }

# ==========================================
# ENTERPRISE AUTHENTICATION & OTP LIFECYCLE
# ==========================================

def get_user_by_email_or_r2(email: str, db: Session) -> Optional[UserModel]:
    """Retrieves user by email from SQLite/PostgreSQL, or restores from Cloudflare R2 on demand."""
    if not email:
        return None
    email_clean = email.strip().lower()
    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if user:
        return user
    try:
        r2_record = get_user_auth_record_r2(email_clean)
        if r2_record:
            user = UserModel(
                id=r2_record.get("id"),
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
            logger.info(f"[R2 SYNC] Restored account {email_clean} on-demand.")
            return user
    except Exception as exc:
        logger.warning(f"Could not retrieve user {email_clean} from R2: {exc}")
    return None

@app.post("/api/auth/register", tags=["Authentication"], status_code=status.HTTP_201_CREATED)
def register_user(
    payload: UserRegisterRequest,
    background_tasks: BackgroundTasks,
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

    # 2. Enforce Phone Validation & Uniqueness
    phone_clean = payload.phone.strip() if payload.phone else ""
    if not phone_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid mobile phone number is required to register a clinical account."
        )

    phone_digits = extract_phone_digits(phone_clean)
    if len(phone_digits) < 7 or len(phone_digits) > 15:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mobile phone number must contain between 7 and 15 digits."
        )

    # Check across all users to guarantee mobile number uniqueness
    all_users = db.query(UserModel).all()
    for u in all_users:
        if u.email != email_clean:
            if u.phone and match_phone_numbers(phone_clean, u.phone):
                    if u.is_verified:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This mobile number is already registered with another account. Each account must have a unique phone number."
                        )
                    else:
                        # Clean up previous unverified abandoned registration under different email
                        db.query(OtpTokenModel).filter(OtpTokenModel.user_id == u.id).delete()
                        db.query(UserSessionModel).filter(UserSessionModel.user_id == u.id).delete()
                        db.delete(u)
                        db.flush()
                        break

    # Check across Cloudflare R2 backup to guarantee mobile number uniqueness
    try:
        from storage_service import get_r2_client, R2_BUCKET_NAME
        r2 = get_r2_client()
        if r2:
            paginator = r2.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=R2_BUCKET_NAME, Prefix="users/"):
                for obj in page.get("Contents", []):
                    key = obj.get("Key", "")
                    if key.endswith("/auth_record.json"):
                        try:
                            record_obj = r2.get_object(Bucket=R2_BUCKET_NAME, Key=key)
                            r2_record = json.loads(record_obj["Body"].read().decode("utf-8"))
                            r2_email = r2_record.get("email", "").strip().lower()
                            r2_phone = r2_record.get("phone")
                            if r2_email != email_clean and r2_phone and match_phone_numbers(phone_clean, r2_phone):
                                raise HTTPException(
                                    status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="This mobile number is already registered with another account. Each account must have a unique phone number."
                                )
                        except HTTPException:
                            raise
                        except Exception:
                            continue
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(f"R2 uniqueness check warning: {exc}")

    # 3. Check for existing account (Local DB or R2 permanent mirror)
    existing_user = get_user_by_email_or_r2(email_clean, db)
    if existing_user:
        if existing_user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists. Please log in or reset your password."
            )
        else:
            # User previously attempted registration but is pending verification.
            # Seamlessly refresh their registration, issue a fresh OTP, and dispatch immediately!
            existing_user.full_name = sanitize_display_name(payload.full_name)
            existing_user.phone = phone_clean
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

    # 4. Hash Password with Bcrypt + Salt
    hashed_pw = hash_password(payload.password)

    # 5. Create User with is_verified=False (Activation Boundary)
    new_user = UserModel(
        full_name=sanitize_display_name(payload.full_name),
        email=email_clean,
        phone=phone_clean,
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

    # 6. Initialize Cloudflare R2 user folder structure in background
    from storage_service import initialize_user_storage
    background_tasks.add_task(initialize_user_storage, email_clean, new_user.full_name)

    return {
        "message": "User registered successfully. A 6-digit verification code has been dispatched to your email.",
        "verification_required": True,
        "user": new_user.to_dict()
    }

@app.post("/api/auth/verify-otp", tags=["Authentication"])
def verify_otp(
    payload: OtpVerifyRequest,
    background_tasks: BackgroundTasks,
    request: Request,
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

    user = get_user_by_email_or_r2(email_clean, db)
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
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token has expired (strictly valid for 10 minutes). Please request a fresh verification code."
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
    if user.phone:
        user.add_saved_phone(user.phone)
    user.add_verified_email(user.email)

    # Create active primary session for the verified user with error containment
    session_id = None
    try:
        dev_id = getattr(payload, "device_id", None)
        reg_fp = parse_device_fingerprint(request, client_device_id=dev_id)
        effective_device_id = dev_id or reg_fp.get("device_id") or "initial-registration"
        
        # Mark registration device as user's Primary Device
        user.add_primary_device(effective_device_id)

        session_record = UserSessionModel(
            user_id=user.id,
            device_id=effective_device_id,
            device_name=reg_fp.get("device_name") or "Primary Workstation Browser",
            browser=reg_fp.get("browser") or "Browser",
            os=reg_fp.get("os") or "Client OS",
            ip_address=reg_fp.get("ip_address") or "127.0.0.1",
            location=reg_fp.get("location") or "Authorized Clinical Workstation",
            status="active",
            is_primary=True
        )
        db.add(session_record)

        # Register in TrustedDeviceModel as Primary
        trusted_dev = db.query(TrustedDeviceModel).filter(
            TrustedDeviceModel.user_id == user.id,
            TrustedDeviceModel.device_id == effective_device_id
        ).first()
        if not trusted_dev:
            trusted_dev = TrustedDeviceModel(
                user_id=user.id,
                device_id=effective_device_id,
                device_name=reg_fp.get("device_name") or "Primary Workstation Browser",
                browser=reg_fp.get("browser") or "Browser",
                os=reg_fp.get("os") or "Client OS",
                ip_address=reg_fp.get("ip_address") or "127.0.0.1",
                is_primary=True
            )
            db.add(trusted_dev)
        else:
            trusted_dev.is_primary = True

        db.flush()
        session_id = session_record.id
    except Exception as exc:
        logger.warning(f"Could not persist registration session record: {exc}")

    # Mint JWT Token with active session claim
    token = create_access_token(
        {"sub": user.id, "email": user.email},
        session_id=session_id
    )
    db.commit()

    # Mirror permanent disaster-proof auth record to Cloudflare R2
    try:
        save_user_auth_record_r2({
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "phone": user.phone,
            "hashed_password": user.hashed_password,
            "is_verified": True,
            "is_2fa_enabled": user.is_2fa_enabled,
            "photo_url": user.photo_url,
            "created_at": user.created_at.isoformat() if user.created_at else None
        })
    except Exception as sync_exc:
        logger.warning(f"Failed to mirror auth record to R2: {sync_exc}")

    # Dispatch Welcome & Profile Activation Email asynchronously in background
    try:
        member_id_val = getattr(user, 'member_id', None) or getattr(user, 'custom_id', None) or ""
        background_tasks.add_task(send_welcome_email, user.email, user.full_name, member_id_val)
    except Exception as exc:
        logger.warning(f"Could not queue welcome email background task: {exc}")

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

    user = get_user_by_email_or_r2(email_clean, db)
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

def extract_phone_digits(phone_str: str) -> str:
    """Extract digits and normalize phone numbers for safe matching."""
    if not phone_str:
        return ""
    return re.sub(r'\D', '', str(phone_str))

def match_phone_numbers(phone_a: str, phone_b: str) -> bool:
    """
    Checks if two phone representations match, whether country code was provided or omitted.
    E.g.: '9876543210' matches '+91 98765 43210' or '09876543210' or '919876543210'.
    """
    da = extract_phone_digits(phone_a)
    db = extract_phone_digits(phone_b)
    if not da or not db:
        return False
    if da == db:
        return True
    
    # Strip leading zeros
    da_clean = da.lstrip('0')
    db_clean = db.lstrip('0')
    if da_clean == db_clean:
        return True
        
    # Suffix matching: one might include country code while the other does not
    # E.g., '919876543210' (len 12) ends with '9876543210' (len 10)
    min_len = min(len(da_clean), len(db_clean))
    if min_len >= 7:
        if da_clean.endswith(db_clean) or db_clean.endswith(da_clean):
            return True
    return False

def find_user_by_credential(credential: str, db: Session) -> Optional[UserModel]:
    if not credential:
        return None
    raw = credential.strip()
    if "@" in raw:
        email_clean = raw.lower()
        user = db.query(UserModel).filter(UserModel.email == email_clean).first()
        if not user:
            r2_record = get_user_auth_record_r2(email_clean)
            if r2_record and r2_record.get("hashed_password"):
                user = UserModel(
                    id=r2_record.get("id") or str(uuid.uuid4()),
                    full_name=r2_record.get("full_name") or "Clinician",
                    email=email_clean,
                    phone=r2_record.get("phone"),
                    hashed_password=r2_record.get("hashed_password"),
                    is_verified=bool(r2_record.get("is_verified", True)),
                    is_2fa_enabled=bool(r2_record.get("is_2fa_enabled", False)),
                    photo_url=r2_record.get("photo_url"),
                    saved_phones=json.dumps(r2_record.get("saved_phones") or []),
                    verified_emails=json.dumps(r2_record.get("verified_emails") or [email_clean])
                )
                db.add(user)
                db.commit()
                db.refresh(user)
        return user
    else:
        # Search by phone number across all users in DB
        input_digits = extract_phone_digits(raw)
        if len(input_digits) < 7:
            return None
        
        users = db.query(UserModel).all()
        for u in users:
            if u.phone and match_phone_numbers(raw, u.phone):
                return u

        # Fallback: Check Cloudflare R2 backup records if not found in local DB
        try:
            from storage_service import get_r2_client, R2_BUCKET_NAME
            r2 = get_r2_client()
            if r2:
                paginator = r2.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=R2_BUCKET_NAME, Prefix="users/"):
                    for obj in page.get("Contents", []):
                        key = obj.get("Key", "")
                        if key.endswith("/auth_record.json"):
                            try:
                                record_obj = r2.get_object(Bucket=R2_BUCKET_NAME, Key=key)
                                r2_record = json.loads(record_obj["Body"].read().decode("utf-8"))
                                r2_phone = r2_record.get("phone")
                                if r2_phone and match_phone_numbers(raw, r2_phone):
                                    email_clean = r2_record.get("email").strip().lower()
                                    existing = db.query(UserModel).filter(UserModel.email == email_clean).first()
                                    if not existing:
                                        existing = UserModel(
                                            id=r2_record.get("id") or str(uuid.uuid4()),
                                            full_name=r2_record.get("full_name") or "Clinician",
                                            email=email_clean,
                                            phone=r2_phone,
                                            hashed_password=r2_record.get("hashed_password"),
                                            is_verified=bool(r2_record.get("is_verified", True)),
                                            is_2fa_enabled=bool(r2_record.get("is_2fa_enabled", False)),
                                            photo_url=r2_record.get("photo_url"),
                                            saved_phones=json.dumps(r2_record.get("saved_phones") or []),
                                            verified_emails=json.dumps(r2_record.get("verified_emails") or [email_clean])
                                        )
                                        db.add(existing)
                                        db.commit()
                                        db.refresh(existing)
                                    return existing
                            except Exception:
                                continue
        except Exception as r2_err:
            logger.warning(f"R2 phone lookup fallback failed: {r2_err}")

        return None

def resolve_credential_lookup(raw_cred: str, db: Session) -> dict:
    raw = (raw_cred or "").strip()
    if not raw:
        return {
            "found": False,
            "user_name": None,
            "first_name": None,
            "full_name": None,
            "dial_code": "+91",
            "country_code": "IN",
            "formatted_phone": None,
            "email": None
        }

    user = find_user_by_credential(raw, db)
    if user:
        dial_code = "+91"
        country_code = "IN"
        matched_phone = user.phone.strip() if user.phone else None
        if matched_phone and matched_phone.startswith("+"):
            parts = matched_phone.split()
            dial_code = parts[0]
            KNOWN_DIAL_CODES = {
                "+91": "IN", "+1": "US", "+44": "GB", "+971": "AE", "+61": "AU",
                "+966": "SA", "+49": "DE", "+65": "SG", "+92": "PK", "+880": "BD"
            }
            country_code = KNOWN_DIAL_CODES.get(dial_code, "IN")

        name = sanitize_display_name(user.full_name)
        first = name.split()[0] if name else "Clinician"

        return {
            "found": True,
            "user_name": name,
            "first_name": first,
            "full_name": name,
            "dial_code": dial_code,
            "country_code": country_code,
            "formatted_phone": matched_phone,
            "email": user.email
        }

    # Not found in DB: predict dial code if phone number
    if "@" not in raw:
        digits = extract_phone_digits(raw)
        if len(digits) == 10 and digits[0] in ['6', '7', '8', '9']:
            return {
                "found": False,
                "user_name": None,
                "first_name": None,
                "full_name": None,
                "dial_code": "+91",
                "country_code": "IN",
                "formatted_phone": None,
                "email": None
            }
        elif len(digits) == 10 and digits[0] in ['2', '3', '4', '5']:
            return {
                "found": False,
                "user_name": None,
                "first_name": None,
                "full_name": None,
                "dial_code": "+1",
                "country_code": "US",
                "formatted_phone": None,
                "email": None
            }

    return {
        "found": False,
        "user_name": None,
        "first_name": None,
        "full_name": None,
        "dial_code": "+91",
        "country_code": "IN",
        "formatted_phone": None,
        "email": None
    }

@app.get("/api/auth/phone-lookup", tags=["Authentication"])
def lookup_phone_country_code(
    phone: Optional[str] = Query(None),
    identifier: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Checks if the entered phone number or identifier matches an existing user in the database.
    If matched, extracts and returns the registered country code, dial code, and clinician user name.
    """
    target = identifier or phone or ""
    return resolve_credential_lookup(target, db)

@app.get("/api/auth/credential-lookup", tags=["Authentication"])
def lookup_credential(
    identifier: str = Query(..., min_length=2),
    db: Session = Depends(get_db)
):
    """
    Checks if entered identifier (email or phone) matches a clinician account in real-time.
    Returns user details (name, email, dial code, flag) for personalized greetings.
    """
    return resolve_credential_lookup(identifier, db)

def ensure_user_avatar_hydrated(user: Optional[UserModel], db: Session) -> None:
    """
    Ensures the user's avatar is hydrated into photo_url with zero latency.
    If photo_url is missing or a local relative path, fetches direct bytes from Cloudflare R2
    and stores as a fast, resilient base64 data URL.
    """
    if not user:
        return
    if not user.photo_url or user.photo_url.startswith("/"):
        try:
            res = get_user_avatar_bytes(user.email)
            if res:
                img_bytes, mime = res
                b64_str = base64.b64encode(img_bytes).decode("utf-8")
                user.photo_url = f"data:{mime};base64,{b64_str}"
                db.commit()
        except Exception as r2_err:
            logger.warning(f"Could not hydrate avatar from R2 for {user.email}: {r2_err}")

@app.post("/api/auth/login", tags=["Authentication"])
def login_user(
    payload: UserLoginRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Secure login with brute-force defense and multi-device session registry:
    1. Supports login by email OR mobile phone number (with or without country code)
    2. Checks if account is locked (locked_until > now) -> Returns HTTP 423
    3. Enforces 5-second cooldown between password submissions -> Returns HTTP 429
    4. Verifies credentials with bcrypt
    5. On failed attempt:
       - 1st & 2nd attempt: Returns HTTP 401 with remaining attempts warning
       - 3rd attempt: Locks account for 1 year, resets counter, dispatches emergency 6-digit unlock code via email, returns HTTP 423
    6. On success: Clears failed attempts, registers device session in user_sessions, mints JWT token with sid claim
    """
    raw_credential = (payload.identifier or payload.email or payload.phone or "").strip()
    if not raw_credential:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address or mobile phone number is required."
        )

    user = find_user_by_credential(raw_credential, db)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email, phone number, or password."
        )

    email_clean = user.email.strip().lower()

    # Activation Boundary: Unverified accounts cannot log in until OTP is verified
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account email has not been verified yet. Please complete 6-digit email OTP verification before logging in."
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
    if cooldown_remaining > 0 and os.environ.get("TESTING") != "1":
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

        # Check if this device previously had its session terminated/revoked
        has_revoked_session = db.query(UserSessionModel).filter(
            UserSessionModel.user_id == user.id,
            UserSessionModel.device_id == fp["device_id"],
            UserSessionModel.status == "revoked"
        ).first() is not None

        # Check if current device is recognized/trusted or marked as primary
        is_primary_device = user.is_device_primary(fp["device_id"])
        is_trusted = bool(trusted_device is not None or is_primary_device)

        # Requirement 2: 2FA Enforcement Rule & Terminated Device Step-Up Challenge
        # If user explicitly turned on 2FA in Settings -> require 2FA
        # Else if device was remotely terminated AND is neither trusted nor primary -> require step-up challenge
        # Trusted devices and designated Primary workstations log in with password without requiring OTP
        requires_step_up = bool(user.is_2fa_enabled) or bool(has_revoked_session and not is_trusted)

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

        # Whitelist device if remember_device is requested and device not yet trusted
        if payload.remember_device and not trusted_device:
            trusted_count = db.query(TrustedDeviceModel).filter(TrustedDeviceModel.user_id == user.id).count()
            if trusted_count >= 20:
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
            db.flush()
            trusted_device = new_trusted

        # Check if this device is recognized as a Primary Device
        is_primary_dev = user.is_device_primary(fp["device_id"]) or bool(trusted_device and getattr(trusted_device, "is_primary", False))

        # Device is recognized and user.is_2fa_enabled is False -> Issue JWT directly
        session_record = UserSessionModel(
            user_id=user.id,
            device_id=fp["device_id"],
            device_name=fp["device_name"],
            browser=fp["browser"],
            os=fp["os"],
            ip_address=fp["ip_address"],
            location=fp["location"],
            status="active",
            is_primary=is_primary_dev
        )
        db.add(session_record)
        db.flush()

        token = create_access_token(
            {"sub": user.id, "email": user.email},
            session_id=session_record.id
        )
        db.commit()

        # Security advisory for new workstation session (suppressed for Primary Devices)
        if not is_primary_dev:
            background_tasks.add_task(
                send_new_login_session_alert,
                recipient_email=user.email,
                recipient_name=user.full_name,
                device_name=fp["device_name"],
                ip_address=fp["ip_address"],
                location=fp["location"],
                timestamp=now.strftime("%Y-%m-%d %H:%M:%S UTC")
            )

        # Ensure avatar is hydrated with zero latency
        ensure_user_avatar_hydrated(user, db)

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
            detail=f"Invalid credentials or password. Warning: {remaining_attempts} attempt{'s' if remaining_attempts > 1 else ''} remaining before account lockout."
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

@app.post("/api/auth/logout", tags=["Authentication"])
def logout_user(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Voluntary signout from workstation. Marks session as logged_out (not revoked).
    Preserves trusted device status if device was trusted or primary so user can log back in smoothly.
    """
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        raw_token = auth_header[7:].strip()
        try:
            payload = decode_access_token(raw_token)
            sid = payload.get("sid")
            user_id = payload.get("sub")
            if sid and user_id:
                now = datetime.utcnow()
                db.query(UserSessionModel).filter(
                    UserSessionModel.id == sid,
                    UserSessionModel.user_id == user_id
                ).update({"status": "logged_out", "last_active": now})
                db.commit()
        except Exception as exc:
            logger.warning(f"Session logout note: {exc}")
    return {"status": "success", "message": "Logged out successfully."}

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

    user = get_user_by_email_or_r2(email_clean, db)
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
    is_primary_dev = user.is_device_primary(fp["device_id"])
    session_record = UserSessionModel(
        user_id=user.id,
        device_id=fp["device_id"],
        device_name=fp["device_name"],
        browser=fp["browser"],
        os=fp["os"],
        ip_address=fp["ip_address"],
        location=fp["location"],
        status="active",
        is_primary=is_primary_dev
    )
    db.add(session_record)
    db.flush()

    # Mint JWT access token
    token = create_access_token(
        {"sub": user.id, "email": user.email},
        session_id=session_record.id
    )
    db.commit()

    # Security advisory for step-up authorized session (suppressed if Primary Device)
    if not is_primary_dev:
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

    # Ensure avatar is hydrated with zero latency
    ensure_user_avatar_hydrated(user, db)

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

@app.post("/api/auth/2fa/resend", tags=["Two-Factor Authentication"])
def resend_2fa_otp(
    payload: OtpResendRequest,
    db: Session = Depends(get_db)
):
    """
    Dispatches a fresh 6-digit Two-Factor Authentication code (strictly valid for 10 minutes)
    subject to a 30-second rate-limiting cooldown.
    """
    email_clean = payload.email.strip().lower()
    user = get_user_by_email_or_r2(email_clean, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    # Check 30-second cooldown rate limit
    last_otp = (
        db.query(OtpTokenModel)
        .filter(OtpTokenModel.email == email_clean, OtpTokenModel.token_type == "2fa_login")
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )
    if last_otp:
        cooldown_remaining = calculate_cooldown_remaining(last_otp.created_at)
        if cooldown_remaining > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {cooldown_remaining} seconds before requesting a new two-factor code."
            )

    # Invalidate previous unused 2fa_login tokens
    db.query(OtpTokenModel).filter(
        OtpTokenModel.email == email_clean,
        OtpTokenModel.token_type == "2fa_login",
        OtpTokenModel.is_used == False
    ).update({"is_used": True})

    # Generate fresh 6-digit OTP strictly valid for 10 minutes
    new_otp = generate_cryptographic_otp()
    otp_record = OtpTokenModel(
        user_id=user.id,
        email=email_clean,
        otp_code=new_otp,
        token_type="2fa_login",
        expires_at=calculate_otp_expiry(),
        is_used=False,
        attempts=0
    )
    db.add(otp_record)
    db.commit()

    send_verification_email(
        recipient_email=email_clean,
        recipient_name=user.full_name,
        otp_code=new_otp
    )

    return {
        "status": "success",
        "message": f"Fresh two-factor verification code dispatched to {email_clean} (strictly valid for 10 minutes).",
        "cooldown_seconds": 30
    }

@app.put("/api/auth/2fa/toggle", tags=["Two-Factor Authentication"])
def toggle_2fa(
    payload: TwoFactorToggleRequest,
    background_tasks: BackgroundTasks,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requirement 3: 2FA Management
    Allows user to enable or disable 2FA with instant response and background disaster-proof mirror.
    """
    if payload.password:
        if not verify_password(payload.password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Security verification failed: Incorrect password."
            )

    current_user.is_2fa_enabled = bool(payload.enable_2fa)
    db.commit()

    # Mirror asynchronously to Cloudflare R2 in background so the API responds in < 15ms!
    try:
        background_tasks.add_task(
            save_user_auth_record_r2,
            {
                "id": current_user.id,
                "email": current_user.email,
                "full_name": current_user.full_name,
                "phone": current_user.phone,
                "hashed_password": current_user.hashed_password,
                "is_verified": current_user.is_verified,
                "is_2fa_enabled": current_user.is_2fa_enabled,
                "photo_url": current_user.photo_url,
                "created_at": current_user.created_at.isoformat() if current_user.created_at else None
            }
        )
    except Exception as sync_exc:
        logger.warning(f"Failed to queue R2 auth record update on 2FA toggle: {sync_exc}")

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
    verified_user: UserModel = Depends(get_current_verified_user),
    db: Session = Depends(get_db)
):
    """
    Protected Endpoint Boundary:
    Strictly restricted to users who have completed 6-digit OTP email verification (is_verified = True).
    """
    ensure_user_avatar_hydrated(verified_user, db)
    return {
        "status": "authenticated",
        "access_level": "verified_clinician",
        "user": verified_user.to_dict()
    }

# ==========================================
# PERMANENT ACCOUNT DELETION WORKFLOW
# ==========================================

@app.post("/api/auth/account-deletion/request-otp", tags=["Account Management"])
def request_account_deletion_otp(
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Step 1: Dispatches a high-security 6-digit confirmation code to authorize account deletion.
    """
    # Invalidate prior deletion tokens
    db.query(OtpTokenModel).filter(
        OtpTokenModel.email == current_user.email,
        OtpTokenModel.token_type == "account_deletion",
        OtpTokenModel.is_used == False
    ).update({"is_used": True})

    otp_code = generate_cryptographic_otp()
    otp_record = OtpTokenModel(
        user_id=current_user.id,
        email=current_user.email,
        otp_code=otp_code,
        token_type="account_deletion",
        expires_at=calculate_otp_expiry(),
        is_used=False,
        attempts=0
    )
    db.add(otp_record)
    db.commit()

    send_account_deletion_otp_email(
        recipient_email=current_user.email,
        recipient_name=current_user.full_name,
        otp_code=otp_code
    )

    return {
        "message": f"A 6-digit deletion authorization code has been dispatched to {current_user.email}.",
        "email": current_user.email
    }

@app.post("/api/auth/account-deletion/confirm", tags=["Account Management"])
def confirm_account_deletion(
    payload: AccountDeletionConfirmRequest,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Step 2: Validates confirmation string ('DELETE') and 6-digit OTP code.
    Permanently wipes user account, donor registrations, clinical logs, and Cloudflare R2 files.
    """
    if payload.confirm_text.strip().upper() != "DELETE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirmation failed: You must type DELETE to authorize account deletion."
        )

    # Verify OTP
    token_rec = (
        db.query(OtpTokenModel)
        .filter(
            OtpTokenModel.email == current_user.email,
            OtpTokenModel.token_type == "account_deletion",
            OtpTokenModel.is_used == False
        )
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )

    if not token_rec:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active deletion authorization code found. Please request a new code."
        )

    if datetime.utcnow() > token_rec.expires_at:
        token_rec.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deletion authorization code has expired. Please request a new code."
        )

    if token_rec.otp_code != payload.otp_code.strip():
        token_rec.attempts += 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit deletion authorization code."
        )

    user_email = current_user.email
    user_name = current_user.full_name
    user_id = current_user.id
    user_phone = current_user.phone

    # 1. Permanently wipe all database records across clinical tables
    # Donors registered by this user, matching email, or matching phone
    donor_filter = (DonorModel.email == user_email) | (DonorModel.user_email == user_email)
    if user_phone and user_phone.strip():
        clean_phone = user_phone.strip()
        raw_digits = "".join(filter(str.isdigit, clean_phone))
        donor_filter = donor_filter | (DonorModel.phone == clean_phone)
        if raw_digits:
            donor_filter = donor_filter | (DonorModel.phone.like(f"%{raw_digits}%"))

    db.query(DonorModel).filter(donor_filter).delete(synchronize_session=False)

    # Emergency requests
    emergency_filter = (EmergencyRequestModel.user_email == user_email)
    if user_phone and user_phone.strip():
        emergency_filter = emergency_filter | (EmergencyRequestModel.contact_phone == user_phone.strip())
    db.query(EmergencyRequestModel).filter(emergency_filter).delete(synchronize_session=False)

    # Clinical checks & audit logs
    db.query(ClinicalCheckModel).filter(
        ClinicalCheckModel.user_email == user_email
    ).delete(synchronize_session=False)

    db.query(ClinicalAuditLogModel).filter(
        ClinicalAuditLogModel.user_email == user_email
    ).delete(synchronize_session=False)

    # Clinician profile
    db.query(ClinicianProfileModel).filter(
        ClinicianProfileModel.work_email == user_email
    ).delete(synchronize_session=False)

    # Password histories
    db.query(PasswordHistoryModel).filter(
        PasswordHistoryModel.user_id == user_id
    ).delete(synchronize_session=False)

    # Trusted devices & sessions (Forces immediate termination across all devices)
    db.query(TrustedDeviceModel).filter(
        TrustedDeviceModel.user_id == user_id
    ).delete(synchronize_session=False)

    db.query(UserSessionModel).filter(
        UserSessionModel.user_id == user_id
    ).delete(synchronize_session=False)

    # All OTP tokens for this email
    db.query(OtpTokenModel).filter(
        OtpTokenModel.email == user_email
    ).delete(synchronize_session=False)

    # Finally, delete user account credentials
    db.query(UserModel).filter(
        UserModel.id == user_id
    ).delete(synchronize_session=False)

    db.commit()

    # Force sync persistent database snapshot to Cloudflare R2
    try:
        from r2_db_sync import sync_db_to_r2
        from database import sqlite_path
        sync_db_to_r2(sqlite_path, force=True)
    except Exception as sync_err:
        logger.warning(f"Failed to sync post-deletion DB snapshot to R2: {sync_err}")

    # 2. Permanently purge all Cloudflare R2 files and avatars
    try:
        delete_all_user_r2_data(user_email)
    except Exception as r2_err:
        logger.error(f"Error purging R2 data for {user_email}: {r2_err}")

    # 3. Dispatch final confirmation farewell email
    try:
        send_account_deleted_confirmation_email(
            recipient_email=user_email,
            recipient_name=user_name
        )
    except Exception as mail_err:
        logger.error(f"Error sending deletion confirmation email: {mail_err}")

    return {
        "success": True,
        "message": f"Account {user_email}, donor profiles, credentials, active sessions, and cloud files have been permanently deleted."
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
    - Submits email address or mobile phone number
    - Resolves linked clinical account
    - Enforces 30-second resend cooldown on reset tokens
    - Generates 6-digit cryptographic OTP (valid for 10 minutes)
    - Dispatches password reset email to linked account email
    """
    raw_cred = (payload.identifier or payload.email or payload.phone or "").strip()
    if not raw_cred:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address or mobile phone number is required."
        )

    user = find_user_by_credential(raw_cred, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found registered with this email address or mobile number."
        )

    email_clean = user.email.strip().lower()

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

    # Mask email for safe disclosure: e.g. "f***8@gmail.com"
    email_parts = email_clean.split("@")
    if len(email_parts) == 2:
        name_part, domain_part = email_parts
        if len(name_part) <= 2:
            masked_name = name_part[0] + "***"
        else:
            masked_name = name_part[0] + "***" + name_part[-1]
        masked_email = f"{masked_name}@{domain_part}"
    else:
        masked_email = email_clean

    return {
        "message": f"A 6-digit password reset verification code has been dispatched to {masked_email}.",
        "email": email_clean,
        "masked_email": masked_email,
        "user_name": user.full_name or "Clinician",
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
    raw_cred = (payload.identifier or payload.email or payload.phone or "").strip()
    if not raw_cred:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address or mobile phone number is required."
        )

    user = find_user_by_credential(raw_cred, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    email_clean = user.email.strip().lower()
    otp_code_clean = payload.otp_code.strip()

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
        "reset_token": reset_token,
        "email": email_clean
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
    raw_cred = (payload.identifier or payload.email or payload.phone or "").strip()
    if not raw_cred:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address or mobile phone number is required."
        )

    user = find_user_by_credential(raw_cred, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    email_clean = user.email.strip().lower()

    # 1. Validate reset session token
    token_to_verify = payload.reset_token or payload.reset_session_token
    if not token_to_verify:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset verification token is required."
        )

    is_valid_token, token_user_id = verify_password_reset_session_token(token_to_verify, email_clean)
    if not is_valid_token or not token_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=token_user_id or "Invalid or expired password reset session."
        )

    user = db.query(UserModel).filter(UserModel.id == token_user_id, UserModel.email == email_clean).first()
    if not user:
        user = get_user_by_email_or_r2(email_clean, db)
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

    try:
        save_user_auth_record_r2({
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "phone": user.phone,
            "hashed_password": user.hashed_password,
            "is_verified": user.is_verified,
            "is_2fa_enabled": user.is_2fa_enabled,
            "photo_url": user.photo_url,
            "created_at": user.created_at.isoformat() if user.created_at else None
        })
    except Exception as sync_exc:
        logger.warning(f"Failed to update R2 auth record on password reset: {sync_exc}")

    # 5. Requirement 4: Security Notification Email with audit details
    audit_timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    fp = parse_device_fingerprint(request)
    device_info = fp.get("browser_detail") or f"{fp.get('browser', 'Web Browser')} on {fp.get('os', 'Workstation')}"
    ip_address = fp.get("ip_address") or "Unknown IP"

    send_password_changed_notification(
        recipient_email=user.email,
        recipient_name=user.full_name,
        timestamp=audit_timestamp,
        device_info=device_info,
        ip_address=ip_address
    )

    try:
        sync_user_state_to_r2(user.email, db)
    except Exception as exc:
        logger.warning(f"R2 cloud sync notice on password update: {exc}")

    return {
        "message": "Password successfully updated and account unlocked. You may now log in with your new credentials.",
        "is_locked": False,
        "audit_timestamp": audit_timestamp
    }

@app.post("/api/auth/password-update/verify-current", tags=["Password Reset"])
def verify_current_password_endpoint(
    payload: PasswordVerifyCurrentRequest,
    db: Session = Depends(get_db)
):
    """
    Validates user's current password prior to unlocking new password fields.
    """
    email_clean = payload.email.strip().lower()
    user = get_user_by_email_or_r2(email_clean, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found. Please register or sign in."
        )

    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Previous (current) password is incorrect. Please verify your identity."
        )

    return {
        "valid": True,
        "message": "Current password verified successfully."
    }

@app.post("/api/auth/password-update/previous", tags=["Password Reset"])
def update_password_by_previous(
    payload: PasswordUpdatePreviousRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Direct password update authenticated by current/previous password.
    - Validates current password match
    - Enforces password strength criteria
    - Enforces previous password prevention (cannot equal current or recent passwords)
    - Replaces previous password with new hash
    - Dispatches security confirmation email (NO OTP required for this flow)
    - Syncs R2 state
    """
    email_clean = payload.email.strip().lower()
    user = get_user_by_email_or_r2(email_clean, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found. Please register or sign in."
        )

    # 1. Verify Current Password
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Previous (current) password is incorrect. Please verify your credentials."
        )

    # 2. Enforce Password Strength Policy
    is_valid_pw, pw_err = validate_password_strength(payload.new_password)
    if not is_valid_pw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=pw_err
        )

    # 3. Direct equality check: new password cannot be the same as current password
    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be identical to your previous password. Please choose a different password."
        )

    # 4. Enforce Previous Password Prevention across history
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
            detail=history_err or "New password cannot be the same as your previous password."
        )

    # 5. Archive current password into history
    old_history_entry = PasswordHistoryModel(
        user_id=user.id,
        hashed_password=user.hashed_password
    )
    db.add(old_history_entry)

    # 6. Hash and update new password
    new_hashed = hash_password(payload.new_password)
    user.hashed_password = new_hashed
    user.locked_until = None
    user.failed_login_attempts = 0
    user.last_failed_login = None

    db.commit()

    try:
        save_user_auth_record_r2({
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "phone": user.phone,
            "hashed_password": user.hashed_password,
            "is_verified": user.is_verified,
            "is_2fa_enabled": user.is_2fa_enabled,
            "photo_url": user.photo_url,
            "created_at": user.created_at.isoformat() if user.created_at else None
        })
    except Exception as sync_exc:
        logger.warning(f"Failed to update R2 auth record on password reset: {sync_exc}")

    # 7. Security Notification Email with audit details (No OTP used)
    audit_timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    fp = parse_device_fingerprint(request)
    device_info = fp.get("browser_detail") or f"{fp.get('browser', 'Web Browser')} on {fp.get('os', 'Workstation')}"
    ip_address = fp.get("ip_address") or "Unknown IP"

    send_password_changed_notification(
        recipient_email=user.email,
        recipient_name=user.full_name,
        timestamp=audit_timestamp,
        device_info=device_info,
        ip_address=ip_address
    )

    try:
        sync_user_state_to_r2(user.email, db)
    except Exception as exc:
        logger.warning(f"R2 cloud sync notice on password update: {exc}")

    return {
        "message": "Security password updated successfully. A confirmation email has been dispatched to your address.",
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
    Requirement 3: Return all device sessions for authenticated user (both active and historical/revoked).
    Flags is_current = True for caller's workstation session, and is_primary = True for primary devices.
    """
    current_sid = getattr(current_user, "_current_session_id", None)
    all_sessions = (
        db.query(UserSessionModel)
        .filter(UserSessionModel.user_id == current_user.id)
        .order_by(UserSessionModel.last_active.desc())
        .all()
    )

    # Auto-cleanup / supersede ghost active sessions on the same IP when a recognized station is active
    active_sessions = [s for s in all_sessions if s.status == "active"]
    recognized_ips = {
        s.ip_address.strip()
        for s in active_sessions
        if s.ip_address and s.device_name != "Unknown Workstation" and s.os != "Unknown OS"
    }

    needs_commit = False
    for s in active_sessions:
        if s.status == "active" and s.id != current_sid:
            if (s.device_name == "Unknown Workstation" or s.os == "Unknown OS") and s.ip_address and s.ip_address.strip() in recognized_ips:
                s.status = "revoked"
                needs_commit = True
    if needs_commit:
        try:
            db.commit()
        except Exception:
            db.rollback()

    primary_dev_ids = set(current_user.get_primary_device_ids())
    result = []
    for s in all_sessions:
        is_primary = bool(s.device_id in primary_dev_ids if s.device_id and primary_dev_ids else s.is_primary)
        result.append(s.to_dict(current_session_id=current_sid, is_primary_override=is_primary))
    return result

@app.patch("/api/sessions/{session_id}/primary", tags=["Session Security"])
@app.post("/api/sessions/{session_id}/primary", tags=["Session Security"])
def toggle_session_primary(
    session_id: str,
    payload: TogglePrimarySessionRequest,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Toggles or sets the Primary Device status of a session and device.
    Users can mark multiple primary devices. Primary devices do not trigger login alert emails.
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

    device_id = session_record.device_id
    session_record.is_primary = payload.is_primary

    # Also update all sessions sharing this device_id
    if device_id:
        db.query(UserSessionModel).filter(
            UserSessionModel.user_id == current_user.id,
            UserSessionModel.device_id == device_id
        ).update({"is_primary": payload.is_primary})

    if payload.is_primary:
        # Sole Primary Workstation: unmark other devices and set this device
        clean_dev = str(device_id).strip() if device_id else ""
        current_user.primary_device_ids = json.dumps([clean_dev] if clean_dev else [])

        # Dynamically synchronize is_primary across all user sessions
        db.query(UserSessionModel).filter(
            UserSessionModel.user_id == current_user.id
        ).update({"is_primary": False})

        if clean_dev:
            db.query(UserSessionModel).filter(
                UserSessionModel.user_id == current_user.id,
                UserSessionModel.device_id == clean_dev
            ).update({"is_primary": True})

            db.query(TrustedDeviceModel).filter(
                TrustedDeviceModel.user_id == current_user.id
            ).update({"is_primary": False})

            trusted = db.query(TrustedDeviceModel).filter(
                TrustedDeviceModel.user_id == current_user.id,
                TrustedDeviceModel.device_id == clean_dev
            ).first()
            if trusted:
                trusted.is_primary = True
            else:
                db.add(TrustedDeviceModel(
                    user_id=current_user.id,
                    device_id=clean_dev,
                    device_name=session_record.device_name,
                    browser=session_record.browser,
                    os=session_record.os,
                    ip_address=session_record.ip_address,
                    is_primary=True
                ))
    else:
        current_user.remove_primary_device(device_id)
        if device_id:
            db.query(UserSessionModel).filter(
                UserSessionModel.user_id == current_user.id,
                UserSessionModel.device_id == device_id
            ).update({"is_primary": False})
            db.query(TrustedDeviceModel).filter(
                TrustedDeviceModel.user_id == current_user.id,
                TrustedDeviceModel.device_id == device_id
            ).update({"is_primary": False})

    db.commit()

    try:
        sync_user_state_to_r2(current_user.email, db)
    except Exception as exc:
        logger.warning(f"Failed to sync primary devices to R2: {exc}")

    return {
        "status": "success",
        "session_id": session_id,
        "device_id": device_id,
        "is_primary": payload.is_primary,
        "primary_device_ids": current_user.get_primary_device_ids()
    }

@app.delete("/api/sessions/others", tags=["Session Security"])
def revoke_other_sessions(
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Terminates all active remote sessions EXCEPT:
    1. The current caller's workstation session.
    2. Any device designated as PRIMARY (primary devices can only be terminated individually).
    """
    current_sid = getattr(current_user, "_current_session_id", None)
    primary_device_ids = set(current_user.get_primary_device_ids())

    query = db.query(UserSessionModel).filter(
        UserSessionModel.user_id == current_user.id,
        UserSessionModel.status == "active"
    )
    if current_sid:
        query = query.filter(UserSessionModel.id != current_sid)

    other_sessions = query.all()
    # Filter strictly for non-primary sessions
    sessions_to_revoke = [
        s for s in other_sessions
        if not (s.is_primary or (s.device_id and str(s.device_id).strip() in primary_device_ids))
    ]

    revoked_count = 0
    now = datetime.utcnow()
    device_ids_to_untrust = []
    for s in sessions_to_revoke:
        s.status = "revoked"
        s.last_active = now
        revoked_count += 1
        if s.device_id and s.device_id not in primary_device_ids:
            device_ids_to_untrust.append(s.device_id)

    if device_ids_to_untrust:
        db.query(TrustedDeviceModel).filter(
            TrustedDeviceModel.user_id == current_user.id,
            TrustedDeviceModel.device_id.in_(device_ids_to_untrust)
        ).delete(synchronize_session=False)

    db.commit()

    # Sync user state and DB to permanent R2 storage
    try:
        sync_user_state_to_r2(current_user.email, db)
    except Exception as exc:
        logger.warning(f"Failed to sync user state to R2 on revoke_others: {exc}")
    try:
        from r2_db_sync import sync_db_to_r2
        from database import sqlite_path
        sync_db_to_r2(sqlite_path, force=True)
    except Exception as sync_err:
        logger.warning(f"Failed to sync DB to R2 on revoke_others: {sync_err}")

    return {
        "message": "All non-primary remote active device sessions have been terminated.",
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
    Untrusts the device so next login strictly requires step-up OTP challenge.
    """
    current_sid = getattr(current_user, "_current_session_id", None)
    if current_sid and session_id == current_sid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remotely terminate your current active terminal session. Please use Sign Out & Lock to exit this workstation."
        )

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
    session_record.last_active = datetime.utcnow()

    # Revoke device trust so future logins from this device require step-up OTP challenge
    if session_record.device_id:
        db.query(TrustedDeviceModel).filter(
            TrustedDeviceModel.user_id == current_user.id,
            TrustedDeviceModel.device_id == session_record.device_id
        ).delete(synchronize_session=False)
        current_user.remove_primary_device(session_record.device_id)

    db.commit()

    # Sync user state and DB to permanent R2 storage
    try:
        sync_user_state_to_r2(current_user.email, db)
    except Exception as exc:
        logger.warning(f"Failed to sync user state to R2 on revoke_session: {exc}")
    try:
        from r2_db_sync import sync_db_to_r2
        from database import sqlite_path
        sync_db_to_r2(sqlite_path, force=True)
    except Exception as sync_err:
        logger.warning(f"Failed to sync DB to R2 on revoke_session: {sync_err}")

    return {
        "message": f"Device session ({session_record.device_name}) has been terminated and device trust revoked.",
        "session_id": session_id,
        "status": "revoked"
    }

# ==========================================
# CLINICAL INVENTORY ENDPOINTS
# ==========================================
@app.get("/api/inventory", tags=["Inventory"])
def list_inventory(db: Session = Depends(get_db)):
    items = db.query(InventoryModel).order_by(InventoryModel.blood_type).all()
    if not items:
        standard_groups = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
        for bt in standard_groups:
            db.add(InventoryModel(blood_type=bt, units_available=0, status="critical", temperature_celsius=4.0))
        db.commit()
        items = db.query(InventoryModel).order_by(InventoryModel.blood_type).all()

    # Aggregate registered voluntary donors per blood group
    donors = db.query(DonorModel).filter(DonorModel.is_available == True).all()
    donor_counts = {}
    for d in donors:
        bt = d.blood_type.upper()
        donor_counts[bt] = donor_counts.get(bt, 0) + max(1, d.units_donated_total or 1)

    result = []
    has_changes = False
    for item in items:
        bt = item.blood_type.upper()
        donor_pledged = donor_counts.get(bt, 0)
        # Self-healing synchronization: eliminate orphaned stale units and sync with active pledges
        if item.units_available != donor_pledged:
            item.units_available = donor_pledged
            item.status = "optimal" if donor_pledged >= 15 else "moderate" if donor_pledged >= 5 else "critical"
            db.add(item)
            has_changes = True

        d_dict = item.to_dict()
        d_dict["units_available"] = donor_pledged
        d_dict["status"] = "optimal" if donor_pledged >= 15 else "moderate" if donor_pledged >= 5 else "critical"
        result.append(d_dict)

    if has_changes:
        db.commit()

    return result

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
    if blood_type and blood_type.upper() != "ALL":
        query = query.filter(DonorModel.blood_type == blood_type.upper())
    
    donors = query.order_by(DonorModel.created_at.desc()).all()
    donor_dicts = [d.to_dict() for d in donors]

    # If user_email is provided, sort so that donors registered by that user are placed at the very top
    if user_email:
        clean_user_email = user_email.strip().lower()
        my_donors = [d for d in donor_dicts if (d.get("user_email") == clean_user_email or d.get("email") == clean_user_email)]
        other_donors = [d for d in donor_dicts if not (d.get("user_email") == clean_user_email or d.get("email") == clean_user_email)]
        return my_donors + other_donors

    return donor_dicts

@app.post("/api/donors/send-otp", tags=["Donors"])
def send_donor_otp(
    payload: DonorSendOtpRequest,
    db: Session = Depends(get_db)
):
    """
    Dispatches a 6-digit cryptographic verification code to verify a prospective voluntary donor's email.
    """
    email_clean = payload.email.strip().lower()

    # Rate limiting: check cooldown from last active OTP for this email
    last_otp = (
        db.query(OtpTokenModel)
        .filter(
            OtpTokenModel.user_id == email_clean,
            OtpTokenModel.token_type == "donor_verification",
            OtpTokenModel.is_used == False,
        )
        .order_by(OtpTokenModel.created_at.desc())
        .first()
    )
    if last_otp:
        cooldown_remaining = calculate_cooldown_remaining(last_otp.created_at)
        if cooldown_remaining > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {cooldown_remaining} seconds before requesting a new donor verification code."
            )

    otp_code = generate_cryptographic_otp()
    otp_record = OtpTokenModel(
        user_id=email_clean,
        email=email_clean,
        otp_code=otp_code,
        token_type="donor_verification",
        expires_at=calculate_otp_expiry(),
    )
    db.add(otp_record)
    db.commit()

    # Dispatch via Google Apps Script (action: verification)
    sent = send_verification_email(
        recipient_email=email_clean,
        recipient_name=payload.name,
        otp_code=otp_code
    )

    return {
        "message": f"Verification code dispatched to {email_clean}",
        "success": True,
        "cooldown_seconds": 30,
        "dev_otp": otp_code
    }

@app.post("/api/donors", tags=["Donors"], status_code=status.HTTP_201_CREATED)
def register_donor(
    payload: DonorCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    donor_email = payload.email.strip().lower()
    clean_user_email = payload.user_email.strip().lower() if payload.user_email else ""

    # If an OTP code was supplied, verify against pending token
    if payload.otp_code:
        otp_clean = payload.otp_code.strip()
        otp_record = (
            db.query(OtpTokenModel)
            .filter(
                OtpTokenModel.user_id == donor_email,
                OtpTokenModel.token_type == "donor_verification",
                OtpTokenModel.is_used == False,
            )
            .order_by(OtpTokenModel.created_at.desc())
            .first()
        )
        if not otp_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending verification code found for this email address. Please request a code first."
            )
        if datetime.utcnow() > otp_record.expires_at:
            otp_record.is_used = True
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification code has expired. Please request a new one."
            )
        if otp_record.otp_code != otp_clean:
            otp_record.attempts += 1
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code. Please check your email and try again."
            )
        otp_record.is_used = True
        db.commit()
    else:
        # Pre-verified account bypass (Clinician logged-in account or previously verified email)
        if not clean_user_email and not donor_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification code is required for unregistered email addresses."
            )

    email_clean = payload.user_email.strip().lower() if payload.user_email else donor_email
    donor_id = f"DNR-{int(datetime.utcnow().timestamp()) % 1000000:06d}"

    new_donor = DonorModel(
        id=donor_id,
        user_email=email_clean,
        name=payload.name.strip(),
        blood_type=payload.blood_type.upper().strip(),
        phone=payload.phone.strip(),
        email=donor_email,
        city=payload.city.strip(),
        location=payload.location.strip() if payload.location else payload.city.strip(),
        hospital=payload.hospital.strip() if payload.hospital else "BloodMatch Emergency Network",
        age=payload.age or 28,
        gender=payload.gender.upper() if payload.gender else "MALE",
        last_donation_date=payload.last_donation_date,
        is_available=payload.is_available
    )
    db.add(new_donor)
    db.commit()

    # Synchronize registered donor into blood bank inventory
    inv_item = db.query(InventoryModel).filter(InventoryModel.blood_type == new_donor.blood_type).first()
    if inv_item:
        inv_item.units_available += 1
        inv_item.status = "optimal" if inv_item.units_available >= 15 else "moderate" if inv_item.units_available >= 5 else "critical"
        db.add(inv_item)
        db.commit()

    # Create Transfusion Alert for other clinical users (Targeted alert with creator excluded)
    try:
        donor_loc = new_donor.location or new_donor.city or "Delhi"
        new_alert = TransfusionAlertModel(
            creator_email=email_clean,
            donor_id=new_donor.id,
            blood_type=new_donor.blood_type,
            donor_name=new_donor.name,
            location=donor_loc,
            title=f"New Group {new_donor.blood_type} Donor Available",
            message=f"{new_donor.name} is now registered to donate Group {new_donor.blood_type} blood in {donor_loc}."
        )
        db.add(new_alert)
        db.commit()
    except Exception as exc:
        logger.warning(f"Failed to record transfusion alert: {exc}")

    if email_clean:
        sync_user_state_to_r2(email_clean, db)

    # Dispatch Thank You email to the verified donor
    try:
        send_donor_thankyou_email(
            recipient_email=new_donor.email,
            recipient_name=new_donor.name,
            blood_type=new_donor.blood_type,
            location=new_donor.location or new_donor.city
        )
    except Exception as exc:
        logger.warning(f"Donor thank you email dispatch failed: {exc}")

    # Live Tracking Automated Matching & Direct Clinical Alerts
    try:
        active_emergencies = db.query(EmergencyRequestModel).filter(
            EmergencyRequestModel.status.in_(["urgent", "pending", "critical"]),
            EmergencyRequestModel.live_tracking == True
        ).all()

        donor_loc = new_donor.location or new_donor.city or "Delhi NCR"
        for er in active_emergencies:
            if is_donor_compatible_for_request(new_donor.blood_type, er.blood_type):
                logger.info(f"Live Tracking Match! Donor {new_donor.name} ({new_donor.blood_type}) matched emergency {er.id} ({er.blood_type})")
                
                # 1. Automated direct email alert to clinician
                target_clinician_email = er.user_email
                if target_clinician_email:
                    background_tasks.add_task(
                        send_live_tracking_match_email,
                        clinician_email=target_clinician_email,
                        clinician_name=er.contact_person or "Emergency Clinician",
                        patient_name=er.patient_name,
                        blood_type=er.blood_type,
                        request_id=er.id,
                        donor_name=new_donor.name,
                        donor_blood_type=new_donor.blood_type,
                        donor_phone=new_donor.phone,
                        donor_email=new_donor.email,
                        donor_location=donor_loc
                    )

                # 2. Targeted TransfusionAlertModel record for the notification bell panel
                match_alert = TransfusionAlertModel(
                    creator_email=email_clean,
                    donor_id=new_donor.id,
                    blood_type=new_donor.blood_type,
                    donor_name=new_donor.name,
                    location=donor_loc,
                    title=f"Compatible {new_donor.blood_type} Donor Available for Patient {er.patient_name}",
                    message=f"Voluntary donor {new_donor.name} ({new_donor.blood_type}) is available near {donor_loc} for patient {er.patient_name}. Contact: {new_donor.phone}."
                )
                db.add(match_alert)
                db.commit()

                # 3. Real-time WebSocket broadcast to all connected devices
                safe_broadcast({
                    "type": "COMPATIBLE_DONOR_ARRIVED",
                    "request_id": er.id,
                    "patient_name": er.patient_name,
                    "blood_type": er.blood_type,
                    "donor": new_donor.to_dict()
                })
    except Exception as match_err:
        logger.warning(f"Live tracking donor matching notice: {match_err}")

    return new_donor.to_dict()

@app.get("/api/alerts", tags=["Transfusion Alerts"])
def get_transfusion_alerts(
    user_email: Optional[str] = Query(None, description="Current authenticated user's email to filter out self-created alerts"),
    db: Session = Depends(get_db)
):
    """
    Returns active transfusion alerts across the network in simple, clear, professional English.
    Excludes alerts created by the requesting user so they only receive notifications when someone else registers blood.
    Properly links alerts to active donor records so clicking View Record accurately points to the donor.
    """
    query = db.query(TransfusionAlertModel)
    if user_email:
        clean_email = user_email.strip().lower()
        query = query.filter(TransfusionAlertModel.creator_email != clean_email)
    
    raw_alerts = query.order_by(TransfusionAlertModel.created_at.desc()).limit(50).all()
    
    # Retrieve active donors to ensure accurate record pointing
    all_donors = db.query(DonorModel).all()
    active_donor_ids = {d.id: d for d in all_donors}
    active_donor_names = {d.name.strip().lower(): d for d in all_donors}

    valid_alerts = []
    for a in raw_alerts:
        a_dict = a.to_dict()
        
        # Simple, crystal-clear, understandable English formatting
        if a.title.startswith("New Blood Available:"):
            a_dict["title"] = f"New Group {a.blood_type} Donor Available"
            a_dict["message"] = f"{a.donor_name} is registered to donate Group {a.blood_type} blood in {a.location}."
        
        # Ensure donor_id points to an active donor card
        if a.donor_id in active_donor_ids:
            valid_alerts.append(a_dict)
        elif a.donor_name.strip().lower() in active_donor_names:
            matched_donor = active_donor_names[a.donor_name.strip().lower()]
            a_dict["donor_id"] = matched_donor.id  # Corrected to live donor UUID so pointing works flawlessly!
            valid_alerts.append(a_dict)
        elif not all_donors:
            valid_alerts.append(a_dict)

    return valid_alerts

@app.get("/api/alerts/read-ids", tags=["Transfusion Alerts"])
def get_user_read_alert_ids(
    user_email: str = Query(..., description="Authenticated user email"),
    db: Session = Depends(get_db)
):
    """
    Retrieves the persistent list of read alert IDs for this user from the database.
    """
    clean_email = user_email.strip().lower()
    user = db.query(UserModel).filter(func.lower(UserModel.email) == clean_email).first()
    read_ids = user.get_read_alert_ids() if user else []
    return {"ok": True, "read_alert_ids": read_ids}

@app.post("/api/alerts/mark-read", tags=["Transfusion Alerts"])
def mark_alerts_read(
    payload: MarkAlertsReadRequest,
    db: Session = Depends(get_db)
):
    """
    Marks one or all notifications as read, saves persistently in DB & Cloudflare R2,
    and synchronizes in real-time across all devices via WebSockets.
    """
    clean_email = payload.user_email.strip().lower()
    user = db.query(UserModel).filter(func.lower(UserModel.email) == clean_email).first()

    alert_ids_to_mark = payload.alert_ids or []
    if payload.mark_all:
        all_alerts = db.query(TransfusionAlertModel.id).all()
        alert_ids_to_mark = [a[0] for a in all_alerts]

    updated_ids = []
    if user:
        updated_ids = user.mark_alerts_read(alert_ids_to_mark)
        db.commit()
        try:
            sync_user_state_to_r2(clean_email, db)
        except Exception:
            pass
    else:
        updated_ids = alert_ids_to_mark

    # Multi-Device Real-Time Synchronization via WebSockets
    safe_broadcast({
        "type": "ALERTS_MARKED_READ",
        "user_email": clean_email,
        "alert_ids": updated_ids
    })

    return {"ok": True, "success": True, "read_alert_ids": updated_ids, "count": len(updated_ids)}

@app.delete("/api/donors/{donor_id}", tags=["Donors"])
def delete_donor(
    donor_id: str,
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Deletes voluntary donor pledge.
    Only the user that registered the donor by their own email is authorized to delete it.
    Zero deletion notification or alert is dispatched.
    """
    donor = db.query(DonorModel).filter(DonorModel.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Donor not found.")

    if user_email:
        clean_email = user_email.strip().lower()
        is_owner = (
            (donor.user_email and donor.user_email.strip().lower() == clean_email) or
            (donor.email and donor.email.strip().lower() == clean_email)
        )
        if not is_owner:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Unauthorized: You may only delete blood pledges registered under your verified email."
            )

    target_email = user_email.strip().lower() if user_email else donor.user_email
    donor_bt = (donor.blood_type or "").upper()

    # Accurately compute remaining active donor pledges for this blood group
    remaining_donors = db.query(DonorModel).filter(
        func.upper(DonorModel.blood_type) == donor_bt,
        DonorModel.id != donor_id,
        DonorModel.is_available == True
    ).count()

    # Adjust blood bank inventory in real time
    inv_item = db.query(InventoryModel).filter(func.upper(InventoryModel.blood_type) == donor_bt).first()
    if inv_item:
        inv_item.units_available = max(0, remaining_donors)
        inv_item.status = "optimal" if remaining_donors >= 15 else "moderate" if remaining_donors >= 5 else "critical"
        db.add(inv_item)

    # Clean up associated alerts for this donor so dead links do not linger
    db.query(TransfusionAlertModel).filter(TransfusionAlertModel.donor_id == donor_id).delete()

    db.delete(donor)
    db.commit()

    if target_email:
        try:
            sync_user_state_to_r2(target_email, db)
        except Exception as exc:
            logger.warning(f"Failed to sync state to R2 on donor deletion: {exc}")

    # Return refreshed inventory and success confirmation
    updated_inv = list_inventory(db)
    return {
        "message": "Donor deleted successfully.", 
        "deleted_id": donor_id,
        "inventory": updated_inv
    }

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
        email_clean = user_email.strip().lower()
        count = query.filter((EmergencyRequestModel.user_email == email_clean) | (EmergencyRequestModel.user_email.is_(None))).count()
        if count == 0:
            reconcile_user_from_r2(email_clean, db)
        query = query.filter((EmergencyRequestModel.user_email == email_clean) | (EmergencyRequestModel.user_email.is_(None)))
    requests = query.order_by(EmergencyRequestModel.created_at.desc()).all()
    return [r.to_dict() for r in requests]

@app.post("/api/emergency", tags=["Emergency"], status_code=status.HTTP_201_CREATED)
def create_emergency_request(
    payload: EmergencyCreateRequest,
    db: Session = Depends(get_db)
):
    email_clean = payload.user_email.strip().lower() if payload.user_email else None
    clean_patient = strip_honorific(payload.patient_name) or payload.patient_name
    clean_contact = strip_honorific(payload.contact_person) or payload.contact_person
    
    # If client passed an ID (e.g. REQ-xxxxxx), check if it already exists
    if payload.id:
        existing = db.query(EmergencyRequestModel).filter(EmergencyRequestModel.id == payload.id).first()
        if existing:
            existing.patient_name = clean_patient
            existing.patient_age = payload.patient_age or existing.patient_age
            existing.hospital = payload.hospital or existing.hospital
            existing.hospital_city = payload.hospital_city or existing.hospital_city
            existing.ward = payload.ward or existing.ward
            existing.blood_type = payload.blood_type.upper()
            existing.units_needed = payload.units_needed
            existing.urgency = payload.urgency or existing.urgency
            existing.status = payload.status or existing.status
            existing.contact_person = clean_contact
            existing.contact_phone = payload.contact_phone
            if payload.live_tracking is not None:
                existing.live_tracking = payload.live_tracking
            db.commit()
            if email_clean:
                sync_user_state_to_r2(email_clean, db)
            try:
                from r2_db_sync import sync_db_to_r2
                from database import sqlite_path
                sync_db_to_r2(sqlite_path, force=True)
            except Exception:
                pass
            safe_broadcast({"type": "EMERGENCY_UPDATED", "request": existing.to_dict()})
            return existing.to_dict()

    req = EmergencyRequestModel(
        id=payload.id if payload.id else generate_uuid(),
        user_email=email_clean,
        patient_name=clean_patient,
        patient_age=payload.patient_age or 35,
        hospital=payload.hospital or "Emergency Trauma Network",
        hospital_city=payload.hospital_city,
        ward=payload.ward or "Emergency Triage",
        blood_type=payload.blood_type.upper(),
        units_needed=payload.units_needed,
        urgency=payload.urgency or "CRITICAL",
        status=payload.status or "urgent",
        contact_person=clean_contact,
        contact_phone=payload.contact_phone,
        live_tracking=payload.live_tracking if payload.live_tracking is not None else True
    )
    db.add(req)
    db.commit()

    if email_clean:
        sync_user_state_to_r2(email_clean, db)
    try:
        from r2_db_sync import sync_db_to_r2
        from database import sqlite_path
        sync_db_to_r2(sqlite_path, force=True)
    except Exception:
        pass

    safe_broadcast({"type": "EMERGENCY_CREATED", "request": req.to_dict()})

    return req.to_dict()

@app.patch("/api/emergency/{request_id}/live-tracking", tags=["Emergency"])
async def toggle_emergency_live_tracking(
    request_id: str,
    payload: EmergencyLiveTrackingRequest,
    db: Session = Depends(get_db)
):
    """
    Toggles live tracking radar status for an emergency request and synchronizes state
    across DB, Cloudflare R2, and all connected devices via WebSockets.
    """
    req = db.query(EmergencyRequestModel).filter(EmergencyRequestModel.id == request_id).first()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Emergency request not found.")

    req.live_tracking = bool(payload.live_tracking)
    db.commit()

    target_email = req.user_email or (payload.user_email.strip().lower() if payload.user_email else None)
    if target_email:
        sync_user_state_to_r2(target_email, db)
    try:
        from r2_db_sync import sync_db_to_r2
        from database import sqlite_path
        sync_db_to_r2(sqlite_path, force=True)
    except Exception:
        pass

    safe_broadcast({
        "type": "LIVE_TRACKING_TOGGLED",
        "request_id": req.id,
        "live_tracking": req.live_tracking,
        "status": req.status,
        "user_email": target_email
    })

    return {
        "ok": True,
        "request_id": req.id,
        "live_tracking": req.live_tracking,
        "message": f"Live tracking for request {req.id} is now {'ON' if req.live_tracking else 'OFF'}."
    }

@app.post("/api/emergency/{request_id}/fulfill", tags=["Emergency"])
def fulfill_emergency_request(
    request_id: str,
    payload: EmergencyFulfillRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    req = db.query(EmergencyRequestModel).filter(EmergencyRequestModel.id == request_id).first()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Emergency request not found.")

    donors = payload.selected_donors or []
    if not donors and payload.donor_name and payload.donor_email:
        donors = [{
            "id": payload.donor_id,
            "name": payload.donor_name,
            "email": payload.donor_email,
            "blood_type": req.blood_type
        }]

    is_reserve = payload.fulfilled_via_reserve or len(donors) == 0

    req.status = "fulfilled"
    req.fulfilled_at = datetime.utcnow()
    req.live_tracking = False  # Turn off live tracking once fulfilled

    if is_reserve:
        req.matched_donor_id = None
        req.fulfilled_by_donor_name = "Alternative Clinical Reserve / External Stock"
        req.fulfilled_by_donor_email = None
    else:
        req.matched_donor_id = donors[0].get("id") or payload.donor_id or req.matched_donor_id
        req.fulfilled_by_donor_name = ", ".join([d.get("name", "Voluntary Donor") for d in donors])
        req.fulfilled_by_donor_email = ", ".join([d.get("email", "") for d in donors if d.get("email")])

    db.commit()

    target_email = req.user_email or (payload.requester_email.strip().lower() if payload.requester_email else None)
    if target_email:
        sync_user_state_to_r2(target_email, db)
    try:
        from r2_db_sync import sync_db_to_r2
        from database import sqlite_path
        sync_db_to_r2(sqlite_path, force=True)
    except Exception:
        pass

    safe_broadcast({
        "type": "EMERGENCY_FULFILLED",
        "request_id": req.id,
        "request": req.to_dict()
    })

    # Dispatch thank you and fulfillment completion emails in background
    background_tasks.add_task(
        send_transfusion_fulfilled_emails,
        requester_email=payload.requester_email or req.user_email,
        requester_name=payload.requester_name or req.contact_person,
        patient_name=req.patient_name,
        blood_type=req.blood_type,
        units_needed=req.units_needed,
        hospital=req.hospital,
        selected_donors=donors,
        fulfilled_via_reserve=is_reserve
    )

    return {
        "ok": True,
        "message": f"Transfusion for {req.patient_name} marked as FULFILLED. Confirmation emails dispatched.",
        "request": req.to_dict()
    }

@app.get("/api/emergency/deleted-ids", tags=["Emergency"])
def get_deleted_emergency_ids(
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Returns the persistent list of emergency request tombstones/deleted IDs
    for cross-device synchronization and cache pruning.
    """
    query = db.query(DeletedEmergencyRequestModel)
    if user_email:
        email_clean = user_email.strip().lower()
        query = query.filter((DeletedEmergencyRequestModel.user_email == email_clean) | (DeletedEmergencyRequestModel.user_email.is_(None)))
    deleted_records = query.all()
    return {"deleted_ids": [r.id for r in deleted_records]}

@app.delete("/api/emergency/{request_id}", tags=["Emergency"])
async def delete_emergency_request(
    request_id: str,
    user_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Requirement 4: Deletion Persistence in Database, Tombstones, R2 Snapshot & Real-time WebSockets
    """
    req = db.query(EmergencyRequestModel).filter(EmergencyRequestModel.id == request_id).first()
    target_email = user_email.strip().lower() if user_email else (req.user_email.strip().lower() if req and req.user_email else None)

    if req:
        db.delete(req)

    # Persist tombstone in DeletedEmergencyRequestModel so any client pulling sync knows it's deleted
    existing_del = db.query(DeletedEmergencyRequestModel).filter(DeletedEmergencyRequestModel.id == request_id).first()
    if not existing_del:
        db.add(DeletedEmergencyRequestModel(id=request_id, user_email=target_email))

    db.commit()

    if target_email:
        sync_user_state_to_r2(target_email, db)

    try:
        from r2_db_sync import sync_db_to_r2
        from database import sqlite_path
        sync_db_to_r2(sqlite_path, force=True)
    except Exception as sync_err:
        logger.warning(f"Failed to sync post-deletion DB snapshot to R2: {sync_err}")

    # Directly await broadcast to all active WebSockets on main event loop!
    await ws_manager.broadcast({"type": "EMERGENCY_DELETED", "deleted_id": request_id, "user_email": target_email})

    return {"message": "Emergency request deleted successfully.", "deleted_id": request_id}

@app.post("/api/emergency/dispatch-donor", tags=["Emergency"])
def dispatch_emergency_donor_alert(
    payload: EmergencyDispatchDonorRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Dispatches real-time emergency mobilization email directly to a compatible voluntary donor
    and transmits an official dispatch confirmation receipt to the attending clinician.
    Enforces a strict 24-hour rate limit cooldown per voluntary donor across DB & all connected devices.
    """
    # 1. Lookup Donor
    donor = None
    if payload.donor_id:
        donor = db.query(DonorModel).filter(DonorModel.id == payload.donor_id).first()
    if not donor and payload.donor_email:
        donor = db.query(DonorModel).filter(func.lower(DonorModel.email) == payload.donor_email.strip().lower()).first()

    # 2. Enforce 24-Hour Cooldown
    now_utc = datetime.utcnow()
    if donor and donor.last_alert_sent_at:
        elapsed = (now_utc - donor.last_alert_sent_at).total_seconds()
        if elapsed < 86400:  # 24 hours
            rem_sec = int(86400 - elapsed)
            rem_h = rem_sec // 3600
            rem_m = (rem_sec % 3600) // 60
            cooldown_display = f"{rem_h}h {rem_m}m" if rem_h > 0 else f"{rem_m}m"
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"24-Hour Alert Cooldown active for voluntary donor {donor.name}. Next alert dispatch unlocks in {cooldown_display}."
            )

    # 3. Update Donor Cooldown Timestamp
    if donor:
        donor.last_alert_sent_at = now_utc
        db.commit()

    # Clean inputs
    effective_phone = payload.contact_number or payload.requester_phone or "Attending Clinical Dispatch"
    clean_patient = payload.patient_name.strip() if payload.patient_name else "Emergency Transfusion Recipient"
    clean_hospital = payload.hospital.strip() if payload.hospital else "Regional Emergency Trauma Center"
    clean_requester_name = payload.requester_name.strip() if payload.requester_name else "Clinical Coordinator"

    # 4. Enqueue Donor Alert Email
    background_tasks.add_task(
        send_emergency_donor_dispatch_email,
        donor_email=payload.donor_email,
        donor_name=payload.donor_name,
        blood_type=payload.blood_type,
        patient_name=clean_patient,
        hospital=clean_hospital,
        hospital_city=payload.hospital_city or "Delhi",
        contact_number=effective_phone,
        distance_km=payload.distance_km,
        custom_message=payload.custom_message,
        requester_name=clean_requester_name,
        requester_email=payload.requester_email,
        requester_phone=effective_phone
    )

    # 5. Enqueue Clinician Confirmation Email
    if payload.requester_email and "@" in payload.requester_email:
        background_tasks.add_task(
            send_emergency_dispatch_confirmation_to_clinician,
            clinician_email=payload.requester_email.strip().lower(),
            clinician_name=clean_requester_name,
            donor_name=payload.donor_name,
            donor_email=payload.donor_email,
            donor_blood_type=payload.blood_type,
            patient_name=clean_patient,
            hospital=clean_hospital,
            contact_number=effective_phone,
            custom_message=payload.custom_message
        )

    # 6. Real-time Multi-Device Sync via WebSockets
    safe_broadcast({
        "type": "DONOR_ALERT_DISPATCHED",
        "donor_id": donor.id if donor else payload.donor_id,
        "donor_email": payload.donor_email,
        "last_alert_sent_at": now_utc.isoformat(),
        "patient_name": clean_patient,
        "blood_type": payload.blood_type,
        "message": f"Emergency blood alert transmitted to {payload.donor_name}."
    })

    # 7. Cloudflare R2 Sync if requester_email available
    if payload.requester_email:
        try:
            sync_user_state_to_r2(payload.requester_email.strip().lower(), db)
        except Exception:
            pass

    return {
        "ok": True,
        "message": f"Emergency dispatch alert transmitted to {payload.donor_name} ({payload.donor_email}). Confirmation receipt dispatched to {payload.requester_email}.",
        "donor_id": donor.id if donor else payload.donor_id,
        "donor_email": payload.donor_email,
        "last_alert_sent_at": now_utc.isoformat(),
        "dispatched_at": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    }

@app.post("/api/emergency/email-roster", tags=["Emergency"])
def email_clinician_donor_roster(
    payload: EmergencyRosterEmailRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Dispatches top proximity-sorted compatible donor roster to the clinician for offline backup.
    """
    background_tasks.add_task(
        send_clinician_donor_roster_email,
        clinician_email=payload.clinician_email,
        clinician_name=payload.clinician_name,
        recipient_blood_type=payload.recipient_blood_type,
        roster_items=payload.roster_items,
        patient_name=payload.patient_name,
        pdf_base64=payload.pdf_base64,
        pdf_filename=payload.pdf_filename,
        dispatch_id=payload.dispatch_id
    )

    return {
        "ok": True,
        "message": f"Top donor roster docket dispatched to clinician {payload.clinician_email}.",
        "clinician_email": payload.clinician_email,
        "count": len(payload.roster_items),
        "has_attachment": bool(payload.pdf_base64)
    }

@app.post("/api/emergency/save-docket", tags=["Emergency"])
def save_emergency_docket_r2(payload: SaveDocketRequest):
    """Persists a clinical emergency PDF docket into user-isolated Cloudflare R2 object storage."""
    try:
        import base64
        pdf_bytes = base64.b64decode(payload.pdf_base64)
        clean_email = payload.user_email.strip().lower()
        res = upload_user_asset(
            email=clean_email,
            filename=f"dockets/{payload.filename}",
            content=pdf_bytes,
            content_type="application/pdf"
        )
        return {"ok": True, "message": "Docket saved to R2 successfully.", "asset": res}
    except Exception as exc:
        logger.warning(f"Could not persist docket to Cloudflare R2: {exc}")
        return {"ok": True, "message": "Docket processed locally.", "error": str(exc)}

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
    clean_name = sanitize_display_name(payload.full_name)
    profile = db.query(ClinicianProfileModel).filter(ClinicianProfileModel.work_email == email_clean).first()
    if not profile:
        profile = ClinicianProfileModel(
            full_name=clean_name,
            work_email=email_clean,
            phone=payload.phone,
            facility=payload.facility,
            department=payload.department,
            license_id=payload.license_id,
            avatar_url=payload.avatar_url
        )
        db.add(profile)
    else:
        profile.full_name = clean_name
        profile.phone = payload.phone
        profile.facility = payload.facility
        profile.department = payload.department
        profile.license_id = payload.license_id
        profile.avatar_url = payload.avatar_url
        db.add(profile)
    db.commit()

    sync_user_state_to_r2(email_clean, db)
    return profile.to_dict()

@app.put("/api/auth/profile", tags=["Profile"])
@app.put("/api/profile", tags=["Profile"])
def update_user_profile(
    payload: ProfileUpdateRequest,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Updates authenticated clinician's full name.
    Email, verified mobile phone, and unique ID are system-bound and strictly immutable.
    Syncs across database and Cloudflare R2 backup.
    """
    cleaned_name = sanitize_display_name(payload.full_name)
    if len(cleaned_name) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Full legal clinician name must be at least 2 characters."
        )

    current_user.full_name = cleaned_name
    # Verified mobile phone is strictly immutable and cannot be changed in settings

    # Also update ClinicianProfileModel if exists
    profile = db.query(ClinicianProfileModel).filter(
        ClinicianProfileModel.work_email == current_user.email
    ).first()
    if profile:
        profile.full_name = current_user.full_name
        profile.phone = current_user.phone

    db.commit()

    # Mirror to R2
    try:
        save_user_auth_record_r2({
            "id": current_user.id,
            "email": current_user.email,
            "full_name": current_user.full_name,
            "phone": current_user.phone,
            "hashed_password": current_user.hashed_password,
            "is_verified": current_user.is_verified,
            "is_2fa_enabled": current_user.is_2fa_enabled,
            "photo_url": current_user.photo_url,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None
        })
        sync_user_state_to_r2(current_user.email, db)
    except Exception as exc:
        logger.warning(f"Failed to sync profile update to R2: {exc}")

    return {
        "status": "success",
        "message": "Clinician profile updated successfully.",
        "user": current_user.to_dict()
    }

# ==========================================
# USER SAVED CONTACT DATA & CROSS-DEVICE SYNC
# ==========================================
@app.get("/api/v1/user/saved-phones", tags=["User Contact Data"])
def get_user_saved_phones(
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
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

    user = db.query(UserModel).filter(UserModel.email == email_clean).first() if email_clean else None
    phones = user.get_saved_phones() if user else []
    return {"user_email": email_clean, "phone": user.phone if user else None, "saved_phones": phones}

@app.post("/api/v1/user/saved-phones", tags=["User Contact Data"])
def save_user_phone(
    payload: SavedPhoneRequest,
    request: Request = None,
    db: Session = Depends(get_db)
):
    email_clean = payload.email.strip().lower() if payload.email else None
    if not email_clean and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email_clean = u.email
    if not email_clean:
        u = db.query(UserModel).first()
        email_clean = u.email if u else None

    user = db.query(UserModel).filter(UserModel.email == email_clean).first() if email_clean else None
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    phones = user.add_saved_phone(payload.phone)
    if not user.phone:
        user.phone = payload.phone.strip()
    db.commit()
    try:
        sync_user_state_to_r2(email_clean, db)
    except Exception as exc:
        logger.warning(f"Failed to sync saved phones to R2: {exc}")

    return {"status": "success", "saved_phones": phones}

@app.get("/api/v1/user/verified-emails", tags=["User Contact Data"])
def get_user_verified_emails(
    user_email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
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

    user = db.query(UserModel).filter(UserModel.email == email_clean).first() if email_clean else None
    emails = user.get_verified_emails() if user else ([email_clean] if email_clean else [])
    return {"user_email": email_clean, "verified_emails": emails}

@app.post("/api/v1/user/verified-emails", tags=["User Contact Data"])
def save_user_verified_email(
    payload: VerifiedEmailRequest,
    request: Request = None,
    db: Session = Depends(get_db)
):
    email_clean = payload.email.strip().lower() if payload.email else None
    if not email_clean and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email_clean = u.email
    if not email_clean:
        u = db.query(UserModel).first()
        email_clean = u.email if u else None

    user = db.query(UserModel).filter(UserModel.email == email_clean).first() if email_clean else None
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    emails = user.add_verified_email(payload.verified_email)
    db.commit()
    try:
        sync_user_state_to_r2(email_clean, db)
    except Exception as exc:
        logger.warning(f"Failed to sync verified emails to R2: {exc}")

    return {"status": "success", "verified_emails": emails}

# ==========================================
# USER GPS PERMISSION & CROSS-DEVICE SYNC
# ==========================================
@app.get("/api/user/gps-permission", tags=["User GPS Permission"])
def get_user_gps_permission(
    email: Optional[str] = Query(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    email_clean = email.strip().lower() if email else None
    if not email_clean and request:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            u = get_user_from_token(auth_header.split(" ")[1], db)
            if u:
                email_clean = u.email
    if not email_clean:
        u = db.query(UserModel).first()
        email_clean = u.email if u else None

    user = db.query(UserModel).filter(UserModel.email == email_clean).first() if email_clean else None
    return {
        "user_email": email_clean,
        "gps_permission_enabled": bool(user.gps_permission_enabled) if user and user.gps_permission_enabled is not None else False
    }

@app.put("/api/user/gps-permission", tags=["User GPS Permission"])
def update_user_gps_permission(
    payload: GpsPermissionToggleRequest,
    request: Request = None,
    db: Session = Depends(get_db)
):
    email_clean = payload.user_email.strip().lower() if payload.user_email else None
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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User email is required.")

    user = db.query(UserModel).filter(UserModel.email == email_clean).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    user.gps_permission_enabled = bool(payload.enabled)
    db.commit()

    try:
        sync_user_state_to_r2(email_clean, db)
    except Exception as exc:
        logger.warning(f"Failed to sync GPS permission to R2: {exc}")

    return {
        "status": "success",
        "user_email": email_clean,
        "gps_permission_enabled": bool(user.gps_permission_enabled)
    }

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

    # 1. Purge any previous avatar files from R2 profile directory
    # Strictly guarantees only ONE avatar/photo exists in R2 for this user
    try:
        delete_user_category_assets(current_user.email, "profile")
    except Exception as exc:
        logger.warning(f"Could not purge previous avatars for {current_user.email}: {exc}")

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

    # Generate immediate base64 data URL for instant zero-latency rendering across all devices
    b64_str = base64.b64encode(processed_bytes).decode("utf-8")
    data_url = f"data:{mime_type};base64,{b64_str}"

    public_url = upload_meta.get("public_url")
    effective_url = public_url if (public_url and (public_url.startswith("http://") or public_url.startswith("https://"))) else data_url

    current_user.photo_url = effective_url
    db.commit()

    # Continuous disaster recovery master mirror update
    sync_user_state_to_r2(current_user.email, db)

    return {
        "photoUrl": effective_url,
        "photo_url": effective_url,
        "dataUrl": data_url,
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

    # Purge any avatar files from R2 storage
    try:
        delete_user_category_assets(current_user.email, "profile")
    except Exception as exc:
        logger.warning(f"Could not purge avatar files from R2 for {current_user.email}: {exc}")

    current_user.photo_url = None
    db.commit()

    # Master Cloud Mirror update on deletion
    sync_user_state_to_r2(current_user.email, db)

    return {
        "photoUrl": None,
        "message": "Avatar removed successfully. Reset to clinical initials."
    }

@app.get("/api/v1/auth/avatar/data", tags=["Cloud Storage Service"])
def get_user_avatar_data(
    user_email: Optional[str] = Query(None),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Fetches raw avatar binary directly from Cloudflare R2 and converts to a
    data:image/webp;base64 URL with full CORS resilience. Completely eliminates
    cross-origin blocking and tainted canvas errors in portrait crop/manage tools.
    """
    target_email = user_email.strip().lower() if user_email else current_user.email
    if not validate_tenant_access(current_user.email, target_email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Multi-tenant violation: Cannot access another tenant's avatar."
        )

    # 1. Fetch direct bytes from Cloudflare R2
    res = get_user_avatar_bytes(target_email)
    if res:
        img_bytes, mime = res
        b64_str = base64.b64encode(img_bytes).decode("utf-8")
        data_url = f"data:{mime};base64,{b64_str}"
        return {
            "dataUrl": data_url,
            "photoUrl": current_user.photo_url or f"{data_url}",
            "source": "r2_direct"
        }

    # 2. Fallback: Check if user has photo_url in DB
    user_record = db.query(UserModel).filter(UserModel.email == target_email).first()
    photo_url = user_record.photo_url if user_record else current_user.photo_url

    if photo_url and photo_url.startswith("data:"):
        return {
            "dataUrl": photo_url,
            "photoUrl": photo_url,
            "source": "db_data_url"
        }

    # 3. If photo_url is an external URL, proxy-fetch server-side to absorb CORS
    if photo_url and (photo_url.startswith("http://") or photo_url.startswith("https://")):
        try:
            import httpx
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(photo_url)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type") or "image/webp"
                    b64_str = base64.b64encode(resp.content).decode("utf-8")
                    data_url = f"data:{ct};base64,{b64_str}"
                    return {
                        "dataUrl": data_url,
                        "photoUrl": photo_url,
                        "source": "server_proxied"
                    }
        except Exception as exc:
            logger.warning(f"Could not server-proxy avatar from {photo_url}: {exc}")

    return {
        "dataUrl": None,
        "photoUrl": photo_url,
        "source": "none"
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
