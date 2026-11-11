import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime
from database import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    full_name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    phone = Column(String(30), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)

    @property
    def name(self) -> str:
        return self.full_name

    # Brute-force protection & Lockout tracking
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    last_failed_login = Column(DateTime, nullable=True)
    locked_until = Column(DateTime, nullable=True)

    # Adaptive Two-Factor Authentication
    is_2fa_enabled = Column(Boolean, default=False, nullable=False)

    # Cloudflare R2 Universal Avatar Profile Picture
    photo_url = Column(String(1024), nullable=True)

    @property
    def member_id(self) -> str:
        clean = (self.id or "9481NX01").replace("-", "").upper()
        return f"BM-{clean[:4]}-{clean[4:8]}"

    def to_dict(self):
        return {
            "id": self.id,
            "member_id": self.member_id,
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "is_verified": self.is_verified,
            "is_2fa_enabled": self.is_2fa_enabled,
            "photo_url": self.photo_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "failed_login_attempts": self.failed_login_attempts,
            "last_failed_login": self.last_failed_login.isoformat() if self.last_failed_login else None,
            "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            "is_locked": bool(self.locked_until and self.locked_until > datetime.utcnow())
        }

class OtpTokenModel(Base):
    __tablename__ = "otp_tokens"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), index=True, nullable=False)
    email = Column(String(120), index=True, nullable=False)
    otp_code = Column(String(6), nullable=False)
    token_type = Column(String(30), default="verification", nullable=False) # "verification" | "emergency_unlock"
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    attempts = Column(Integer, default=0, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.email,
            "token_type": self.token_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_used": self.is_used,
            "attempts": self.attempts
        }

class PasswordHistoryModel(Base):
    __tablename__ = "password_history"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class UserSessionModel(Base):
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), index=True, nullable=False)
    device_id = Column(String(64), index=True, nullable=False)
    device_name = Column(String(100), nullable=False)
    browser = Column(String(100), nullable=False)
    os = Column(String(50), nullable=False)
    ip_address = Column(String(50), nullable=False)
    location = Column(String(120), default="Metro Transfusion Center")
    status = Column(String(20), default="active", nullable=False) # "active" | "revoked"
    created_at = Column(DateTime, default=datetime.utcnow)
    last_active = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self, current_session_id: str = None):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "browser": self.browser,
            "os": self.os,
            "ip_address": self.ip_address,
            "location": self.location,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_active": self.last_active.isoformat() if self.last_active else None,
            "is_current": bool(current_session_id and self.id == current_session_id)
        }

class TrustedDeviceModel(Base):
    __tablename__ = "trusted_devices"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), index=True, nullable=False)
    device_id = Column(String(64), index=True, nullable=False)
    device_name = Column(String(100), nullable=False)
    browser = Column(String(100), nullable=False)
    os = Column(String(50), nullable=False)
    ip_address = Column(String(50), nullable=False)
    trusted_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "browser": self.browser,
            "os": self.os,
            "ip_address": self.ip_address,
            "trusted_at": self.trusted_at.isoformat() if self.trusted_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None
        }

class InventoryModel(Base):
    __tablename__ = "inventory"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    blood_type = Column(String(10), unique=True, nullable=False, index=True)
    units_available = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="optimal")
    temperature_celsius = Column(Float, default=4.0)
    last_inspected = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "blood_type": self.blood_type,
            "units_available": self.units_available,
            "status": self.status,
            "temperature_celsius": self.temperature_celsius,
            "last_inspected": self.last_inspected.isoformat() if self.last_inspected else None
        }

class DonorModel(Base):
    __tablename__ = "donors"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_email = Column(String(120), nullable=True, index=True)
    name = Column(String(100), nullable=False)
    blood_type = Column(String(10), nullable=False, index=True)
    phone = Column(String(30), nullable=False)
    email = Column(String(120), nullable=False)
    city = Column(String(100), nullable=False)
    location = Column(String(200), nullable=True)  # Detailed locality / area (e.g., in Delhi)
    hospital = Column(String(120), nullable=False, default="BloodMatch Emergency Network")
    age = Column(Integer, nullable=True, default=28)
    gender = Column(String(20), nullable=True, default="MALE")
    units_donated_total = Column(Integer, nullable=True, default=0)
    last_donation_date = Column(String(30), nullable=True)
    is_available = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "name": self.name,
            "blood_type": self.blood_type,
            "phone": self.phone,
            "email": self.email,
            "city": self.city,
            "location": self.location or self.city,
            "hospital": self.hospital,
            "age": self.age or 28,
            "gender": self.gender or "MALE",
            "units_donated_total": self.units_donated_total or 0,
            "last_donation_date": self.last_donation_date,
            "is_available": self.is_available,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class EmergencyRequestModel(Base):
    __tablename__ = "emergency_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_email = Column(String(120), nullable=True, index=True)
    patient_name = Column(String(100), nullable=False)
    hospital = Column(String(120), nullable=False)
    blood_type = Column(String(10), nullable=False, index=True)
    units_needed = Column(Integer, nullable=False, default=1)
    status = Column(String(20), nullable=False, default="urgent", index=True)
    contact_person = Column(String(100), nullable=False)
    contact_phone = Column(String(30), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "patient_name": self.patient_name,
            "hospital": self.hospital,
            "blood_type": self.blood_type,
            "units_needed": self.units_needed,
            "status": self.status,
            "contact_person": self.contact_person,
            "contact_phone": self.contact_phone,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class ClinicianProfileModel(Base):
    __tablename__ = "clinician_profiles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    full_name = Column(String(100), nullable=False)
    work_email = Column(String(120), unique=True, nullable=False)
    phone = Column(String(30), nullable=True)
    facility = Column(String(120), nullable=True)
    department = Column(String(100), nullable=True)
    license_id = Column(String(50), nullable=True)
    avatar_url = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def member_id(self) -> str:
        clean = (self.id or "9481NX01").replace("-", "").upper()
        return f"BM-{clean[:4]}-{clean[4:8]}"

    def to_dict(self):
        return {
            "id": self.id,
            "member_id": self.member_id,
            "full_name": self.full_name,
            "work_email": self.work_email,
            "phone": self.phone,
            "facility": self.facility,
            "department": self.department,
            "license_id": self.license_id,
            "avatar_url": self.avatar_url,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

class ClinicalCheckModel(Base):
    __tablename__ = "clinical_checks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_email = Column(String(120), index=True, nullable=False)
    patient_name = Column(String(100), nullable=False)
    patient_id = Column(String(50), nullable=True)
    blood_type = Column(String(10), nullable=False)
    check_type = Column(String(50), default="compatibility") # "compatibility" | "crossmatch" | "antibody_screen"
    status = Column(String(20), default="passed") # "passed" | "flagged" | "inconclusive"
    notes = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "patient_name": self.patient_name,
            "patient_id": self.patient_id,
            "blood_type": self.blood_type,
            "check_type": self.check_type,
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class ClinicalAuditLogModel(Base):
    __tablename__ = "clinical_audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_email = Column(String(120), index=True, nullable=False)
    action = Column(String(100), nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(50), nullable=True)
    details = Column(String(1024), nullable=True)
    ip_address = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "details": self.details,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }

class ClinicalDocumentModel(Base):
    __tablename__ = "clinical_documents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_email = Column(String(120), index=True, nullable=False)
    title = Column(String(150), nullable=False)
    doc_type = Column(String(50), default="lab_report") # "crossmatch_certificate" | "lab_report" | "consent_form"
    file_url = Column(String(1024), nullable=False)
    file_size_kb = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "title": self.title,
            "doc_type": self.doc_type,
            "file_url": self.file_url,
            "file_size_kb": self.file_size_kb,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class TransfusionAlertModel(Base):
    __tablename__ = "transfusion_alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    creator_email = Column(String(120), index=True, nullable=False) # Registrant email (excluded from alert)
    donor_id = Column(String(36), index=True, nullable=False) # Targeted donor ID for direct navigation
    blood_type = Column(String(10), nullable=False, index=True)
    donor_name = Column(String(100), nullable=False)
    location = Column(String(200), nullable=False)
    title = Column(String(150), nullable=False)
    message = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "creator_email": self.creator_email,
            "donor_id": self.donor_id,
            "blood_type": self.blood_type,
            "donor_name": self.donor_name,
            "location": self.location,
            "title": self.title,
            "message": self.message,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
