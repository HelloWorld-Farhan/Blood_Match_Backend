import re
import uuid
import json
from typing import Optional
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime
from database import Base

def strip_honorific(name: Optional[str]) -> str:
    if not name:
        return ""
    return re.sub(r'^(?:Dr\.?|Doctor|Prof\.?|Mr\.?|Mrs\.?|Ms\.?)\s+', '', name.strip(), flags=re.IGNORECASE).strip()

def generate_uuid() -> str:
    return str(uuid.uuid4())

class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    full_name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    phone = Column(String(50), unique=True, index=True, nullable=True)
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

    # Saved phone numbers & verified emails (JSON serialized lists for cross-device sync)
    saved_phones = Column(String(1024), nullable=True, default="[]")
    verified_emails = Column(String(2048), nullable=True, default="[]")
    primary_device_ids = Column(String(1024), nullable=True, default="[]")
    gps_permission_enabled = Column(Boolean, default=False, nullable=False)
    read_alert_ids = Column(String(4096), nullable=True, default="[]")

    def get_read_alert_ids(self) -> list:
        if self.read_alert_ids:
            try:
                parsed = json.loads(self.read_alert_ids)
                if isinstance(parsed, list):
                    return [str(aid).strip() for aid in parsed if aid and str(aid).strip()]
            except Exception:
                pass
        return []

    def mark_alerts_read(self, alert_ids: list) -> list:
        current = set(self.get_read_alert_ids())
        for aid in alert_ids:
            if aid and str(aid).strip():
                current.add(str(aid).strip())
        updated = list(current)
        self.read_alert_ids = json.dumps(updated)
        return updated

    def get_primary_device_ids(self) -> list:
        if self.primary_device_ids:
            try:
                parsed = json.loads(self.primary_device_ids)
                if isinstance(parsed, list):
                    return [str(d).strip() for d in parsed if d and str(d).strip()]
            except Exception:
                pass
        return []

    def add_primary_device(self, device_id: str) -> list:
        current = self.get_primary_device_ids()
        clean = str(device_id).strip()
        if clean and clean not in current:
            current.append(clean)
            self.primary_device_ids = json.dumps(current)
        return current

    def remove_primary_device(self, device_id: str) -> list:
        current = self.get_primary_device_ids()
        clean = str(device_id).strip()
        if clean in current:
            current = [d for d in current if d != clean]
            self.primary_device_ids = json.dumps(current)
        return current

    def is_device_primary(self, device_id: str) -> bool:
        if not device_id:
            return False
        return str(device_id).strip() in self.get_primary_device_ids()

    def get_saved_phones(self) -> list:
        phones = []
        seen_core_map = {}

        def insert_or_upgrade(p_raw: str):
            clean = (p_raw or "").strip()
            if not clean:
                return
            digits = re.sub(r"\D", "", clean)
            core10 = digits[-10:] if len(digits) >= 10 else digits
            if not core10:
                return
            if core10 in seen_core_map:
                idx = seen_core_map[core10]
                existing = phones[idx]
                if "+" in clean and "+" not in existing:
                    phones[idx] = clean
            else:
                seen_core_map[core10] = len(phones)
                phones.append(clean)

        if self.phone and self.phone.strip():
            insert_or_upgrade(self.phone.strip())
        if self.saved_phones:
            try:
                parsed = json.loads(self.saved_phones)
                if isinstance(parsed, list):
                    for p in parsed:
                        if p and isinstance(p, str):
                            insert_or_upgrade(p)
            except Exception:
                for p in self.saved_phones.split(","):
                    insert_or_upgrade(p)
        return phones

    def add_saved_phone(self, new_phone: str) -> list:
        clean = (new_phone or "").strip()
        current = self.get_saved_phones()
        if clean:
            digits = re.sub(r"\D", "", clean)
            core10 = digits[-10:] if len(digits) >= 10 else digits
            if core10:
                found = False
                for idx, existing in enumerate(current):
                    e_digits = re.sub(r"\D", "", existing)
                    e_core10 = e_digits[-10:] if len(e_digits) >= 10 else e_digits
                    if e_core10 == core10:
                        found = True
                        if "+" in clean and "+" not in existing:
                            current[idx] = clean
                        break
                if not found:
                    current.append(clean)
        self.saved_phones = json.dumps(current)
        return current

    def get_verified_emails(self) -> list:
        emails = []
        if self.email and self.email.strip():
            emails.append(self.email.strip().lower())
        if self.verified_emails:
            try:
                parsed = json.loads(self.verified_emails)
                if isinstance(parsed, list):
                    for e in parsed:
                        if e and isinstance(e, str) and e.strip() and e.strip().lower() not in emails:
                            emails.append(e.strip().lower())
            except Exception:
                for e in self.verified_emails.split(","):
                    if e.strip() and e.strip().lower() not in emails:
                        emails.append(e.strip().lower())
        return emails

    def add_verified_email(self, new_email: str) -> list:
        current = self.get_verified_emails()
        clean = (new_email or "").strip().lower()
        if clean and clean not in current:
            current.append(clean)
        self.verified_emails = json.dumps(current)
        return current

    @property
    def member_id(self) -> str:
        clean = (self.id or "9481NX01").replace("-", "").upper()
        return f"BM-{clean[:4]}-{clean[4:8]}"

    @property
    def custom_id(self) -> str:
        return self.member_id

    def to_dict(self):
        clean_name = strip_honorific(self.full_name) or "Clinician"
        return {
            "id": self.id,
            "member_id": self.member_id,
            "full_name": clean_name,
            "email": self.email,
            "phone": self.phone,
            "saved_phones": self.get_saved_phones(),
            "verified_emails": self.get_verified_emails(),
            "is_verified": self.is_verified,
            "is_2fa_enabled": self.is_2fa_enabled,
            "gps_permission_enabled": bool(self.gps_permission_enabled) if self.gps_permission_enabled is not None else False,
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
    device_name = Column(String(100), nullable=False, default="Workstation Browser")
    browser = Column(String(100), nullable=True, default="Browser")
    os = Column(String(50), nullable=True, default="Operating System")
    ip_address = Column(String(50), nullable=True, default="127.0.0.1")
    location = Column(String(120), default="Metro Transfusion Center")
    status = Column(String(20), default="active", nullable=False) # "active" | "revoked"
    is_primary = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_active = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self, current_session_id: str = None, is_primary_override: bool = None):
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
            "is_primary": bool(self.is_primary if is_primary_override is None else is_primary_override),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_active": self.last_active.isoformat() if self.last_active else None,
            "login_time": self.created_at.isoformat() if self.created_at else None,
            "ended_time": self.last_active.isoformat() if self.status in ("revoked", "logged_out") else None,
            "is_current": bool(current_session_id and self.id == current_session_id)
        }

class TrustedDeviceModel(Base):
    __tablename__ = "trusted_devices"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), index=True, nullable=False)
    device_id = Column(String(64), index=True, nullable=False)
    device_name = Column(String(100), nullable=False, default="Workstation Browser")
    browser = Column(String(100), nullable=True, default="Browser")
    os = Column(String(50), nullable=True, default="Operating System")
    ip_address = Column(String(50), nullable=True, default="127.0.0.1")
    is_primary = Column(Boolean, default=False, nullable=False)
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
            "is_primary": bool(self.is_primary),
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
    last_alert_sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "name": self.name,
            "fullName": self.name,
            "blood_type": self.blood_type,
            "bloodType": self.blood_type,
            "phone": self.phone,
            "email": self.email,
            "city": self.city,
            "state": "Delhi",
            "location": self.location or self.city,
            "hospital": self.hospital,
            "age": self.age or 28,
            "gender": self.gender or "MALE",
            "units_donated_total": self.units_donated_total or 0,
            "unitsDonatedTotal": self.units_donated_total or 0,
            "last_donation_date": self.last_donation_date,
            "lastDonationDate": self.last_donation_date,
            "is_available": self.is_available,
            "isAvailable": self.is_available,
            "available": self.is_available,
            "last_alert_sent_at": self.last_alert_sent_at.isoformat() if self.last_alert_sent_at else None,
            "lastAlertSentAt": self.last_alert_sent_at.isoformat() if self.last_alert_sent_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "registeredAt": self.created_at.isoformat() if self.created_at else None
        }

class EmergencyRequestModel(Base):
    __tablename__ = "emergency_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_email = Column(String(120), nullable=True, index=True)
    patient_name = Column(String(100), nullable=False)
    patient_age = Column(Integer, nullable=True, default=35)
    hospital = Column(String(120), nullable=False)
    hospital_city = Column(String(120), nullable=True)
    ward = Column(String(100), nullable=True)
    blood_type = Column(String(10), nullable=False, index=True)
    units_needed = Column(Integer, nullable=False, default=1)
    urgency = Column(String(20), nullable=True, default="CRITICAL")
    status = Column(String(20), nullable=False, default="urgent", index=True)
    contact_person = Column(String(100), nullable=False)
    contact_phone = Column(String(30), nullable=False)
    matched_donor_id = Column(String(36), nullable=True)
    fulfilled_at = Column(DateTime, nullable=True)
    fulfilled_by_donor_name = Column(String(100), nullable=True)
    fulfilled_by_donor_email = Column(String(120), nullable=True)
    live_tracking = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "patient_name": self.patient_name,
            "patient_age": self.patient_age,
            "hospital": self.hospital,
            "hospital_city": self.hospital_city,
            "ward": self.ward,
            "blood_type": self.blood_type,
            "units_needed": self.units_needed,
            "urgency": self.urgency or "CRITICAL",
            "status": self.status,
            "contact_person": self.contact_person,
            "contact_phone": self.contact_phone,
            "matched_donor_id": self.matched_donor_id,
            "fulfilled_at": self.fulfilled_at.isoformat() if self.fulfilled_at else None,
            "fulfilled_by_donor_name": self.fulfilled_by_donor_name,
            "fulfilled_by_donor_email": self.fulfilled_by_donor_email,
            "live_tracking": bool(self.live_tracking) if self.live_tracking is not None else True,
            "liveTracking": bool(self.live_tracking) if self.live_tracking is not None else True,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class DeletedEmergencyRequestModel(Base):
    __tablename__ = "deleted_emergency_requests"

    id = Column(String(36), primary_key=True)
    user_email = Column(String(120), nullable=True, index=True)
    deleted_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None
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

    @property
    def custom_id(self) -> str:
        return self.member_id

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
