from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr

class InventoryUpdateRequest(BaseModel):
    units_available: Optional[int] = Field(None, ge=0)
    status: Optional[str] = None
    temperature_celsius: Optional[float] = None

class DonorSendOtpRequest(BaseModel):
    email: str = Field(..., min_length=5)
    name: str = Field(..., min_length=2)

class DonorCreateRequest(BaseModel):
    user_email: Optional[str] = None
    name: str = Field(..., min_length=2)
    blood_type: str = Field(..., min_length=1, max_length=5)
    phone: str = Field(..., min_length=5)
    email: str = Field(..., min_length=5)
    city: str = Field(..., min_length=2)
    location: Optional[str] = None
    hospital: Optional[str] = "BloodMatch Emergency Network"
    age: Optional[int] = Field(28, ge=18, le=65)
    gender: Optional[str] = "MALE"
    last_donation_date: Optional[str] = None
    is_available: bool = True
    otp_code: Optional[str] = None

class EmergencyCreateRequest(BaseModel):
    user_email: Optional[str] = None
    patient_name: str = Field(..., min_length=2)
    hospital: str = Field(..., min_length=2)
    blood_type: str = Field(..., min_length=1, max_length=5)
    units_needed: int = Field(1, ge=1)
    status: str = "urgent"
    contact_person: str = Field(..., min_length=2)
    contact_phone: str = Field(..., min_length=5)

class ClinicianProfileRequest(BaseModel):
    full_name: str = Field(..., min_length=2)
    work_email: str = Field(..., min_length=5)
    phone: Optional[str] = None
    facility: Optional[str] = None
    department: Optional[str] = None
    license_id: Optional[str] = None
    avatar_url: Optional[str] = None

# Enterprise Auth Schemas
class UserRegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=120)
    phone: Optional[str] = Field(None, max_length=30)
    password: str = Field(..., min_length=1, max_length=128)

class OtpVerifyRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)
    otp_code: str = Field(..., min_length=6, max_length=6)

class OtpResendRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)

class UserLoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=1)
    device_id: Optional[str] = None
    remember_device: bool = False

# Two-Factor Authentication Schemas
class TwoFactorVerifyRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)
    otp_code: str = Field(..., min_length=6, max_length=6)
    device_id: str = Field(..., min_length=1, max_length=64)
    remember_device: bool = False

class TwoFactorToggleRequest(BaseModel):
    enable_2fa: bool
    password: Optional[str] = None

class AccountUnlockRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)
    unlock_code: str = Field(..., min_length=6, max_length=6)

# Multi-Step Password Reset Schemas
class PasswordResetRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)

class PasswordResetVerifyRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)
    otp_code: str = Field(..., min_length=6, max_length=6)

class PasswordResetConfirmRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)
    reset_token: Optional[str] = None
    reset_session_token: Optional[str] = None
    new_password: str = Field(..., min_length=1, max_length=128)

class PasswordVerifyCurrentRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)
    current_password: str = Field(..., min_length=1, max_length=128)

class PasswordUpdatePreviousRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=120)
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=1, max_length=128)

class AccountDeletionConfirmRequest(BaseModel):
    confirm_text: str = Field(..., min_length=1, max_length=50)
    otp_code: str = Field(..., min_length=6, max_length=6)

class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    is_verified: bool
    user: Dict[str, Any]

class ClinicalCheckCreateRequest(BaseModel):
    patient_name: str = Field(..., min_length=1, max_length=100)
    patient_id: Optional[str] = None
    blood_type: str = Field(..., min_length=2, max_length=10)
    check_type: str = Field("compatibility", max_length=50)
    status: str = Field("passed", max_length=20)
    notes: Optional[str] = None

class ClinicalDocumentCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=150)
    doc_type: str = Field("lab_report", max_length=50)
    file_url: str = Field(..., min_length=5, max_length=1024)
    file_size_kb: Optional[float] = 0.0

class ClinicalAuditLogCreateRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    entity_type: str = Field(..., min_length=1, max_length=50)
    entity_id: Optional[str] = None
    details: Optional[str] = None
