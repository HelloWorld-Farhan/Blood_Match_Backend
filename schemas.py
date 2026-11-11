from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr

class InventoryUpdateRequest(BaseModel):
    units_available: Optional[int] = Field(None, ge=0)
    status: Optional[str] = None
    temperature_celsius: Optional[float] = None

class DonorCreateRequest(BaseModel):
    name: str = Field(..., min_length=2)
    blood_type: str = Field(..., min_length=1, max_length=5)
    phone: str = Field(..., min_length=5)
    email: str = Field(..., min_length=5)
    city: str = Field(..., min_length=2)
    hospital: str = Field(..., min_length=2)
    last_donation_date: Optional[str] = None
    is_available: bool = True

class EmergencyCreateRequest(BaseModel):
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
    reset_token: str = Field(..., min_length=10)
    new_password: str = Field(..., min_length=1, max_length=128)

class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    is_verified: bool
    user: Dict[str, Any]
