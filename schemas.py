from typing import Optional
from pydantic import BaseModel, Field

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
