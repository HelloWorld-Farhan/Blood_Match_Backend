import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime
from database import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

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
    name = Column(String(100), nullable=False)
    blood_type = Column(String(10), nullable=False, index=True)
    phone = Column(String(30), nullable=False)
    email = Column(String(120), nullable=False)
    city = Column(String(100), nullable=False)
    hospital = Column(String(120), nullable=False)
    last_donation_date = Column(String(30), nullable=True)
    is_available = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "blood_type": self.blood_type,
            "phone": self.phone,
            "email": self.email,
            "city": self.city,
            "hospital": self.hospital,
            "last_donation_date": self.last_donation_date,
            "is_available": self.is_available,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class EmergencyRequestModel(Base):
    __tablename__ = "emergency_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
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

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "work_email": self.work_email,
            "phone": self.phone,
            "facility": self.facility,
            "department": self.department,
            "license_id": self.license_id,
            "avatar_url": self.avatar_url,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
