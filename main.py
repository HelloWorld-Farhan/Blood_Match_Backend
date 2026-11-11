import os
import logging
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from database import init_db, get_db, is_sqlite_fallback
from models import (
    InventoryModel,
    DonorModel,
    EmergencyRequestModel,
    ClinicianProfileModel
)
from schemas import (
    InventoryUpdateRequest,
    DonorCreateRequest,
    EmergencyCreateRequest,
    ClinicianProfileRequest
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
    description="Resilient database abstraction layer with PostgreSQL and persistent SQLite fallback.",
    version="1.0.0",
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

# Root & Health Endpoints
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

# Inventory Endpoints
@app.get("/api/inventory", tags=["Inventory"])
def list_inventory(db: Session = Depends(get_db)):
    items = db.query(InventoryModel).order_by(InventoryModel.blood_type).all()
    return [item.to_dict() for item in items]

@app.put("/api/inventory/{blood_type}", tags=["Inventory"])
def update_inventory_units(
    blood_type: str,
    payload: InventoryUpdateRequest,
    db: Session = Depends(get_db)
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

# Donor Endpoints
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

# Emergency Request Endpoints
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

# Clinician Profile Endpoints
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
