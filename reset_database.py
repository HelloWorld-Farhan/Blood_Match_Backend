"""
Database Fresh Start Reset Script
Wipes all test/dummy data across all tables and seeds the pristine 8-group blood inventory.
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

import database
import models

# Ensure tables are created
database.init_db()

print("Connecting to database session...")
session = database.SessionLocal()

try:
    # Clear all user and transactional records
    tables_to_clear = [
        models.UserModel,
        models.OtpTokenModel,
        models.UserSessionModel,
        models.TrustedDeviceModel,
        models.ClinicianProfileModel,
        models.PasswordHistoryModel,
        models.EmergencyRequestModel,
        models.ClinicalCheckModel,
        models.ClinicalAuditLogModel,
        models.ClinicalDocumentModel,
        models.DonorModel,
        models.TransfusionAlertModel,
        models.InventoryModel
    ]

    for model_cls in tables_to_clear:
        deleted = session.query(model_cls).delete()
        print(f"Cleared {model_cls.__tablename__} ({deleted} rows removed)")

    session.commit()

    # Re-seed the 8 clean ABO & RhD blood groups initialized to zero for fresh operational start
    initial_inventory = [
        models.InventoryModel(blood_type="O-", units_available=0, status="critical", temperature_celsius=4.0),
        models.InventoryModel(blood_type="O+", units_available=0, status="critical", temperature_celsius=4.0),
        models.InventoryModel(blood_type="A-", units_available=0, status="critical", temperature_celsius=4.0),
        models.InventoryModel(blood_type="A+", units_available=0, status="critical", temperature_celsius=4.0),
        models.InventoryModel(blood_type="B-", units_available=0, status="critical", temperature_celsius=4.0),
        models.InventoryModel(blood_type="B+", units_available=0, status="critical", temperature_celsius=4.0),
        models.InventoryModel(blood_type="AB-", units_available=0, status="critical", temperature_celsius=4.0),
        models.InventoryModel(blood_type="AB+", units_available=0, status="critical", temperature_celsius=4.0),
    ]
    session.add_all(initial_inventory)
    session.commit()
    print("Re-seeded pristine 8-group ABO/Rh inventory at 0 units.")

    # Status summary
    print("\n--- Current Database Table Counts ---")
    for model_cls in tables_to_clear:
        count = session.query(model_cls).count()
        print(f"  {model_cls.__tablename__}: {count} rows")

finally:
    session.close()

# Clean Cloudflare R2 Storage (users/ prefix)
try:
    from storage_service import get_r2_client, R2_BUCKET_NAME
    r2 = get_r2_client()
    if r2:
        print("\nPurging Cloudflare R2 storage bucket (users/ prefix)...")
        paginator = r2.get_paginator('list_objects_v2')
        deleted_r2_count = 0
        for page in paginator.paginate(Bucket=R2_BUCKET_NAME, Prefix="users/"):
            items = page.get("Contents", [])
            if items:
                delete_keys = [{"Key": item["Key"]} for item in items]
                r2.delete_objects(Bucket=R2_BUCKET_NAME, Delete={"Objects": delete_keys})
                deleted_r2_count += len(delete_keys)
        print(f"Cloudflare R2 storage cleared ({deleted_r2_count} objects deleted under users/).")
except Exception as r2_err:
    print(f"Cloudflare R2 cleanup notice: {r2_err}")

# Vacuum SQLite database if using SQLite fallback
if "sqlite" in str(database.engine.url):
    import sqlite3
    import tempfile
    db_file = os.path.join(tempfile.gettempdir(), "bloodmatch_fallback.db")
    if os.path.exists(db_file):
        conn = sqlite3.connect(db_file)
        conn.execute("VACUUM")
        conn.close()
        print(f"VACUUM executed on {db_file} (disk space reclaimed).")

print("\nDatabase is completely fresh, clean, and ready for real users!")
