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
        models.InventoryModel
    ]

    for model_cls in tables_to_clear:
        deleted = session.query(model_cls).delete()
        print(f"Cleared {model_cls.__tablename__} ({deleted} rows removed)")

    session.commit()

    # Re-seed the 8 clean ABO & RhD blood groups
    initial_inventory = [
        models.InventoryModel(blood_type="O-", units_available=14, status="optimal", temperature_celsius=3.8),
        models.InventoryModel(blood_type="O+", units_available=22, status="optimal", temperature_celsius=4.0),
        models.InventoryModel(blood_type="A-", units_available=8, status="moderate", temperature_celsius=3.9),
        models.InventoryModel(blood_type="A+", units_available=19, status="optimal", temperature_celsius=4.1),
        models.InventoryModel(blood_type="B-", units_available=4, status="critical", temperature_celsius=4.0),
        models.InventoryModel(blood_type="B+", units_available=17, status="optimal", temperature_celsius=3.7),
        models.InventoryModel(blood_type="AB-", units_available=2, status="critical", temperature_celsius=4.2),
        models.InventoryModel(blood_type="AB+", units_available=9, status="moderate", temperature_celsius=4.0),
    ]
    session.add_all(initial_inventory)
    session.commit()
    print("Re-seeded pristine 8-group ABO/Rh inventory.")

    # Status summary
    print("\n--- Current Database Table Counts ---")
    for model_cls in tables_to_clear:
        count = session.query(model_cls).count()
        print(f"  {model_cls.__tablename__}: {count} rows")

finally:
    session.close()

# Vacuum SQLite database if using SQLite fallback
if "sqlite" in str(database.engine.url):
    import sqlite3
    db_file = os.path.join(os.path.dirname(__file__), "bloodmatch_fallback.db")
    if os.path.exists(db_file):
        conn = sqlite3.connect(db_file)
        conn.execute("VACUUM")
        conn.close()
        print(f"VACUUM executed on {db_file} (disk space reclaimed).")

print("\nDatabase is completely fresh, clean, and ready for real users!")
