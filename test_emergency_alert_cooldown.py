import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from database import SessionLocal, init_db
from models import DonorModel
from main import app

def test_dispatch_alert_cooldown_and_confirmation():
    init_db()
    client = TestClient(app)
    db = SessionLocal()

    # Create a test donor
    test_email = "test_cooldown_donor@bloodmatch.org"
    donor = db.query(DonorModel).filter(DonorModel.email == test_email).first()
    if not donor:
        donor = DonorModel(
            name="Aarav Sharma",
            blood_type="O-",
            phone="+919876543210",
            email=test_email,
            city="Delhi",
            location="Connaught Place, Central Delhi",
            hospital="Regional Emergency Trauma Center",
            last_alert_sent_at=None
        )
        db.add(donor)
        db.commit()
        db.refresh(donor)
    else:
        donor.last_alert_sent_at = None
        db.commit()

    # 1. First dispatch should succeed
    payload = {
        "donor_id": donor.id,
        "donor_name": donor.name,
        "donor_email": donor.email,
        "blood_type": donor.blood_type,
        "patient_name": "Emergency Recipient Alpha",
        "hospital": "Connaught Place Emergency Center",
        "hospital_city": "Delhi",
        "contact_number": "+919876543210",
        "custom_message": "Immediate voluntary blood donation needed.",
        "requester_name": "Dr. Clinical Lead",
        "requester_email": "clinician_test@bloodmatch.org",
        "requester_phone": "+919876543210"
    }

    res1 = client.post("/api/emergency/dispatch-donor", json=payload)
    assert res1.status_code == 200, res1.text
    data1 = res1.json()
    assert data1["ok"] is True
    assert "last_alert_sent_at" in data1
    assert data1["last_alert_sent_at"] is not None

    # Check donor in DB has updated last_alert_sent_at
    db.refresh(donor)
    assert donor.last_alert_sent_at is not None

    # 2. Second dispatch immediately afterwards should be rejected with 429 Too Many Requests
    res2 = client.post("/api/emergency/dispatch-donor", json=payload)
    assert res2.status_code == 429, f"Expected 429 but got {res2.status_code}: {res2.text}"
    err_detail = res2.json().get("detail", "")
    assert "24-Hour Alert Cooldown active" in err_detail

    # 3. Simulate 25 hours passed
    donor.last_alert_sent_at = datetime.utcnow() - timedelta(hours=25)
    db.commit()

    # 4. Third dispatch should now succeed again
    res3 = client.post("/api/emergency/dispatch-donor", json=payload)
    assert res3.status_code == 200, res3.text
    data3 = res3.json()
    assert data3["ok"] is True

    # Clean up test donor
    db.delete(donor)
    db.commit()
    db.close()

if __name__ == "__main__":
    test_dispatch_alert_cooldown_and_confirmation()
    print("ALL TESTS PASSED!")
