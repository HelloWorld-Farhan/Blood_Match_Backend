import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal
import models

class TestDonorsGeolocationAndOtp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from database import init_db
        init_db()

    def setUp(self):
        self.client = TestClient(app)
        self.db = SessionLocal()
        self.test_email = "donor.test@example.com"
        self.test_name = "Rohan Sharma"
        self.test_location = "Connaught Place, Central Delhi"

    def tearDown(self):
        # Clean test records
        self.db.query(models.DonorModel).filter(models.DonorModel.email == self.test_email).delete()
        self.db.query(models.OtpTokenModel).filter(models.OtpTokenModel.user_id == self.test_email).delete()
        self.db.commit()
        self.db.close()

    @patch("email_service._dispatch_google_apps_script")
    def test_01_send_donor_otp(self, mock_gas):
        mock_gas.return_value = True

        response = self.client.post("/api/donors/send-otp", json={
            "email": self.test_email,
            "name": self.test_name
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))

        # Verify token created in database
        otp_rec = self.db.query(models.OtpTokenModel).filter(
            models.OtpTokenModel.user_id == self.test_email,
            models.OtpTokenModel.token_type == "donor_verification"
        ).first()
        self.assertIsNotNone(otp_rec)
        self.assertEqual(len(otp_rec.otp_code), 6)

    @patch("email_service._dispatch_google_apps_script")
    def test_02_register_donor_with_valid_otp(self, mock_gas):
        mock_gas.return_value = True

        # Send OTP first
        self.client.post("/api/donors/send-otp", json={
            "email": self.test_email,
            "name": self.test_name
        })
        otp_rec = self.db.query(models.OtpTokenModel).filter(
            models.OtpTokenModel.user_id == self.test_email,
            models.OtpTokenModel.token_type == "donor_verification"
        ).first()

        # Register donor with OTP
        response = self.client.post("/api/donors", json={
            "name": self.test_name,
            "blood_type": "B+",
            "phone": "+91 9811223344",
            "email": self.test_email,
            "city": "Delhi",
            "location": self.test_location,
            "age": 29,
            "gender": "MALE",
            "user_email": "clinician.lead@hospital.org",
            "otp_code": otp_rec.otp_code
        })
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["name"], self.test_name)
        self.assertEqual(data["blood_type"], "B+")
        self.assertEqual(data["location"], self.test_location)

    def test_03_list_donors_prioritizes_user_email(self):
        # Create a test donor
        donor = models.DonorModel(
            name="Priority Donor",
            blood_type="O-",
            phone="+91 9988776655",
            email="priority.test@hospital.org",
            city="Delhi",
            location="Rohini, North West Delhi",
            user_email="priority.test@hospital.org"
        )
        self.db.add(donor)
        self.db.commit()

        response = self.client.get("/api/donors?user_email=priority.test@hospital.org")
        self.assertEqual(response.status_code, 200)
        donors = response.json()
        self.assertTrue(len(donors) > 0)
        # First donor must be the one matching user_email
        self.assertEqual(donors[0]["email"], "priority.test@hospital.org")

    def test_04_inventory_reflects_donor_pledge(self):
        # Create a test donor with O- blood type
        donor = models.DonorModel(
            name="Donor For Inventory Test",
            blood_type="O-",
            phone="+91 9911223344",
            email=self.test_email,
            city="Delhi",
            location="Saket, South Delhi",
            user_email="clinician.lead@hospital.org",
            units_donated_total=2,
            is_available=True
        )
        self.db.add(donor)
        self.db.commit()

        # Query GET /api/inventory
        response = self.client.get("/api/inventory")
        self.assertEqual(response.status_code, 200)
        items = response.json()
        o_neg = next((i for i in items if i["blood_type"] == "O-"), None)
        self.assertIsNotNone(o_neg)
        self.assertGreaterEqual(o_neg["units_available"], 2)

        # Cleanup
        self.db.delete(donor)
        self.db.commit()

if __name__ == "__main__":
    unittest.main()
