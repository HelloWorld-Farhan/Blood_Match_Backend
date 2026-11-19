import unittest
import uuid
import json
from unittest.mock import patch
from fastapi.testclient import TestClient

from database import init_db, SessionLocal
from main import app, hash_password
from models import UserModel, OtpTokenModel, UserSessionModel

class TestPhoneAndEmailLogin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        os.environ["MOCK_EXTERNAL_EMAIL"] = "1"
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        self.session = SessionLocal()
        self.test_email = f"clinician.phone.{uuid.uuid4().hex[:6]}@hospital.org"
        self.password = "HospitalSecure99!#"
        self.primary_phone = "+91 98765 43210"
        self.secondary_phone = "+1 555-432-1098"

        # Create verified test user
        self.user = UserModel(
            id=str(uuid.uuid4()),
            full_name="Dr. Farhan Khalid",
            email=self.test_email,
            phone=self.primary_phone,
            hashed_password=hash_password(self.password),
            is_verified=True,
            is_2fa_enabled=False,
            saved_phones=json.dumps([self.secondary_phone])
        )
        self.session.add(self.user)
        self.session.commit()

    def tearDown(self):
        self.session.query(OtpTokenModel).filter(OtpTokenModel.email == self.test_email).delete()
        self.session.query(UserSessionModel).filter(UserSessionModel.user_id == self.user.id).delete()
        self.session.query(UserModel).filter(UserModel.email == self.test_email).delete()
        self.session.commit()
        self.session.close()

    def test_phone_lookup_endpoint_matched_in_db(self):
        # 1. Lookup without country code (just 10 digits)
        resp = self.client.get("/api/auth/phone-lookup", params={"phone": "9876543210"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["found"])
        self.assertEqual(data["dial_code"], "+91")
        self.assertEqual(data["country_code"], "IN")

        # 2. Lookup with secondary saved phone
        resp2 = self.client.get("/api/auth/phone-lookup", params={"phone": "5554321098"})
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertTrue(data2["found"])

    def test_phone_lookup_endpoint_unmatched_fallback(self):
        # Number not in DB, but matches Indian 10-digit mobile rule
        resp = self.client.get("/api/auth/phone-lookup", params={"phone": "9123456789"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["found"])
        self.assertEqual(data["dial_code"], "+91")

    def test_login_by_email(self):
        payload = {
            "identifier": self.test_email,
            "password": self.password,
            "device_id": "test-device-01"
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], self.test_email)

    def test_login_by_phone_without_country_code(self):
        # User only enters 10 digits without +91
        payload = {
            "identifier": "9876543210",
            "password": self.password,
            "device_id": "test-device-02"
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], self.test_email)

    def test_login_by_phone_with_full_country_code(self):
        # User enters full phone "+91 98765 43210"
        payload = {
            "identifier": "+91 98765 43210",
            "password": self.password,
            "device_id": "test-device-03"
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], self.test_email)

    def test_login_by_secondary_saved_phone(self):
        # User enters secondary phone
        payload = {
            "identifier": "555-432-1098",
            "password": self.password,
            "device_id": "test-device-04"
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], self.test_email)

    def test_login_invalid_phone_or_password(self):
        # Wrong phone
        resp1 = self.client.post("/api/auth/login", json={
            "identifier": "9999999999",
            "password": self.password
        })
        self.assertEqual(resp1.status_code, 401)

        # Correct phone, wrong password
        resp2 = self.client.post("/api/auth/login", json={
            "identifier": "9876543210",
            "password": "WrongPassword123!"
        })
        self.assertEqual(resp2.status_code, 401)

if __name__ == "__main__":
    unittest.main()
