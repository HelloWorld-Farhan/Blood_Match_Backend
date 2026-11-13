import unittest
from datetime import datetime
from unittest.mock import patch
from fastapi.testclient import TestClient

from database import init_db, SessionLocal
from main import app
from models import UserModel, OtpTokenModel, UserSessionModel

class TestRegistrationOtpVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        os.environ["MOCK_EXTERNAL_EMAIL"] = "1"
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        self.session = SessionLocal()
        import uuid
        self.test_email = f"clinician.verify.{uuid.uuid4().hex[:6]}@hospital.org"
        self.session.query(OtpTokenModel).filter(OtpTokenModel.email == self.test_email).delete()
        self.session.query(UserSessionModel).delete()
        self.session.query(UserModel).filter(UserModel.email == self.test_email).delete()
        self.session.commit()

    def tearDown(self):
        self.session.query(OtpTokenModel).filter(OtpTokenModel.email == self.test_email).delete()
        self.session.query(UserModel).filter(UserModel.email == self.test_email).delete()
        self.session.commit()
        self.session.close()

    @patch("email_service._dispatch_google_apps_script", return_value=True)
    def test_registration_and_otp_verification_success(self, mock_dispatch):
        password = "SecurePassword12!@"

        # 1. Register User
        reg_payload = {
            "full_name": "Dr. Sarah Connor",
            "email": self.test_email,
            "phone": "+91 98765 43210",
            "password": password
        }
        reg_resp = self.client.post("/api/auth/register", json=reg_payload)
        self.assertEqual(reg_resp.status_code, 201)
        self.assertTrue(reg_resp.json().get("verification_required"))

        # 2. Extract OTP from database
        otp_entry = (
            self.session.query(OtpTokenModel)
            .filter(OtpTokenModel.email == self.test_email, OtpTokenModel.token_type == "verification")
            .order_by(OtpTokenModel.created_at.desc())
            .first()
        )
        self.assertIsNotNone(otp_entry)
        otp_code = otp_entry.otp_code

        # 3. Verify OTP - Must return 200 OK without any AttributeError or 500 error!
        verify_resp = self.client.post("/api/auth/verify-otp", json={
            "email": self.test_email,
            "otp_code": otp_code
        })
        self.assertEqual(verify_resp.status_code, 200)
        data = verify_resp.json()
        self.assertTrue(data.get("is_verified"))
        self.assertIn("access_token", data)
        self.assertIn("user", data)
        self.assertTrue(data["user"].get("member_id").startswith("BM-"))

        # 4. Verify user can now log in directly
        login_resp = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": password
        })
        self.assertEqual(login_resp.status_code, 200)
        login_data = login_resp.json()
        self.assertTrue("access_token" in login_data or login_data.get("two_factor_required"))

    def test_invalid_otp_code_returns_400(self):
        password = "ValidPass123!#"
        reg_resp = self.client.post("/api/auth/register", json={
            "full_name": "Dr. James Smith",
            "email": self.test_email,
            "password": password
        })
        self.assertEqual(reg_resp.status_code, 201)

        # Submit wrong OTP
        verify_resp = self.client.post("/api/auth/verify-otp", json={
            "email": self.test_email,
            "otp_code": "000000"
        })
        self.assertEqual(verify_resp.status_code, 400)
        self.assertIn("Invalid verification code", verify_resp.json()["detail"])

if __name__ == "__main__":
    unittest.main()
