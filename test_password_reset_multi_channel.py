import unittest
from datetime import datetime
from unittest.mock import patch
from fastapi.testclient import TestClient

from database import init_db, SessionLocal
from main import app
from models import UserModel, OtpTokenModel, PasswordHistoryModel
from auth_service import hash_password

class TestPasswordResetMultiChannel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        os.environ["MOCK_EXTERNAL_EMAIL"] = "1"
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        self.db = SessionLocal()
        self.db.query(PasswordHistoryModel).delete()
        self.db.query(OtpTokenModel).delete()
        self.db.query(UserModel).delete()
        self.db.commit()

        # Seed test clinician
        self.test_email = "clinician.pw@hospital.org"
        self.initial_password = "OldStrongPassword@2026!"
        self.user = UserModel(
            email=self.test_email,
            full_name="Dr. PW Tester",
            hashed_password=hash_password(self.initial_password),
            is_verified=True
        )
        self.db.add(self.user)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_01_verify_current_password_correct(self):
        resp = self.client.post("/api/auth/password-update/verify-current", json={
            "email": self.test_email,
            "current_password": self.initial_password
        })
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json().get("valid"))

    def test_02_verify_current_password_incorrect(self):
        resp = self.client.post("/api/auth/password-update/verify-current", json={
            "email": self.test_email,
            "current_password": "WrongPassword@999"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Previous (current) password is incorrect", resp.json().get("detail", ""))

    def test_03_update_by_previous_password_success(self):
        new_password = "BrandNewPassword@2027#!"
        resp = self.client.post("/api/auth/password-update/previous", json={
            "email": self.test_email,
            "current_password": self.initial_password,
            "new_password": new_password
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Security password updated successfully", resp.json().get("message", ""))

        # Verify old password no longer works
        verify_old = self.client.post("/api/auth/password-update/verify-current", json={
            "email": self.test_email,
            "current_password": self.initial_password
        })
        self.assertEqual(verify_old.status_code, 400)

        # Verify new password works
        verify_new = self.client.post("/api/auth/password-update/verify-current", json={
            "email": self.test_email,
            "current_password": new_password
        })
        self.assertEqual(verify_new.status_code, 200)

    def test_04_update_by_previous_password_rejects_identical(self):
        # Trying to set new password equal to previous password
        resp = self.client.post("/api/auth/password-update/previous", json={
            "email": self.test_email,
            "current_password": self.initial_password,
            "new_password": self.initial_password
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("cannot be identical to your previous password", resp.json().get("detail", ""))

    @patch("email_service._dispatch_google_apps_script", return_value=True)
    def test_05_email_otp_flow_and_rejection_of_previous_password(self, mock_dispatch):
        # 1. Request OTP
        req_resp = self.client.post("/api/auth/password-reset/request", json={
            "email": self.test_email
        })
        self.assertEqual(req_resp.status_code, 200)

        # Retrieve generated OTP from DB
        token_rec = self.db.query(OtpTokenModel).filter(
            OtpTokenModel.email == self.test_email,
            OtpTokenModel.token_type == "password_reset",
            OtpTokenModel.is_used == False
        ).order_by(OtpTokenModel.created_at.desc()).first()
        self.assertIsNotNone(token_rec)

        # 2. Verify OTP
        ver_resp = self.client.post("/api/auth/password-reset/verify", json={
            "email": self.test_email,
            "otp_code": token_rec.otp_code
        })
        self.assertEqual(ver_resp.status_code, 200)
        reset_token = ver_resp.json().get("reset_token")
        self.assertTrue(bool(reset_token))

        # 3. Confirm with identical password -> must reject
        reject_resp = self.client.post("/api/auth/password-reset/confirm", json={
            "email": self.test_email,
            "reset_token": reset_token,
            "new_password": self.initial_password
        })
        self.assertEqual(reject_resp.status_code, 400)
        self.assertIn("cannot be identical to your current password", reject_resp.json().get("detail", ""))

        # 4. Confirm with novel strong password -> must succeed
        new_pw = "AnotherSuperFreshPW@2028$$"
        ok_resp = self.client.post("/api/auth/password-reset/confirm", json={
            "email": self.test_email,
            "reset_token": reset_token,
            "new_password": new_pw
        })
        self.assertEqual(ok_resp.status_code, 200)

if __name__ == "__main__":
    unittest.main()
