import unittest
import uuid
from unittest.mock import patch
from fastapi.testclient import TestClient

from database import init_db, SessionLocal
from main import app
from models import UserModel, OtpTokenModel, TrustedDeviceModel, UserSessionModel
from auth_service import hash_password

class TestTwoFactorAuthToggle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        os.environ["MOCK_EXTERNAL_EMAIL"] = "1"
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        self.db = SessionLocal()
        self.email = f"test2fa_{uuid.uuid4().hex[:6]}@hospital.org"
        self.password = "SecuP@ss99!"
        self.user = UserModel(
            full_name="2FA Test User",
            email=self.email,
            phone="+91 9999999999",
            hashed_password=hash_password(self.password),
            is_verified=True,
            is_2fa_enabled=False
        )
        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

    def tearDown(self):
        try:
            self.db.query(OtpTokenModel).filter(OtpTokenModel.email == self.email).delete()
            self.db.query(TrustedDeviceModel).filter(TrustedDeviceModel.user_id == self.user.id).delete()
            self.db.query(UserSessionModel).filter(UserSessionModel.user_id == self.user.id).delete()
            self.db.query(UserModel).filter(UserModel.id == self.user.id).delete()
            self.db.commit()
        except Exception:
            self.db.rollback()
        finally:
            self.db.close()

    @patch("email_service._dispatch_google_apps_script", return_value=True)
    def test_direct_login_when_2fa_disabled_and_otp_when_enabled(self, mock_dispatch):
        payload = {
            "email": self.email,
            "password": self.password,
            "device_id": "test-dev-toggle",
            "device_name": "Test Browser",
            "remember_device": True
        }
        # 1. 2FA is OFF by default -> Direct login (no OTP needed)
        res = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data.get("two_factor_required"))
        self.assertIn("access_token", data)
        token = data["access_token"]

        # 2. Toggle 2FA to ON
        headers = {"Authorization": f"Bearer {token}"}
        toggle_res = self.client.put("/api/auth/2fa/toggle", json={"enable_2fa": True}, headers=headers)
        self.assertEqual(toggle_res.status_code, 200)
        self.assertTrue(toggle_res.json().get("is_2fa_enabled"))

        # 3. Login again -> 2FA is ON, so it MUST challenge with OTP
        res_2fa = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(res_2fa.status_code, 200)
        data_2fa = res_2fa.json()
        self.assertTrue(data_2fa.get("two_factor_required"))
        self.assertNotIn("access_token", data_2fa)

        # 4. Verify 2FA with generated token
        otp_rec = self.db.query(OtpTokenModel).filter(
            OtpTokenModel.email == self.email,
            OtpTokenModel.token_type == "2fa_login",
            OtpTokenModel.is_used == False
        ).order_by(OtpTokenModel.created_at.desc()).first()
        self.assertIsNotNone(otp_rec)

        verify_res = self.client.post("/api/auth/2fa/verify", json={
            "email": self.email,
            "otp_code": otp_rec.otp_code,
            "device_id": "test-dev-toggle",
            "remember_device": True
        })
        self.assertEqual(verify_res.status_code, 200)
        self.assertIn("access_token", verify_res.json())

        # 5. Toggle 2FA back to OFF
        new_token = verify_res.json()["access_token"]
        new_headers = {"Authorization": f"Bearer {new_token}"}
        toggle_off_res = self.client.put("/api/auth/2fa/toggle", json={"enable_2fa": False}, headers=new_headers)
        self.assertEqual(toggle_off_res.status_code, 200)
        self.assertFalse(toggle_off_res.json().get("is_2fa_enabled"))

        # 6. Login again -> 2FA is OFF, direct login
        res_after = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(res_after.status_code, 200)
        self.assertFalse(res_after.json().get("two_factor_required"))
        self.assertIn("access_token", res_after.json())

if __name__ == "__main__":
    unittest.main()
