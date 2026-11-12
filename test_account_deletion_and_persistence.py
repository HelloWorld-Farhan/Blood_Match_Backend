import unittest
import uuid
from fastapi.testclient import TestClient

from database import init_db, SessionLocal
from main import app
from models import UserModel, OtpTokenModel, DonorModel, ClinicianProfileModel
from auth_service import hash_password

class TestAccountDeletionAndPersistence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        self.db = SessionLocal()
        self.email = f"delete_test_{uuid.uuid4().hex[:6]}@hospital.org"
        self.password = "StrongP@ss2026!"
        self.user = UserModel(
            full_name="Deletion Test Clinician",
            email=self.email,
            phone="+91 9888888888",
            hashed_password=hash_password(self.password),
            is_verified=True,
            is_2fa_enabled=False
        )
        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

        # Add a donor registration for this user
        self.donor = DonorModel(
            id=f"DNR-{uuid.uuid4().hex[:6].upper()}",
            user_email=self.email,
            name="Deletion Test Clinician",
            blood_type="O+",
            phone="+91 9888888888",
            email=self.email,
            city="Metro City",
            is_available=True
        )
        self.db.add(self.donor)
        self.db.commit()

    def tearDown(self):
        try:
            self.db.query(DonorModel).filter(DonorModel.user_email == self.email).delete()
            self.db.query(OtpTokenModel).filter(OtpTokenModel.email == self.email).delete()
            self.db.query(UserModel).filter(UserModel.email == self.email).delete()
            self.db.commit()
        except Exception:
            self.db.rollback()
        finally:
            self.db.close()

    def test_account_deletion_flow(self):
        # 1. Login to obtain access token
        login_res = self.client.post("/api/auth/login", json={
            "email": self.email,
            "password": self.password,
            "device_id": "test-dev-del",
            "remember_device": True
        })
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Request Account Deletion OTP
        req_res = self.client.post("/api/auth/account-deletion/request-otp", headers=headers)
        self.assertEqual(req_res.status_code, 200)

        # Fetch generated deletion OTP
        otp_rec = self.db.query(OtpTokenModel).filter(
            OtpTokenModel.email == self.email,
            OtpTokenModel.token_type == "account_deletion",
            OtpTokenModel.is_used == False
        ).order_by(OtpTokenModel.created_at.desc()).first()
        self.assertIsNotNone(otp_rec)

        # 3. Confirm with wrong text -> Must fail (400)
        fail_text_res = self.client.post("/api/auth/account-deletion/confirm", json={
            "confirm_text": "no",
            "otp_code": otp_rec.otp_code
        }, headers=headers)
        self.assertEqual(fail_text_res.status_code, 400)

        # 4. Confirm with wrong OTP -> Must fail (400)
        fail_otp_res = self.client.post("/api/auth/account-deletion/confirm", json={
            "confirm_text": "DELETE",
            "otp_code": "000000"
        }, headers=headers)
        self.assertEqual(fail_otp_res.status_code, 400)

        # 5. Confirm with correct 'DELETE' and correct OTP -> Must succeed (200)
        success_res = self.client.post("/api/auth/account-deletion/confirm", json={
            "confirm_text": "DELETE",
            "otp_code": otp_rec.otp_code
        }, headers=headers)
        self.assertEqual(success_res.status_code, 200)
        self.assertTrue(success_res.json().get("success"))

        # 6. Verify User and Donor records are completely gone from DB
        user_check = self.db.query(UserModel).filter(UserModel.email == self.email).first()
        self.assertIsNone(user_check)
        donor_check = self.db.query(DonorModel).filter(DonorModel.user_email == self.email).first()
        self.assertIsNone(donor_check)

        # 7. Subsequent login must be rejected (401)
        subsequent_login = self.client.post("/api/auth/login", json={
            "email": self.email,
            "password": self.password,
            "device_id": "test-dev-del"
        })
        self.assertEqual(subsequent_login.status_code, 401)

if __name__ == "__main__":
    unittest.main()
