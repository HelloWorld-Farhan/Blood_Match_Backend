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
        os.environ["TESTING"] = "1"
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
        self.assertIn("Dr. Farhan Khalid", data["user_name"])

        # 2. Lookup with full international formatted phone
        resp2 = self.client.get("/api/auth/phone-lookup", params={"phone": "+91 98765 43210"})
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertTrue(data2["found"])
        self.assertEqual(data2["dial_code"], "+91")

    def test_credential_lookup_endpoint_email_and_phone(self):
        # 1. Lookup by registered email
        resp_email = self.client.get("/api/auth/credential-lookup", params={"identifier": self.test_email})
        self.assertEqual(resp_email.status_code, 200)
        data_email = resp_email.json()
        self.assertTrue(data_email["found"])
        self.assertEqual(data_email["user_name"], "Dr. Farhan Khalid")
        self.assertEqual(data_email["first_name"], "Dr.")
        self.assertEqual(data_email["email"], self.test_email)

        # 2. Lookup by registered phone number
        resp_phone = self.client.get("/api/auth/credential-lookup", params={"identifier": "9876543210"})
        self.assertEqual(resp_phone.status_code, 200)
        data_phone = resp_phone.json()
        self.assertTrue(data_phone["found"])
        self.assertEqual(data_phone["user_name"], "Dr. Farhan Khalid")

        # 3. Lookup by unknown email
        resp_unknown = self.client.get("/api/auth/credential-lookup", params={"identifier": "unknown.user@hospital.org"})
        self.assertEqual(resp_unknown.status_code, 200)
        self.assertFalse(resp_unknown.json()["found"])

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

    def test_login_by_unlinked_phone_fails_401(self):
        # An unlinked phone number must strictly be rejected with 401
        payload = {
            "identifier": "9811122233",
            "password": self.password,
            "device_id": "test-device-unlinked"
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("invalid", resp.json()["detail"].lower())

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

    def test_verify_otp_marks_device_as_primary(self):
        # Test that registration OTP verification marks the registering device as primary
        new_email = f"primary.reg.{uuid.uuid4().hex[:6]}@hospital.org"
        signup_dev_id = f"signup-dev-{uuid.uuid4().hex[:6]}"

        req_resp = self.client.post("/api/auth/register", json={
            "email": new_email,
            "full_name": "Dr. Primary Tester",
            "phone": "+91 91111 22222",
            "password": self.password
        })
        self.assertIn(req_resp.status_code, [200, 201])

        # Get the OTP from db
        otp_entry = self.session.query(OtpTokenModel).filter(OtpTokenModel.email == new_email).order_by(OtpTokenModel.created_at.desc()).first()
        self.assertIsNotNone(otp_entry)

        # Verify OTP
        verify_resp = self.client.post("/api/auth/verify-otp", json={
            "email": new_email,
            "otp_code": otp_entry.otp_code,
            "device_id": signup_dev_id
        })
        self.assertEqual(verify_resp.status_code, 200)

        # Check DB user has primary device
        created_user = self.session.query(UserModel).filter(UserModel.email == new_email).first()
        self.assertIsNotNone(created_user)
        self.assertTrue(created_user.is_device_primary(signup_dev_id))

        # Check session is marked primary
        sessions = self.session.query(UserSessionModel).filter(UserSessionModel.user_id == created_user.id).all()
        self.assertTrue(any(s.is_primary for s in sessions))

        # Cleanup
        self.session.query(OtpTokenModel).filter(OtpTokenModel.email == new_email).delete()
        self.session.query(UserSessionModel).filter(UserSessionModel.user_id == created_user.id).delete()
        self.session.query(UserModel).filter(UserModel.email == new_email).delete()
        self.session.commit()

    def test_primary_device_suppresses_login_alert_email(self):
        # Register user with a primary device
        primary_dev = f"dev-primary-{uuid.uuid4().hex[:6]}"
        self.user.add_primary_device(primary_dev)
        self.session.commit()

        with patch("main.send_new_login_session_alert") as mock_send_alert:
            login_resp = self.client.post("/api/auth/login", json={
                "identifier": self.test_email,
                "password": self.password,
                "device_id": primary_dev
            })
            self.assertEqual(login_resp.status_code, 200)
            # Alert email MUST be suppressed for primary device
            mock_send_alert.assert_not_called()

    def test_non_primary_device_triggers_login_alert_email(self):
        non_primary_dev = f"dev-secondary-{uuid.uuid4().hex[:6]}"

        with patch("main.send_new_login_session_alert") as mock_send_alert:
            login_resp = self.client.post("/api/auth/login", json={
                "identifier": self.test_email,
                "password": self.password,
                "device_id": non_primary_dev
            })
            self.assertEqual(login_resp.status_code, 200)
            # Alert email MUST be called for non-primary device
            mock_send_alert.assert_called_once()

    def test_toggle_primary_device_status_allows_multiple_primary(self):
        dev1 = f"dev-multi-1-{uuid.uuid4().hex[:6]}"
        dev2 = f"dev-multi-2-{uuid.uuid4().hex[:6]}"

        # Login from dev1
        resp1 = self.client.post("/api/auth/login", json={
            "identifier": self.test_email,
            "password": self.password,
            "device_id": dev1
        })
        token1 = resp1.json()["access_token"]

        # Login from dev2
        resp2 = self.client.post("/api/auth/login", json={
            "identifier": self.test_email,
            "password": self.password,
            "device_id": dev2
        })

        # Fetch sessions
        sessions_resp = self.client.get("/api/sessions", headers={"Authorization": f"Bearer {token1}"})
        self.assertEqual(sessions_resp.status_code, 200)
        sessions = sessions_resp.json()
        self.assertGreaterEqual(len(sessions), 2)

        s1 = next(s for s in sessions if s.get("device_id") == dev1)
        s2 = next(s for s in sessions if s.get("device_id") == dev2)

        # Mark dev1 as primary
        patch_resp1 = self.client.patch(
            f"/api/sessions/{s1['id']}/primary",
            json={"is_primary": True},
            headers={"Authorization": f"Bearer {token1}"}
        )
        self.assertEqual(patch_resp1.status_code, 200)
        self.assertTrue(patch_resp1.json()["is_primary"])

        # Mark dev2 as primary as well (Multiple primary support)
        patch_resp2 = self.client.patch(
            f"/api/sessions/{s2['id']}/primary",
            json={"is_primary": True},
            headers={"Authorization": f"Bearer {token1}"}
        )
        self.assertEqual(patch_resp2.status_code, 200)
        self.assertTrue(patch_resp2.json()["is_primary"])

        # Refresh user from DB
        self.session.refresh(self.user)
        self.assertTrue(self.user.is_device_primary(dev1))
        self.assertTrue(self.user.is_device_primary(dev2))

        # Unmark dev1 from primary
        unmark_resp = self.client.patch(
            f"/api/sessions/{s1['id']}/primary",
            json={"is_primary": False},
            headers={"Authorization": f"Bearer {token1}"}
        )
        self.assertEqual(unmark_resp.status_code, 200)
        self.assertFalse(unmark_resp.json()["is_primary"])

        self.session.refresh(self.user)
        self.assertFalse(self.user.is_device_primary(dev1))
        self.assertTrue(self.user.is_device_primary(dev2))

    def test_registration_rejects_duplicate_email(self):
        # Attempt to register with self.user.email which is verified
        resp = self.client.post("/api/auth/register", json={
            "email": self.test_email,
            "full_name": "Duplicate Tester",
            "phone": "+91 99999 00000",
            "password": "Password99!#"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("already exists", resp.json()["detail"].lower())

    def test_registration_rejects_duplicate_phone(self):
        # Attempt to register with self.primary_phone which belongs to self.user
        new_email = f"other.clinician.{uuid.uuid4().hex[:6]}@hospital.org"
        resp = self.client.post("/api/auth/register", json={
            "email": new_email,
            "full_name": "Another Clinician",
            "phone": self.primary_phone,
            "password": "Password99!#"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("mobile number is already registered", resp.json()["detail"].lower())

    def test_login_by_email_and_by_phone_open_identical_account(self):
        # 1. Login with email
        resp_email = self.client.post("/api/auth/login", json={
            "identifier": self.test_email,
            "password": self.password,
            "device_id": "device-email-login"
        })
        self.assertEqual(resp_email.status_code, 200)
        data_email = resp_email.json()

        # 2. Login with phone (omitting country code)
        resp_phone = self.client.post("/api/auth/login", json={
            "identifier": "9876543210",
            "password": self.password,
            "device_id": "device-phone-login"
        })
        self.assertEqual(resp_phone.status_code, 200)
        data_phone = resp_phone.json()

        # Both MUST authenticate as the identical user
        self.assertEqual(data_email["user"]["id"], data_phone["user"]["id"])
        self.assertEqual(data_email["user"]["email"], data_phone["user"]["email"])
        self.assertEqual(data_email["user"]["phone"], data_phone["user"]["phone"])
        self.assertEqual(data_email["user"]["full_name"], data_phone["user"]["full_name"])

    def test_profile_update_preserves_immutable_phone(self):
        login_resp = self.client.post("/api/auth/login", json={
            "identifier": self.test_email,
            "password": self.password
        })
        token = login_resp.json()["access_token"]

        # Attempt to update name and change phone
        update_resp = self.client.put(
            "/api/profile",
            json={
                "full_name": "Dr. Farhan Khalid Updated",
                "phone": "+1 999 888 7777"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(update_resp.status_code, 200)

        # Refresh user from DB - name should update, phone must remain unchanged
        self.session.refresh(self.user)
        self.assertEqual(self.user.full_name, "Dr. Farhan Khalid Updated")
        self.assertEqual(self.user.phone, self.primary_phone)

    def test_password_reset_by_phone_number_dispatches_to_linked_email(self):
        # 1. User submits only their 10-digit mobile number for password reset
        req_resp = self.client.post("/api/auth/password-reset/request", json={
            "identifier": "9876543210"
        })
        self.assertEqual(req_resp.status_code, 200)
        req_data = req_resp.json()
        self.assertEqual(req_data["email"], self.test_email)
        self.assertIn("@hospital.org", req_data["masked_email"])

        # 2. Retrieve generated reset OTP from database
        otp_record = (
            self.session.query(OtpTokenModel)
            .filter(OtpTokenModel.email == self.test_email, OtpTokenModel.token_type == "password_reset", OtpTokenModel.is_used == False)
            .order_by(OtpTokenModel.created_at.desc())
            .first()
        )
        self.assertIsNotNone(otp_record)

        # 3. Verify OTP using the phone number
        verify_resp = self.client.post("/api/auth/password-reset/verify", json={
            "identifier": "9876543210",
            "otp_code": otp_record.otp_code
        })
        self.assertEqual(verify_resp.status_code, 200)
        reset_token = verify_resp.json()["reset_token"]
        self.assertTrue(len(reset_token) > 20)

        # 4. Confirm new password using the phone number
        new_pwd = "BrandNewPassword99!#"
        confirm_resp = self.client.post("/api/auth/password-reset/confirm", json={
            "identifier": "9876543210",
            "reset_token": reset_token,
            "new_password": new_pwd
        })
        self.assertEqual(confirm_resp.status_code, 200)

        # 5. Verify user can now log in using phone number and new password
        login_resp = self.client.post("/api/auth/login", json={
            "identifier": "9876543210",
            "password": new_pwd
        })
        self.assertEqual(login_resp.status_code, 200)
        self.assertEqual(login_resp.json()["user"]["email"], self.test_email)

if __name__ == "__main__":
    unittest.main()
