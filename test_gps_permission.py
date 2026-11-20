import unittest
from fastapi.testclient import TestClient
from database import init_db, SessionLocal
from main import app
from models import UserModel

class TestGpsPermission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        os.environ["MOCK_EXTERNAL_EMAIL"] = "1"
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        self.session = SessionLocal()
        import uuid
        self.test_email = f"gps.test.{uuid.uuid4().hex[:6]}@hospital.org"
        user = UserModel(
            full_name="GPS Tester",
            email=self.test_email,
            phone="+91 99999 88888",
            hashed_password="hashed_pass_placeholder",
            is_verified=True,
            gps_permission_enabled=False
        )
        self.session.add(user)
        self.session.commit()

    def tearDown(self):
        self.session.query(UserModel).filter(UserModel.email == self.test_email).delete()
        self.session.commit()
        self.session.close()

    def test_default_gps_permission_is_false(self):
        res = self.client.get(f"/api/user/gps-permission?email={self.test_email}")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json().get("gps_permission_enabled"))

    def test_toggle_gps_permission_on_and_off(self):
        # 1. Turn ON
        res_on = self.client.put("/api/user/gps-permission", json={
            "enabled": True,
            "user_email": self.test_email
        })
        self.assertEqual(res_on.status_code, 200)
        self.assertTrue(res_on.json().get("gps_permission_enabled"))

        # Verify GET returns True
        res_get = self.client.get(f"/api/user/gps-permission?email={self.test_email}")
        self.assertEqual(res_get.status_code, 200)
        self.assertTrue(res_get.json().get("gps_permission_enabled"))

        # 2. Turn OFF
        res_off = self.client.put("/api/user/gps-permission", json={
            "enabled": False,
            "user_email": self.test_email
        })
        self.assertEqual(res_off.status_code, 200)
        self.assertFalse(res_off.json().get("gps_permission_enabled"))
