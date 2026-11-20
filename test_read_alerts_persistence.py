import unittest
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal, init_db
import models

class TestReadAlertsPersistence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.client = TestClient(app)
        self.db = SessionLocal()
        self.user_email = "clinician.test_alerts@hospital.org"

        # Ensure user exists
        user = self.db.query(models.UserModel).filter(models.UserModel.email == self.user_email).first()
        if not user:
            user = models.UserModel(
                email=self.user_email,
                full_name="Test Clinician",
                hashed_password="dummy_hashed_pw",
                read_alert_ids="[]"
            )
            self.db.add(user)
            self.db.commit()
        else:
            user.read_alert_ids = "[]"
            self.db.commit()

    def tearDown(self):
        user = self.db.query(models.UserModel).filter(models.UserModel.email == self.user_email).first()
        if user:
            self.db.delete(user)
            self.db.commit()
        self.db.close()

    def test_read_ids_get_and_post_persistence(self):
        # 1. Initially empty read_alert_ids
        get_res = self.client.get(f"/api/alerts/read-ids?user_email={self.user_email}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["read_alert_ids"], [])

        # 2. Mark specific alerts as read
        post_res = self.client.post("/api/alerts/mark-read", json={
            "user_email": self.user_email,
            "alert_ids": ["ALT-001", "ALT-002"],
            "mark_all": False
        })
        self.assertEqual(post_res.status_code, 200)
        self.assertIn("ALT-001", post_res.json()["read_alert_ids"])
        self.assertIn("ALT-002", post_res.json()["read_alert_ids"])

        # 3. Retrieve persistent read alerts
        get_res2 = self.client.get(f"/api/alerts/read-ids?user_email={self.user_email}")
        self.assertEqual(get_res2.status_code, 200)
        self.assertIn("ALT-001", get_res2.json()["read_alert_ids"])
        self.assertIn("ALT-002", get_res2.json()["read_alert_ids"])

        # 4. Mark all read
        post_res_all = self.client.post("/api/alerts/mark-read", json={
            "user_email": self.user_email,
            "mark_all": True
        })
        self.assertEqual(post_res_all.status_code, 200)
        self.assertTrue(post_res_all.json()["success"])

if __name__ == "__main__":
    unittest.main()
