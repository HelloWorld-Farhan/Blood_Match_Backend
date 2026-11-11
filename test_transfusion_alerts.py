import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal, init_db
import models

class TestTransfusionAlertsAndExclusion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.client = TestClient(app)
        self.db = SessionLocal()
        self.user_a = "registrant.alice@hospital.org"
        self.user_b = "clinician.bob@hospital.org"
        self.user_c = "intruder.charlie@hospital.org"
        self.donor_email = "alice.donor@example.com"
        # Clean any alerts created by user_a
        self.db.query(models.TransfusionAlertModel).filter(
            models.TransfusionAlertModel.creator_email == self.user_a
        ).delete(synchronize_session=False)
        self.db.commit()

    def tearDown(self):
        self.db.query(models.TransfusionAlertModel).filter(
            models.TransfusionAlertModel.creator_email.in_([self.user_a, self.user_b, self.donor_email])
        ).delete(synchronize_session=False)
        self.db.query(models.DonorModel).filter(
            models.DonorModel.user_email.in_([self.user_a, self.user_b, self.donor_email])
        ).delete(synchronize_session=False)
        self.db.query(models.OtpTokenModel).filter(
            models.OtpTokenModel.user_id.in_([self.user_a, self.user_b, self.donor_email])
        ).delete(synchronize_session=False)
        self.db.commit()
        self.db.close()

    @patch("email_service._dispatch_google_apps_script")
    def test_01_alert_created_and_excluded_for_creator(self, mock_gas):
        mock_gas.return_value = True

        # 1. Send OTP for donor
        self.client.post("/api/donors/send-otp", json={
            "email": self.donor_email,
            "name": "Alice Pledged Donor"
        })
        otp = self.db.query(models.OtpTokenModel).filter(
            models.OtpTokenModel.user_id == self.donor_email
        ).first()
        self.assertIsNotNone(otp)

        # 2. Register donor as User A
        reg_resp = self.client.post("/api/donors", json={
            "name": "Alice Pledged Donor",
            "blood_type": "AB-",
            "phone": "+91 9876543210",
            "email": self.donor_email,
            "city": "Delhi",
            "location": "Saket, South Delhi",
            "age": 27,
            "gender": "FEMALE",
            "user_email": self.user_a,
            "otp_code": otp.otp_code
        })
        self.assertEqual(reg_resp.status_code, 201)
        donor_id = reg_resp.json()["id"]

        # 3. User A queries alerts: MUST NOT contain any alerts created by User A (creator exclusion rule)
        alerts_a = self.client.get(f"/api/alerts?user_email={self.user_a}")
        self.assertEqual(alerts_a.status_code, 200)
        matching_own_alerts = [a for a in alerts_a.json() if a.get("creator_email") == self.user_a]
        self.assertEqual(len(matching_own_alerts), 0, "Creator must NOT receive alerts for their own donor registry")

        # 4. User B queries alerts: MUST BE 1 with donor details and location
        alerts_b = self.client.get(f"/api/alerts?user_email={self.user_b}")
        self.assertEqual(alerts_b.status_code, 200)
        b_list = alerts_b.json()
        self.assertGreaterEqual(len(b_list), 1)
        matching_alert = next((a for a in b_list if a["donor_id"] == donor_id), None)
        self.assertIsNotNone(matching_alert)
        self.assertEqual(matching_alert["blood_type"], "AB-")
        self.assertIn("Saket", matching_alert["location"])

        # 5. User C attempts unauthorized deletion: MUST BE 403 Forbidden
        del_unauth = self.client.delete(f"/api/donors/{donor_id}?user_email={self.user_c}")
        self.assertEqual(del_unauth.status_code, 403)

        # 6. User A (owner) deletes donor: MUST succeed with 200
        del_auth = self.client.delete(f"/api/donors/{donor_id}?user_email={self.user_a}")
        self.assertEqual(del_auth.status_code, 200)

        # 7. Check alerts again: zero deletion alerts created
        alerts_b_after = self.client.get(f"/api/alerts?user_email={self.user_b}").json()
        matching_after = [a for a in alerts_b_after if a["donor_id"] == donor_id]
        self.assertEqual(len(matching_after), 0, "Zero deletion notification should be sent")

if __name__ == "__main__":
    unittest.main()
