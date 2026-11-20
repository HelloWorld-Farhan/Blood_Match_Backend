import unittest
from fastapi.testclient import TestClient
from main import app, get_db
from models import EmergencyRequestModel, strip_honorific

client = TestClient(app)

class TestEmergencyUpsertAndLifecycle(unittest.TestCase):
    def test_emergency_modify_unique_id(self):
        req_id = "REQ-TEST-UNIQUE-001"
        payload1 = {
            "id": req_id,
            "user_email": "test.clinician@hospital.org",
            "patient_name": "Dr. Farhan Khalid",
            "patient_age": 25,
            "hospital": "Emergency Trauma Network",
            "hospital_city": "Rohini Sector 7",
            "ward": "Emergency Triage",
            "blood_type": "B+",
            "units_needed": 1,
            "urgency": "CRITICAL",
            "status": "urgent",
            "contact_person": "Dr. Farhan Khalid",
            "contact_phone": "+91 8851860838"
        }

        # Step 1: Initial check run
        res1 = client.post("/api/emergency", json=payload1)
        self.assertEqual(res1.status_code, 201)
        data1 = res1.json()
        self.assertEqual(data1["id"], req_id)
        self.assertEqual(data1["patient_name"], "Farhan Khalid")  # stripped honorific
        self.assertEqual(data1["contact_person"], "Farhan Khalid")
        self.assertEqual(data1["hospital_city"], "Rohini Sector 7")

        # Step 2: Modify & Re-Test with SAME ID
        payload2 = {
            "id": req_id,
            "user_email": "test.clinician@hospital.org",
            "patient_name": "Farhan Khalid",
            "patient_age": 26,
            "hospital": "Emergency Trauma Network",
            "hospital_city": "Jamia Nagar, Delhi",
            "ward": "Emergency Triage",
            "blood_type": "B+",
            "units_needed": 2,
            "urgency": "CRITICAL",
            "status": "urgent",
            "contact_person": "Farhan Khalid",
            "contact_phone": "+91 8851860838"
        }
        res2 = client.post("/api/emergency", json=payload2)
        self.assertEqual(res2.status_code, 201)
        data2 = res2.json()
        self.assertEqual(data2["id"], req_id)
        self.assertEqual(data2["hospital_city"], "Jamia Nagar, Delhi")
        self.assertEqual(data2["units_needed"], 2)

        # Step 3: Verify only ONE record exists for this user/id, not two
        list_res = client.get(f"/api/emergency?user_email=test.clinician@hospital.org")
        matching = [r for r in list_res.json() if r["id"] == req_id]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["hospital_city"], "Jamia Nagar, Delhi")

        # Step 4: Delete the test request
        del_res = client.delete(f"/api/emergency/{req_id}?user_email=test.clinician@hospital.org")
        self.assertEqual(del_res.status_code, 200)

if __name__ == "__main__":
    unittest.main()
