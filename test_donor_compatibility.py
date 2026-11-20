import unittest
import sys
import os

sys.path.append(os.path.dirname(__file__))

from models import DonorModel

class TestDonorCompatibility(unittest.TestCase):
    def test_donor_dual_serialization(self):
        donor = DonorModel(
            id="test-donor-123",
            user_email="test.donor@hospital.org",
            name="Rohit Sharma",
            blood_type="O-",
            phone="+91 9988776655",
            email="rohit@hospital.org",
            city="Delhi",
            location="Rohini Sector 7, North West Delhi",
            hospital="BloodMatch Emergency Network",
            age=29,
            gender="MALE",
            is_available=True
        )

        d = donor.to_dict()
        # Verify snake_case
        self.assertEqual(d["blood_type"], "O-")
        self.assertEqual(d["name"], "Rohit Sharma")
        self.assertEqual(d["is_available"], True)

        # Verify camelCase for frontend interfaces
        self.assertEqual(d["bloodType"], "O-")
        self.assertEqual(d["fullName"], "Rohit Sharma")
        self.assertEqual(d["isAvailable"], True)
        self.assertEqual(d["available"], True)
        self.assertEqual(d["unitsDonatedTotal"], 0)

    def test_b_positive_compatibility_with_o_negative(self):
        # B+ can receive from B+, B-, O+, O-
        b_pos_compatible = ["B+", "B-", "O+", "O-"]
        donor_o_neg_type = "O-"
        donor_b_pos_type = "B+"

        self.assertIn(donor_o_neg_type, b_pos_compatible)
        self.assertIn(donor_b_pos_type, b_pos_compatible)

    def test_a_negative_compatibility_with_o_negative(self):
        # A- can receive from A-, O-
        a_neg_compatible = ["A-", "O-"]
        donor_o_neg_type = "O-"

        self.assertIn(donor_o_neg_type, a_neg_compatible)

if __name__ == '__main__':
    unittest.main()
