import unittest
import json
from models import UserModel

class TestPhoneDeduplication(unittest.TestCase):
    def test_deduplicate_same_10_digits_with_and_without_country_code(self):
        user = UserModel(phone="+91 8851860838")
        user.add_saved_phone("8851860838")
        phones = user.get_saved_phones()
        self.assertEqual(len(phones), 1)
        self.assertEqual(phones[0], "+91 8851860838")

    def test_upgrade_raw_phone_when_country_code_added_later(self):
        user = UserModel(phone=None)
        user.add_saved_phone("8851860838")
        self.assertEqual(user.get_saved_phones(), ["8851860838"])
        user.add_saved_phone("+91 8851860838")
        self.assertEqual(user.get_saved_phones(), ["+91 8851860838"])

    def test_preserves_different_10_digit_numbers(self):
        user = UserModel(phone="+91 8851860838")
        user.add_saved_phone("9988776655")
        phones = user.get_saved_phones()
        self.assertEqual(len(phones), 2)
        self.assertIn("+91 8851860838", phones)
        self.assertIn("9988776655", phones)

if __name__ == '__main__':
    unittest.main()
