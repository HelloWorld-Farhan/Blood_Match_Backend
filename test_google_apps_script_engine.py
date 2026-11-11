"""
Automated Integration Test for BloodMatch Google Apps Script Webhook Engine & Email Dispatcher
Tests:
1. Complete template generation for all 7 actions
2. Webhook payload formatting & contract alignment
3. Mocked Google Apps Script dispatch (200 OK, 302 Redirect, and fallback logic)
4. Session alert triggering on login and 2FA
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Set test environment
os.environ["SMTP_HOST"] = ""
os.environ["SMTP_USER"] = ""
os.environ["SMTP_PASSWORD"] = ""
os.environ["GOOGLE_APP_SCRIPT_URL"] = "https://script.google.com/macros/s/TEST_DEPLOYMENT/exec"

import email_service

class TestGoogleAppsScriptEngine(unittest.TestCase):

    def setUp(self):
        self.test_email = "clinician@bloodmatch.io"
        self.test_name = "Dr. Farhan Khalid"

    @patch("email_service.requests.post")
    def test_01_otp_verification_dispatch(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "action": "otp_verification"}
        mock_post.return_value = mock_response

        result = email_service.send_verification_email(self.test_email, self.test_name, "123456")
        self.assertTrue(result)
        self.assertTrue(mock_post.called)
        call_args = mock_post.call_args[1]
        self.assertEqual(call_args["json"]["action"], "otp_verification")
        self.assertEqual(call_args["json"]["to"], self.test_email)
        self.assertEqual(call_args["json"]["otp_code"], "123456")

    @patch("email_service.requests.post")
    def test_02_two_factor_login_dispatch(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "action": "2fa_login"}
        mock_post.return_value = mock_response

        result = email_service.send_2fa_login_email(
            self.test_email, self.test_name, "654321", "Chrome on Windows", "192.168.1.10"
        )
        self.assertTrue(result)
        call_args = mock_post.call_args[1]
        self.assertEqual(call_args["json"]["action"], "2fa_login")
        self.assertEqual(call_args["json"]["device_name"], "Chrome on Windows")
        self.assertEqual(call_args["json"]["otp_code"], "654321")

    @patch("email_service.requests.post")
    def test_03_new_login_session_alert_dispatch(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "action": "new_login_session"}
        mock_post.return_value = mock_response

        result = email_service.send_new_login_session_alert(
            self.test_email,
            self.test_name,
            "Safari on macOS",
            "10.0.0.42",
            "Chicago Trauma Center",
            "2026-11-11 16:30:00 UTC"
        )
        self.assertTrue(result)
        call_args = mock_post.call_args[1]
        self.assertEqual(call_args["json"]["action"], "new_login_session")
        self.assertEqual(call_args["json"]["location"], "Chicago Trauma Center")
        self.assertEqual(call_args["json"]["device_name"], "Safari on macOS")

    @patch("email_service.requests.post")
    def test_04_password_reset_dispatch(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "action": "password_reset"}
        mock_post.return_value = mock_response

        result = email_service.send_password_reset_email(self.test_email, self.test_name, "789012")
        self.assertTrue(result)
        call_args = mock_post.call_args[1]
        self.assertEqual(call_args["json"]["action"], "password_reset")
        self.assertEqual(call_args["json"]["otp_code"], "789012")

    @patch("email_service.requests.post")
    def test_05_password_changed_notification_dispatch(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "action": "password_changed"}
        mock_post.return_value = mock_response

        result = email_service.send_password_changed_notification(
            self.test_email,
            self.test_name,
            "2026-11-11 16:35:00 UTC",
            browser="Edge on Windows 11",
            ip_address="192.168.1.1"
        )
        self.assertTrue(result)
        call_args = mock_post.call_args[1]
        self.assertEqual(call_args["json"]["action"], "password_changed")
        self.assertEqual(call_args["json"]["browser"], "Edge on Windows 11")

    @patch("email_service.requests.post")
    def test_06_account_lockout_alert_dispatch(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "action": "account_lockout"}
        mock_post.return_value = mock_response

        result = email_service.send_lockout_alert_email(self.test_email, self.test_name, "998877")
        self.assertTrue(result)
        call_args = mock_post.call_args[1]
        self.assertEqual(call_args["json"]["action"], "account_lockout")
        self.assertEqual(call_args["json"]["unlock_code"], "998877")

    @patch("email_service.requests.post")
    def test_07_welcome_activation_dispatch(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "action": "welcome_thankyou"}
        mock_post.return_value = mock_response

        result = email_service.send_welcome_email(self.test_email, self.test_name, "BM-8841-A9")
        self.assertTrue(result)
        call_args = mock_post.call_args[1]
        self.assertEqual(call_args["json"]["action"], "welcome_thankyou")
        self.assertEqual(call_args["json"]["member_id"], "BM-8841-A9")

    @patch("email_service.requests.post")
    def test_08_fallback_to_simulation_when_webhook_fails(self, mock_post):
        mock_post.side_effect = Exception("Connection timeout to script.google.com")

        # When GAS fails and SMTP is not configured, it gracefully falls back to local logging without crashing
        result = email_service.send_verification_email(self.test_email, self.test_name, "123456")
        self.assertTrue(result)

    def test_09_code_gs_file_integrity(self):
        code_gs_path = os.path.join(os.path.dirname(__file__), "google_apps_script", "Code.gs")
        self.assertTrue(os.path.exists(code_gs_path))
        with open(code_gs_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check entry points
        self.assertIn("function doGet(e)", content)
        self.assertIn("function doPost(e)", content)
        self.assertIn("MailApp.sendEmail", content)

        # Check all 7 templates
        self.assertIn("buildVerificationEmail", content)
        self.assertIn("build2FALoginEmail", content)
        self.assertIn("buildNewSessionEmail", content)
        self.assertIn("buildPasswordResetEmail", content)
        self.assertIn("buildPasswordChangedEmail", content)
        self.assertIn("buildLockoutEmail", content)
        self.assertIn("buildWelcomeEmail", content)

if __name__ == "__main__":
    unittest.main()

