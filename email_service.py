import os
import re
import smtplib
import logging
import base64
from datetime import datetime
from typing import Optional, List
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import requests
from jinja2 import Template

logger = logging.getLogger("BloodBackend.EmailService")

def sanitize_recipient_name(name: Optional[str]) -> str:
    """Completely strips honorifics (Dr., Dr, Doctor, etc.) so user is addressed cleanly."""
    if not name:
        return "Clinician"
    cleaned = re.sub(r'^(?:Dr\.?|Doctor|Prof\.?|Mr\.?|Mrs\.?|Ms\.?)\s+', '', str(name).strip(), flags=re.IGNORECASE).strip()
    return cleaned or "Clinician"

# Environment-based SMTP configuration (Zero hardcoded credentials)
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "security@bloodmatch.io").strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "BloodMatch Transfusion Network").strip()
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")

# Autonomous Google Apps Script Webhook Integration (strictly from environment)
GOOGLE_APP_SCRIPT_URL = os.getenv("GOOGLE_APP_SCRIPT_URL", "").strip()

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates", "email")

def load_template(filename: str, fallback_string: str) -> Template:
    """Loads a template file from templates/email/ or uses the fallback inline string."""
    file_path = os.path.join(TEMPLATES_DIR, filename)
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return Template(f.read())
        except Exception as exc:
            logger.warning(f"Could not load external template {filename}: {exc}")
    return Template(fallback_string)

# =========================================================================
# MINIMAL, BUTTON-FREE INLINE FALLBACK TEMPLATES (EXACT MATCH TO UI DESIGN)
# =========================================================================

EMAIL_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>Account Verification Code</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
    .header { padding: 24px 32px 16px 32px; border-bottom: 1px solid #F5F1EF; }
    .brand-pill { display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 700; color: #D72638; text-transform: uppercase; }
    .content { padding: 32px; }
    .title { font-size: 22px; font-weight: 900; color: #1A1D20; margin: 0 0 10px 0; }
    .greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }
    .paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }
    .otp-container { background: #FDF9F8; border: 1.5px dashed #D72638; border-radius: 14px; padding: 20px 16px; text-align: center; margin: 20px 0; }
    .otp-label { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .otp-code { font-family: monospace; font-size: 38px; font-weight: 900; letter-spacing: 10px; color: #D72638; display: inline-block; margin: 0; }
    .otp-validity { margin-top: 10px; font-size: 12px; color: #7A0C17; font-weight: 600; }
    .notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 20px; }
    .notice-box strong { color: #D72638; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
    @media only screen and (max-width: 600px) {
      .wrapper { padding: 12px 8px !important; }
      .card { border-radius: 14px !important; width: 100% !important; }
      .content { padding: 18px 14px !important; }
      .header { padding: 16px 14px 12px 14px !important; }
      .footer { padding: 14px 12px !important; }
      .audit-card, .status-card, .member-box, .pledge-box { padding: 12px 12px !important; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">BloodMatch Clinical Network</span></div>
      <div class="content">
        <h1 class="title">Account Verification Code</h1>
        <div class="greeting">Hello, {{ name }}</div>
        <p class="paragraph">Thank you for registering with the BloodMatch Transfusion Network. Please use the following single-use verification code in the application to activate your clinical profile.</p>
        <div style="background: #F8FAFC; border: 1.5px solid #E2E8F0; border-radius: 16px; padding: 22px 16px; text-align: center; margin: 22px 0;">
          <div style="font-size: 11px; font-weight: 800; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Code Requested</div>
          <table align="center" border="0" cellpadding="0" cellspacing="6" style="margin: 0 auto;">
            <tr>
              {% for d in otp_code %}
              <td align="center" style="width: 44px; height: 50px; background: #FFFFFF; border: 1.5px solid #CBD5E1; border-radius: 10px; font-family: monospace, -apple-system, BlinkMacSystemFont, sans-serif; font-size: 26px; font-weight: 800; color: #1E293B; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.06);">
                {{ d }}
              </td>
              {% endfor %}
            </tr>
          </table>
          <div style="margin-top: 16px;">
            <span style="display: inline-block; padding: 8px 22px; background: #0284C7; color: #FFFFFF; border-radius: 24px; font-size: 13px; font-weight: 700; text-decoration: none;">Copy code</span>
          </div>
          <div style="margin-top: 12px; font-size: 12px; color: #64748B; font-weight: 600;">⏱ Valid for 10 minutes • Single device session</div>
        </div>
        <div class="notice-box"><strong>Security Notice:</strong> Never share this verification token with anyone. BloodMatch personnel will never ask for your authentication codes.</div>
      </div>
      <div class="footer">BloodMatch Emergency Transfusion Network • Automated Clinical Dispatch Node<br>If you did not request this registration, please disregard this email.</div>
    </div>
  </div>
</body>
</html>
"""

LOCKOUT_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>CRITICAL: Account Lockout Security Alert</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1.5px solid #D72638; border-radius: 20px; overflow: hidden; }
    .header { padding: 24px 32px 16px 32px; border-bottom: 1px solid #F5F1EF; }
    .brand-pill { display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 800; color: #D72638; text-transform: uppercase; }
    .content { padding: 32px; }
    .title { font-size: 22px; font-weight: 900; color: #7A0C17; margin: 0 0 10px 0; }
    .greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }
    .paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }
    .unlock-container { background: #FFF5F5; border: 1.5px solid #D72638; border-radius: 14px; padding: 20px 16px; text-align: center; margin: 20px 0; }
    .unlock-label { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .unlock-code { font-family: monospace; font-size: 38px; font-weight: 900; letter-spacing: 10px; color: #D72638; display: inline-block; margin: 0; }
    .unlock-validity { margin-top: 10px; font-size: 12px; color: #7A0C17; font-weight: 600; }
    .notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 20px; }
    .notice-box strong { color: #D72638; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
    @media only screen and (max-width: 600px) {
      .wrapper { padding: 12px 8px !important; }
      .card { border-radius: 14px !important; width: 100% !important; }
      .content { padding: 18px 14px !important; }
      .header { padding: 16px 14px 12px 14px !important; }
      .footer { padding: 14px 12px !important; }
      .audit-card, .status-card, .member-box, .pledge-box { padding: 12px 12px !important; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">Critical Security Defense</span></div>
      <div class="content">
        <h1 class="title">Account Locked</h1>
        <div class="greeting">Attention, {{ name }}</div>
        <p class="paragraph">Your BloodMatch clinical account was automatically locked after <strong>3 consecutive failed password attempts</strong> to safeguard patient records from automated brute-force attacks.</p>
        <div style="background: #F8FAFC; border: 1.5px solid #E2E8F0; border-radius: 16px; padding: 22px 16px; text-align: center; margin: 22px 0;">
          <div style="font-size: 11px; font-weight: 800; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Code Requested</div>
          <table align="center" border="0" cellpadding="0" cellspacing="6" style="margin: 0 auto;">
            <tr>
              {% for d in unlock_code %}
              <td align="center" style="width: 44px; height: 50px; background: #FFFFFF; border: 1.5px solid #CBD5E1; border-radius: 10px; font-family: monospace, -apple-system, BlinkMacSystemFont, sans-serif; font-size: 26px; font-weight: 800; color: #1E293B; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.06);">
                {{ d }}
              </td>
              {% endfor %}
            </tr>
          </table>
          <div style="margin-top: 16px;">
            <span style="display: inline-block; padding: 8px 22px; background: #0284C7; color: #FFFFFF; border-radius: 24px; font-size: 13px; font-weight: 700; text-decoration: none;">Copy code</span>
          </div>
          <div style="margin-top: 12px; font-size: 12px; color: #64748B; font-weight: 600;">⏱ Valid for 10 minutes • Clear lockout immediately</div>
        </div>
        <div class="notice-box"><strong>Immediate Action:</strong> Submit this code in the portal to unlock your account. If you did not initiate these login attempts, update your password right away.</div>
      </div>
      <div class="footer">BloodMatch Threat Defense Center • Transfusion Zero-Trust Infrastructure</div>
    </div>
  </div>
</body>
</html>
"""

RESET_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>Password Reset Code</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
    .header { padding: 24px 32px 16px 32px; border-bottom: 1px solid #F5F1EF; }
    .brand-pill { display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 700; color: #D72638; text-transform: uppercase; }
    .content { padding: 32px; }
    .title { font-size: 22px; font-weight: 900; color: #1A1D20; margin: 0 0 10px 0; }
    .greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }
    .paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }
    .otp-container { background: #FDF9F8; border: 1.5px dashed #D72638; border-radius: 14px; padding: 20px 16px; text-align: center; margin: 20px 0; }
    .otp-label { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .otp-code { font-family: monospace; font-size: 38px; font-weight: 900; letter-spacing: 10px; color: #D72638; display: inline-block; margin: 0; }
    .otp-validity { margin-top: 10px; font-size: 12px; color: #7A0C17; font-weight: 600; }
    .notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 20px; }
    .notice-box strong { color: #D72638; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
    @media only screen and (max-width: 600px) {
      .wrapper { padding: 12px 8px !important; }
      .card { border-radius: 14px !important; width: 100% !important; }
      .content { padding: 18px 14px !important; }
      .header { padding: 16px 14px 12px 14px !important; }
      .footer { padding: 14px 12px !important; }
      .audit-card, .status-card, .member-box, .pledge-box { padding: 12px 12px !important; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">BloodMatch Security Center</span></div>
      <div class="content">
        <h1 class="title">Password Reset Code</h1>
        <div class="greeting">Hello, {{ name }}</div>
        <p class="paragraph">We received an authentication request to reset your clinical account password. Enter the following 6-digit recovery code in the password recovery modal to verify your identity and set a new password.</p>
        <div style="background: #F8FAFC; border: 1.5px solid #E2E8F0; border-radius: 16px; padding: 22px 16px; text-align: center; margin: 22px 0;">
          <div style="font-size: 11px; font-weight: 800; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Code Requested</div>
          <table align="center" border="0" cellpadding="0" cellspacing="6" style="margin: 0 auto;">
            <tr>
              {% for d in otp_code %}
              <td align="center" style="width: 44px; height: 50px; background: #FFFFFF; border: 1.5px solid #CBD5E1; border-radius: 10px; font-family: monospace, -apple-system, BlinkMacSystemFont, sans-serif; font-size: 26px; font-weight: 800; color: #1E293B; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.06);">
                {{ d }}
              </td>
              {% endfor %}
            </tr>
          </table>
          <div style="margin-top: 16px;">
            <span style="display: inline-block; padding: 8px 22px; background: #0284C7; color: #FFFFFF; border-radius: 24px; font-size: 13px; font-weight: 700; text-decoration: none;">Copy code</span>
          </div>
          <div style="margin-top: 12px; font-size: 12px; color: #64748B; font-weight: 600;">⏱ Valid for 10 minutes • Single-use recovery token</div>
        </div>
        <div class="notice-box"><strong>Security Notice:</strong> If you did not request a password reset, your credentials may be targeted. Please notify your facility network administrator immediately.</div>
      </div>
      <div class="footer">BloodMatch Emergency Transfusion Network • Automated Security Gate</div>
    </div>
  </div>
</body>
</html>
"""

CHANGED_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>Security Alert: Password Changed</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
    .header { padding: 24px 32px 16px 32px; border-bottom: 1px solid #F5F1EF; }
    .brand-pill { display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 700; color: #D72638; text-transform: uppercase; }
    .content { padding: 32px; }
    .title { font-size: 22px; font-weight: 900; color: #1A1D20; margin: 0 0 10px 0; }
    .greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }
    .paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }
    .audit-card { background: #FAF8F7; border: 1px solid #D9C7C2; border-radius: 14px; padding: 18px 20px; margin: 20px 0; }
    .audit-title { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
    .notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 20px; }
    .notice-box strong { color: #D72638; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
    @media only screen and (max-width: 600px) {
      .wrapper { padding: 12px 8px !important; }
      .card { border-radius: 14px !important; width: 100% !important; }
      .content { padding: 18px 14px !important; }
      .header { padding: 16px 14px 12px 14px !important; }
      .footer { padding: 14px 12px !important; }
      .audit-card, .status-card, .member-box, .pledge-box { padding: 12px 12px !important; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">BloodMatch Security Alert</span></div>
      <div class="content">
        <h1 class="title">Security Password Updated</h1>
        <div class="greeting">Hello, {{ name }}</div>
        <p class="paragraph">This automated security advisory confirms that the access password for your clinical account has been updated successfully. Active sessions have been audited and cryptographic tokens regenerated.</p>
        <div class="audit-card">
          <div class="audit-title">Security Event Audit Trail</div>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Timestamp</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">{{ timestamp }}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Terminal / Device</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">{{ browser }}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Origin Network IP</td>
              <td style="padding: 8px 0; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">{{ ip_address }}</td>
            </tr>
          </table>
        </div>
        <div class="notice-box"><strong>Important:</strong> If you did not make this change, your credentials may be compromised. Lock down your terminal and report this incident to your facility trauma administrator immediately.</div>
      </div>
      <div class="footer">
        BloodMatch Clinical Security Service • Real-Time Transfusion Defense
        <div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Audit Ref: #{{ timestamp }}</div>
      </div>
    </div>
  </div>
</body>
</html>
"""

TWO_FACTOR_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>Two-Factor Authentication Challenge</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
    .header { padding: 24px 32px 16px 32px; border-bottom: 1px solid #F5F1EF; }
    .brand-pill { display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 700; color: #D72638; text-transform: uppercase; }
    .content { padding: 32px; }
    .title { font-size: 22px; font-weight: 900; color: #1A1D20; margin: 0 0 10px 0; }
    .greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }
    .paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }
    .otp-container { background: #FDF9F8; border: 1.5px dashed #D72638; border-radius: 14px; padding: 20px 16px; text-align: center; margin: 20px 0; }
    .otp-label { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .otp-code { font-family: monospace; font-size: 38px; font-weight: 900; letter-spacing: 10px; color: #D72638; display: inline-block; margin: 0; }
    .otp-validity { margin-top: 10px; font-size: 12px; color: #7A0C17; font-weight: 600; }
    .audit-card { background: #FAF8F7; border: 1px solid #D9C7C2; border-radius: 14px; padding: 18px 20px; margin: 20px 0; font-size: 12px; }
    .audit-title { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
    .notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 20px; }
    .notice-box strong { color: #D72638; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
    @media only screen and (max-width: 600px) {
      .wrapper { padding: 12px 8px !important; }
      .card { border-radius: 14px !important; width: 100% !important; }
      .content { padding: 18px 14px !important; }
      .header { padding: 16px 14px 12px 14px !important; }
      .footer { padding: 14px 12px !important; }
      .audit-card, .status-card, .member-box, .pledge-box { padding: 12px 12px !important; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">Step-Up 2FA Challenge</span></div>
      <div class="content">
        <h1 class="title">Two-Factor Authentication</h1>
        <div class="greeting">Hello, {{ name }}</div>
        <p class="paragraph">A sign-in attempt was initiated from a workstation requiring step-up two-factor verification. Enter the security code below to complete sign in:</p>
        <div style="background: #F8FAFC; border: 1.5px solid #E2E8F0; border-radius: 16px; padding: 22px 16px; text-align: center; margin: 22px 0;">
          <div style="font-size: 11px; font-weight: 800; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Code Requested</div>
          <table align="center" border="0" cellpadding="0" cellspacing="6" style="margin: 0 auto;">
            <tr>
              {% for d in otp_code %}
              <td align="center" style="width: 44px; height: 50px; background: #FFFFFF; border: 1.5px solid #CBD5E1; border-radius: 10px; font-family: monospace, -apple-system, BlinkMacSystemFont, sans-serif; font-size: 26px; font-weight: 800; color: #1E293B; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.06);">
                {{ d }}
              </td>
              {% endfor %}
            </tr>
          </table>
          <div style="margin-top: 16px;">
            <span style="display: inline-block; padding: 8px 22px; background: #0284C7; color: #FFFFFF; border-radius: 24px; font-size: 13px; font-weight: 700; text-decoration: none;">Copy code</span>
          </div>
          <div style="margin-top: 12px; font-size: 12px; color: #64748B; font-weight: 600;">⏱ Valid for 10 minutes • Device Step-Up</div>
        </div>
        <div class="audit-card">
          <div class="audit-title">Access Request Telemetry</div>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Workstation</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">{{ device_name }}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Network IP</td>
              <td style="padding: 8px 0; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">{{ ip_address }}</td>
            </tr>
          </table>
        </div>
        <div class="notice-box"><strong>Security Notice:</strong> If you did not initiate this sign-in attempt, your credentials may be known to an unauthorized party. Change your password immediately.</div>
      </div>
      <div class="footer">
        BloodMatch Transfusion Network • Autonomous Threat Defense Node
        <div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Telemetry Dispatch Node • Encrypted Relay</div>
      </div>
    </div>
  </div>
</body>
</html>
"""

WELCOME_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>Welcome to BloodMatch Transfusion Network</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
    .header { padding: 24px 32px 16px 32px; border-bottom: 1px solid #F5F1EF; }
    .brand-pill { display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 700; color: #D72638; text-transform: uppercase; }
    .content { padding: 32px; }
    .title { font-size: 22px; font-weight: 900; color: #1A1D20; margin: 0 0 10px 0; }
    .greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }
    .paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }
    .member-box { background: #FDF9F8; border: 1px solid #D72638; border-radius: 12px; padding: 14px 18px; margin: 16px 0; font-size: 13px; color: #1A1D20; }
    .member-id { font-family: monospace; font-weight: 800; color: #D72638; font-size: 15px; }
    .notice-box { background: #F0FDF4; border-left: 3px solid #10B981; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #166534; line-height: 1.5; margin-top: 20px; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
    @media only screen and (max-width: 600px) {
      .wrapper { padding: 12px 8px !important; }
      .card { border-radius: 14px !important; width: 100% !important; }
      .content { padding: 18px 14px !important; }
      .header { padding: 16px 14px 12px 14px !important; }
      .footer { padding: 14px 12px !important; }
      .audit-card, .status-card, .member-box, .pledge-box { padding: 12px 12px !important; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">BloodMatch Network Welcome</span></div>
      <div class="content">
        <h1 class="title">Profile Verified & Activated</h1>
        <div class="greeting">Welcome, {{ name }}</div>
        <p class="paragraph">Your profile has been successfully verified and activated on the BloodMatch platform. You now have full access to your personal dashboard, 8-group cross-match matrix, and donor coordination services.</p>
        {% if member_id %}
        <div class="member-box">
          <strong>Your Unique Member ID:</strong> <span class="member-id">{{ member_id }}</span>
        </div>
        {% endif %}
        <div class="notice-box">Your account is ready. You can log into your account to manage your profile and view compatibility insights anytime.</div>
      </div>
      <div class="footer">BloodMatch Emergency Transfusion Network</div>
    </div>
  </div>
</body>
</html>
"""

# Plain Text Fallbacks (Clean & Button-Free)
EMAIL_TEXT_TEMPLATE = """
BloodMatch Clinical Network - Account Verification
Hello, {{ name }}

Your 6-digit single-use verification code is: {{ otp_code }}

This code is valid for 10 minutes.
If you did not initiate this registration, please disregard this email.
"""

LOCKOUT_TEXT_TEMPLATE = """
CRITICAL SECURITY ALERT: Account Locked
Attention, {{ name }}

Your BloodMatch clinical account was locked after 3 consecutive failed login attempts.
Your 6-digit emergency reset/unlock code is: {{ unlock_code }}

This unlock code is valid for 10 minutes.
If you did not perform these login attempts, immediately unlock your account and change your security credentials.
"""

RESET_TEXT_TEMPLATE = """
BloodMatch Security Center - Password Reset Code
Hello, {{ name }}

Your 6-digit password recovery code is: {{ otp_code }}

This code is valid for 10 minutes.
If you did not request this, please contact clinical security immediately.
"""

CHANGED_TEXT_TEMPLATE = """
Security Notice: Password Successfully Updated
Hello, {{ name }}

The password for your BloodMatch clinical account was updated at {{ timestamp }}.
Terminal / Device: {{ browser }}
Origin IP: {{ ip_address }}

If you did not make this change, please report this incident immediately.
"""

TWO_FACTOR_TEXT_TEMPLATE = """
BloodMatch Two-Factor Authentication Challenge
Hello, {{ name }}

Your 6-digit login verification code is: {{ otp_code }}
Attempted Device: {{ device_name }}
Source IP: {{ ip_address }}

This code is valid for 10 minutes.
"""

WELCOME_TEXT_TEMPLATE = """
Welcome to BloodMatch Emergency Transfusion Network
Hello, {{ name }}

Your profile has been successfully verified and activated on the BloodMatch platform.
You now have full access to your personal dashboard, 8-group cross-match matrix, and donor coordination services.
{% if member_id %}Member ID: {{ member_id }}{% endif %}

Thank you for being part of the BloodMatch community.
BloodMatch Emergency Transfusion Network
"""

DONOR_THANKYOU_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>Thank You for Registering as a Voluntary Blood Donor</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
    .header { padding: 24px 32px 16px 32px; border-bottom: 1px solid #F5F1EF; }
    .brand-pill { display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 700; color: #D72638; text-transform: uppercase; }
    .content { padding: 32px; }
    .title { font-size: 22px; font-weight: 900; color: #1A1D20; margin: 0 0 10px 0; }
    .greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }
    .paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }
    .pledge-box { background: #FDF9F8; border: 1.5px solid #D72638; border-radius: 14px; padding: 18px 20px; margin: 18px 0; }
    .pledge-title { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .pledge-row { font-size: 13px; color: #1A1D20; margin-top: 4px; }
    .pledge-val { font-weight: 800; color: #D72638; }
    .notice-box { background: #F0FDF4; border-left: 3px solid #10B981; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #166534; line-height: 1.5; margin-top: 20px; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
    @media only screen and (max-width: 600px) {
      .wrapper { padding: 12px 8px !important; }
      .card { border-radius: 14px !important; width: 100% !important; }
      .content { padding: 18px 14px !important; }
      .header { padding: 16px 14px 12px 14px !important; }
      .footer { padding: 14px 12px !important; }
      .audit-card, .status-card, .member-box, .pledge-box { padding: 12px 12px !important; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">BloodMatch Voluntary Donor Network</span></div>
      <div class="content">
        <h1 class="title">Thank You, Lifesaver!</h1>
        <div class="greeting">Hello, {{ name }}</div>
        <p class="paragraph">Thank you for registering as a certified voluntary blood donor with the BloodMatch Emergency Transfusion Network.</p>
        <div class="pledge-box">
          <div class="pledge-title">Voluntary Blood Pledge Confirmed</div>
          <div class="pledge-row">Blood Group: <span class="pledge-val">{{ blood_type }}</span></div>
          <div class="pledge-row">Emergency Locality: <strong>{{ location }}</strong></div>
        </div>
        <div class="notice-box">
          <strong>Standby Notification:</strong> If someone in your area needs blood matching your {{ blood_type }} group, our clinical coordination team will notify you immediately.
        </div>
        <p class="paragraph" style="margin-top: 18px; font-size: 12px;">Your noble readiness to donate helps trauma centers and local hospitals save lives in critical situations.</p>
      </div>
      <div class="footer">BloodMatch Emergency Transfusion Network • Voluntary Donor Ledger</div>
    </div>
  </div>
</body>
</html>
"""

DONOR_THANKYOU_TEXT_TEMPLATE = """
Thank You for Registering as a Voluntary Blood Donor - BloodMatch
Hello, {{ name }}

Thank you for registering as a voluntary blood donor with BloodMatch.
Your voluntary pledge to donate Group {{ blood_type }} blood has been enrolled in our emergency registry for {{ location }}.

If an emergency transfusion request matching your blood group arises in your area, our clinical coordination team will notify you immediately.

Thank you for your noble commitment to saving lives.
BloodMatch Emergency Transfusion Network
"""

NEW_SESSION_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>New Session Login Advisory</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
    .header { padding: 24px 32px 16px 32px; border-bottom: 1px solid #F5F1EF; }
    .brand-pill { display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 700; color: #D72638; text-transform: uppercase; }
    .content { padding: 32px; }
    .title { font-size: 22px; font-weight: 900; color: #1A1D20; margin: 0 0 10px 0; }
    .greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }
    .paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }
    .audit-card { background: #FAF8F7; border: 1px solid #D9C7C2; border-radius: 14px; padding: 18px 20px; margin: 20px 0; }
    .audit-title { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
    .audit-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; }
    .audit-row:last-child { border-bottom: none; }
    .audit-label { color: #75808A; font-weight: 500; }
    .audit-val { color: #1A1D20; font-weight: 700; font-family: monospace; }
    .notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 24px; }
    .notice-box strong { color: #D72638; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
    @media only screen and (max-width: 600px) {
      .wrapper { padding: 12px 8px !important; }
      .card { border-radius: 14px !important; width: 100% !important; }
      .content { padding: 18px 14px !important; }
      .header { padding: 16px 14px 12px 14px !important; }
      .footer { padding: 14px 12px !important; }
      .audit-card, .status-card, .member-box, .pledge-box { padding: 12px 12px !important; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">BloodMatch Security Advisory</span></div>
      <div class="content">
        <h1 class="title">New Active Session Detected</h1>
        <div class="greeting">Hello, {{ name }}</div>
        <p class="paragraph">Your BloodMatch account was authenticated from a new workstation session. Review the access telemetry below to ensure this session was authorized by you.</p>
        <div class="audit-card">
          <div class="audit-title" style="margin-bottom: 14px;">New Session Telemetry</div>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Workstation</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">{{ device_name }}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Origin Network IP</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">{{ ip_address }}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Location</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">{{ location }}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Timestamp</td>
              <td style="padding: 8px 0; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">{{ timestamp }}</td>
            </tr>
          </table>
        </div>
        <div class="notice-box">
          <strong>Security Notice:</strong> If this was not you, someone may have compromised your credentials. Log into your dashboard and remotely revoke this workstation in Security Settings immediately.
        </div>
      </div>
      <div class="footer">
        BloodMatch Emergency Transfusion Network • Automated Session Registry<br>Real-Time Transfusion Node Monitor
        <div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Session Dispatch ID: BM-{{ timestamp }}</div>
      </div>
    </div>
  </div>
</body>
</html>
"""

NEW_SESSION_TEXT_TEMPLATE = """
BloodMatch Security Advisory: New Device Session
Hello, {{ name }}

Your BloodMatch clinical account was accessed from a new active session:
Workstation: {{ device_name }}
Network IP: {{ ip_address }}
Location: {{ location }}
Timestamp: {{ timestamp }}

If this was you, no action is needed. If you do not recognize this activity, navigate to Settings > Active Terminal Sessions to remotely revoke this device.
"""

# Compile Jinja2 Templates (loaded from templates/email/ with fallback to inline constants)
jinja_html_template = load_template("otp-verification.html", EMAIL_HTML_FALLBACK)
jinja_text_template = Template(EMAIL_TEXT_TEMPLATE)

jinja_lockout_html = Template(LOCKOUT_HTML_FALLBACK)
jinja_lockout_text = Template(LOCKOUT_TEXT_TEMPLATE)

jinja_reset_html = load_template("password-reset.html", RESET_HTML_FALLBACK)
jinja_reset_text = Template(RESET_TEXT_TEMPLATE)

jinja_changed_html = load_template("password-changed.html", CHANGED_HTML_FALLBACK)
jinja_changed_text = Template(CHANGED_TEXT_TEMPLATE)

jinja_2fa_html = Template(TWO_FACTOR_HTML_FALLBACK)
jinja_2fa_text = Template(TWO_FACTOR_TEXT_TEMPLATE)

jinja_welcome_html = load_template("welcome-thankyou.html", WELCOME_HTML_FALLBACK)
jinja_welcome_text = Template(WELCOME_TEXT_TEMPLATE)

jinja_donor_thankyou_html = Template(DONOR_THANKYOU_HTML_FALLBACK)
jinja_donor_thankyou_text = Template(DONOR_THANKYOU_TEXT_TEMPLATE)

jinja_session_html = Template(NEW_SESSION_HTML_FALLBACK)
jinja_session_text = Template(NEW_SESSION_TEXT_TEMPLATE)

def _dispatch_google_apps_script(action: str, payload: dict) -> bool:
    """Dispatches transactional email payload to autonomous Google Apps Script webhook."""
    # Safeguard: Never drain user's daily Google account email quota during automated testing if mock flag enabled
    if os.getenv("MOCK_EXTERNAL_EMAIL") == "1":
        logger.info(f"[TEST RUNNER MOCK] Webhook dispatch bypassed for action: {action}")
        return True

    if not GOOGLE_APP_SCRIPT_URL:
        return False
    try:
        data = {
            "action": action,
            **payload
        }
        resp = requests.post(GOOGLE_APP_SCRIPT_URL, json=data, timeout=10.0)
        if resp.status_code in (200, 302):
            try:
                res_json = resp.json()
                if res_json.get("success"):
                    logger.info(f"[GAS WEBHOOK SUCCESS] Dispatched {action} to {payload.get('to')}")
                    return True
                else:
                    err_detail = res_json.get('error', '')
                    logger.warning(f"[GAS WEBHOOK WARNING] Webhook returned error: {err_detail}")
                    return False
            except Exception:
                # 200/302 response processed by Google Apps Script successfully
                logger.info(f"[GAS WEBHOOK SUCCESS] Dispatched {action} to {payload.get('to')} (HTTP {resp.status_code})")
                return True
        logger.warning(f"[GAS WEBHOOK WARNING] HTTP status {resp.status_code}: {resp.text[:120]}")
        return False
    except Exception as exc:
        logger.error(f"[GAS WEBHOOK ERROR] Failed to dispatch {action} to {GOOGLE_APP_SCRIPT_URL}: {exc}")
        return False

def _dispatch_smtp(subject: str, recipient_email: str, text_body: str, html_body: str, attachments: Optional[list] = None) -> bool:
    """Internal helper to dispatch MIME multipart emails via SMTP with optional attachments."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        return True

    try:
        if attachments:
            msg = MIMEMultipart("mixed")
            alt_part = MIMEMultipart("alternative")
            alt_part.attach(MIMEText(text_body, "plain", "utf-8"))
            alt_part.attach(MIMEText(html_body, "html", "utf-8"))
            msg.attach(alt_part)

            for att in attachments:
                part = MIMEApplication(att["content_bytes"], _subtype="pdf")
                part.add_header("Content-Disposition", "attachment", filename=att.get("filename", "BloodMatch_Document.pdf"))
                msg.attach(part)
        else:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))

        msg["Subject"] = subject
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg["To"] = recipient_email

        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                if SMTP_USE_TLS:
                    server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        return True
    except Exception as exc:
        logger.error(f"Failed to dispatch email ({subject}) to {recipient_email}: {exc}")
        return False

def send_verification_email(recipient_email: str, recipient_name: str, otp_code: str) -> bool:
    recipient_name = sanitize_recipient_name(recipient_name)
    # 1. Primary delivery: Autonomous Google Apps Script Webhook
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "otp_code": otp_code
    }
    if _dispatch_google_apps_script("otp_verification", gas_payload):
        return True

    # 2. Fallback: SMTP Transport or Simulated Local Logging
    rendered_html = jinja_html_template.render(name=recipient_name, otp_code=otp_code)
    rendered_text = jinja_text_template.render(name=recipient_name, otp_code=otp_code)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(f"[SIMULATED EMAIL DISPATCH] Recipient: {recipient_email} | Name: {recipient_name} | OTP: {otp_code}")
        return True
    return _dispatch_smtp(f"BloodMatch Verification Code: {otp_code}", recipient_email, rendered_text, rendered_html)

def send_lockout_alert_email(recipient_email: str, recipient_name: str, unlock_code: str) -> bool:
    recipient_name = sanitize_recipient_name(recipient_name)
    # 1. Primary delivery: Autonomous Google Apps Script Webhook
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "unlock_code": unlock_code
    }
    if _dispatch_google_apps_script("account_lockout", gas_payload):
        return True

    # 2. Fallback: SMTP Transport or Simulated Local Logging
    rendered_html = jinja_lockout_html.render(name=recipient_name, unlock_code=unlock_code)
    rendered_text = jinja_lockout_text.render(name=recipient_name, unlock_code=unlock_code)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(f"[CRITICAL LOCKOUT SIMULATION] Recipient: {recipient_email} | Name: {recipient_name} | Unlock Code: {unlock_code}")
        return True
    return _dispatch_smtp(f"🚨 URGENT: BloodMatch Account Locked - Emergency Reset Code: {unlock_code}", recipient_email, rendered_text, rendered_html)

def send_password_reset_email(recipient_email: str, recipient_name: str, otp_code: str) -> bool:
    """Dispatches the 6-digit password reset verification code."""
    recipient_name = sanitize_recipient_name(recipient_name)
    # 1. Primary delivery: Autonomous Google Apps Script Webhook
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "otp_code": otp_code
    }
    if _dispatch_google_apps_script("password_reset", gas_payload):
        return True

    # 2. Fallback: SMTP Transport or Simulated Local Logging
    rendered_html = jinja_reset_html.render(name=recipient_name, otp_code=otp_code)
    rendered_text = jinja_reset_text.render(name=recipient_name, otp_code=otp_code)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(f"[PASSWORD RESET CODE DISPATCH] Recipient: {recipient_email} | Name: {recipient_name} | Reset OTP: {otp_code} (10m expiry)")
        return True
    return _dispatch_smtp(f"BloodMatch Password Reset Verification Code: {otp_code}", recipient_email, rendered_text, rendered_html)

def send_password_changed_notification(
    recipient_email: str,
    recipient_name: str,
    timestamp: str,
    browser: str = "Unknown Browser / Device",
    ip_address: str = "Unknown IP",
    device_info: Optional[str] = None
) -> bool:
    """Dispatches the security audit confirmation email upon successful password update."""
    recipient_name = sanitize_recipient_name(recipient_name)
    effective_browser = device_info or browser

    # 1. Primary delivery: Autonomous Google Apps Script Webhook
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "timestamp": timestamp,
        "browser": effective_browser,
        "ip_address": ip_address,
        "device_info": effective_browser
    }
    if _dispatch_google_apps_script("password_changed", gas_payload):
        return True

    # 2. Fallback: SMTP Transport or Simulated Local Logging
    rendered_html = jinja_changed_html.render(
        name=recipient_name,
        timestamp=timestamp,
        browser=effective_browser,
        ip_address=ip_address
    )
    rendered_text = jinja_changed_text.render(
        name=recipient_name,
        timestamp=timestamp,
        browser=effective_browser,
        ip_address=ip_address
    )

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(
            f"[SECURITY AUDIT CONFIRMATION] Recipient: {recipient_email} | Password Changed at: {timestamp} | Browser: {browser} | IP: {ip_address}"
        )
        return True
    return _dispatch_smtp("Security Notice: BloodMatch Password Successfully Updated", recipient_email, rendered_text, rendered_html)

def send_2fa_login_email(
    recipient_email: str,
    recipient_name: str,
    otp_code: str,
    device_name: str,
    ip_address: str
) -> bool:
    """Dispatches 2FA step-up login verification email."""
    recipient_name = sanitize_recipient_name(recipient_name)
    # 1. Primary delivery: Autonomous Google Apps Script Webhook
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "otp_code": otp_code,
        "device_name": device_name,
        "ip_address": ip_address
    }
    if _dispatch_google_apps_script("2fa_login", gas_payload):
        return True

    # 2. Fallback: SMTP Transport or Simulated Local Logging
    rendered_html = jinja_2fa_html.render(
        name=recipient_name,
        otp_code=otp_code,
        device_name=device_name,
        ip_address=ip_address
    )
    rendered_text = jinja_2fa_text.render(
        name=recipient_name,
        otp_code=otp_code,
        device_name=device_name,
        ip_address=ip_address
    )

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(
            f"[2FA LOGIN CODE DISPATCH] Recipient: {recipient_email} | Name: {recipient_name} | OTP: {otp_code} | Device: {device_name} | IP: {ip_address}"
        )
        return True
    return _dispatch_smtp(f"BloodMatch 2FA Login Code: {otp_code}", recipient_email, rendered_text, rendered_html)

def send_welcome_email(recipient_email: str, recipient_name: str, member_id: Optional[str] = None) -> bool:
    """Dispatches the clean, relevant welcome & thank-you email once profile is verified."""
    recipient_name = sanitize_recipient_name(recipient_name)
    # 1. Primary delivery: Autonomous Google Apps Script Webhook
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "member_id": member_id or ""
    }
    if _dispatch_google_apps_script("welcome_thankyou", gas_payload):
        return True

    # 2. Fallback: SMTP Transport or Simulated Local Logging
    rendered_html = jinja_welcome_html.render(name=recipient_name, member_id=member_id)
    rendered_text = jinja_welcome_text.render(name=recipient_name, member_id=member_id)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(f"[WELCOME EMAIL DISPATCH] Recipient: {recipient_email} | Name: {recipient_name} | Member ID: {member_id}")
        return True
    return _dispatch_smtp("Welcome to BloodMatch Emergency Transfusion Network", recipient_email, rendered_text, rendered_html)

def send_new_login_session_alert(
    recipient_email: str,
    recipient_name: str,
    device_name: str,
    ip_address: str,
    location: str,
    timestamp: str
) -> bool:
    """Dispatches security advisory email when account logs in from a new workstation or session."""
    recipient_name = sanitize_recipient_name(recipient_name)
    # 1. Primary delivery: Autonomous Google Apps Script Webhook
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "device_name": device_name,
        "ip_address": ip_address,
        "location": location,
        "timestamp": timestamp
    }
    if _dispatch_google_apps_script("new_login_session", gas_payload):
        return True

    # 2. Fallback: SMTP Transport or Simulated Local Logging
    rendered_html = jinja_session_html.render(
        name=recipient_name,
        device_name=device_name,
        ip_address=ip_address,
        location=location,
        timestamp=timestamp
    )
    rendered_text = jinja_session_text.render(
        name=recipient_name,
        device_name=device_name,
        ip_address=ip_address,
        location=location,
        timestamp=timestamp
    )

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(
            f"[NEW SESSION ALERT] Recipient: {recipient_email} | Device: {device_name} | IP: {ip_address} | Location: {location} | Time: {timestamp}"
        )
        return True
    return _dispatch_smtp("Security Notice: New Session Login on BloodMatch", recipient_email, rendered_text, rendered_html)

def send_donor_thankyou_email(recipient_email: str, recipient_name: str, blood_type: str, location: str) -> bool:
    """Dispatches the voluntary blood donor thank-you & emergency readiness notice."""
    recipient_name = sanitize_recipient_name(recipient_name)
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "blood_type": blood_type,
        "location": location
    }
    if _dispatch_google_apps_script("donor_thankyou", gas_payload):
        return True

    rendered_html = jinja_donor_thankyou_html.render(name=recipient_name, blood_type=blood_type, location=location)
    rendered_text = jinja_donor_thankyou_text.render(name=recipient_name, blood_type=blood_type, location=location)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(f"[DONOR THANK YOU DISPATCH] Recipient: {recipient_email} | Name: {recipient_name} | Blood: {blood_type} | Location: {location}")
        return True
    return _dispatch_smtp("Thank You for Registering as a Voluntary Blood Donor - BloodMatch", recipient_email, rendered_text, rendered_html)

def send_account_deletion_otp_email(recipient_email: str, recipient_name: str, otp_code: str) -> bool:
    """Dispatches the critical 6-digit confirmation code for permanent account deletion."""
    recipient_name = sanitize_recipient_name(recipient_name)
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "otp_code": otp_code,
        "action": "account_deletion_request"
    }
    if _dispatch_google_apps_script("account_deletion_otp", gas_payload):
        return True

    text_body = f"Hello {recipient_name},\n\nWe received an authorization request to permanently delete your BloodMatch account and all associated donor records.\nYour 6-digit deletion authorization code is: {otp_code}\n\nIf you did NOT request this deletion, change your password immediately."
    cells_html = "".join([f'<td align="center" style="width: 44px; height: 50px; background: #ffffff; border: 1.5px solid #CBD5E1; border-radius: 10px; font-family: monospace; font-size: 26px; font-weight: 800; color: #991b1b; text-align: center;">{d}</td>' for d in str(otp_code).strip()])
    html_body = f"""
    <div style="font-family: sans-serif; max-width: 500px; padding: 24px; border: 1px solid #fee2e2; border-radius: 12px; background: #fff5f5;">
        <h2 style="color: #991b1b; margin-top: 0;">Confirm your identity</h2>
        <p>Hello <strong>{recipient_name}</strong>,</p>
        <p>A request was received to permanently delete your BloodMatch account and clinical records.</p>
        <div style="background: #F8FAFC; border: 1.5px solid #E2E8F0; border-radius: 16px; padding: 20px 16px; text-align: center; margin: 20px 0;">
            <div style="font-size: 11px; font-weight: 800; color: #991b1b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Code Requested</div>
            <table align="center" border="0" cellpadding="0" cellspacing="6" style="margin: 0 auto;">
                <tr>{cells_html}</tr>
            </table>
            <div style="margin-top: 14px;">
                <span style="display: inline-block; padding: 8px 22px; background: #dc2626; color: #FFFFFF; border-radius: 24px; font-size: 13px; font-weight: 700;">Copy code</span>
            </div>
            <div style="margin-top: 10px; font-size: 12px; color: #7f1d1d; font-weight: 600;">⏱ Valid for 10 minutes • Permanent Deletion Authorization</div>
        </div>
        <p style="font-size: 13px; color: #7f1d1d;">This code expires in 10 minutes. If you did not initiate this request, your account may be compromised.</p>
    </div>
    """
    return _dispatch_smtp("URGENT: BloodMatch Account Deletion Authorization Code", recipient_email, text_body, html_body)

def send_account_deleted_confirmation_email(recipient_email: str, recipient_name: str) -> bool:
    """Dispatches final confirmation that account and all associated records have been wiped."""
    recipient_name = sanitize_recipient_name(recipient_name)
    gas_payload = {
        "to": recipient_email,
        "name": recipient_name,
        "action": "account_deleted_confirmed"
    }
    if _dispatch_google_apps_script("account_deleted", gas_payload):
        return True

    text_body = f"""Hello {recipient_name},

This official confirmation verifies that your BloodMatch clinician account, login credentials, voluntary blood donor registry records, active sessions across all devices, and Cloudflare R2 storage files have been permanently and completely deleted from our clinical servers.

Deleted Data Summary:
• Clinician Credentials & Password Records: Expunged
• Voluntary Blood Donor Registry & Transfusion History: Expunged
• Active Workstation & Mobile Device Sessions: Revoked & Terminated
• Cloudflare R2 Avatars & Document Storage: Completely Purged

All active sessions have been terminated. Thank you for your service with BloodMatch Clinical Network."""

    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 540px; margin: 0 auto; padding: 28px; border: 1px solid #fee2e2; border-radius: 16px; background: #ffffff;">
        <div style="text-align: center; margin-bottom: 20px;">
            <div style="display: inline-block; padding: 10px 16px; border-radius: 9999px; background: #fef2f2; color: #dc2626; font-size: 12px; font-weight: 700; border: 1px solid #fecaca;">
                Account Purge Confirmation
            </div>
        </div>
        <h2 style="color: #0f172a; margin-top: 0; text-align: center; font-size: 22px; font-weight: 800;">Account Permanently Deleted</h2>
        <p style="color: #334155; font-size: 14px; line-height: 1.6;">Hello <strong>{recipient_name}</strong>,</p>
        <p style="color: #475569; font-size: 13px; line-height: 1.6;">
            As requested, your BloodMatch account and all associated operational records have been permanently erased from our clinical database and disaster-proof storage.
        </p>
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; margin: 20px 0;">
            <h4 style="margin: 0 0 10px 0; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b;">Purged Clinical Assets:</h4>
            <ul style="margin: 0; padding-left: 20px; color: #334155; font-size: 13px; line-height: 1.8;">
                <li><strong>Clinician Credentials:</strong> Login passwords, phone linkage, and tokens permanently removed.</li>
                <li><strong>Donor Registry:</strong> Blood donation profile and records in the donation suite completely wiped.</li>
                <li><strong>Cross-Device Sessions:</strong> Terminated and logged out automatically from all terminals.</li>
                <li><strong>Cloud Storage:</strong> Avatars, photos, and sync documents expunged from Cloudflare R2.</li>
            </ul>
        </div>
        <p style="font-size: 12px; color: #94a3b8; text-align: center; margin-top: 24px; border-top: 1px solid #f1f5f9; padding-top: 16px;">
            If you ever need emergency blood matching in the future, you may register a new account at any time.
        </p>
    </div>
    """
    return _dispatch_smtp("Your BloodMatch Account Has Been Permanently Deleted", recipient_email, text_body, html_body)

def send_emergency_donor_dispatch_email(
    donor_email: str,
    donor_name: str,
    blood_type: str,
    patient_name: str,
    hospital: str,
    hospital_city: str,
    contact_number: Optional[str] = None,
    distance_km: float = 0.0,
    custom_message: Optional[str] = None,
    requester_name: Optional[str] = None,
    requester_email: Optional[str] = None,
    requester_phone: Optional[str] = None
) -> bool:
    """Dispatches high-urgency mobilization call to a compatible voluntary donor."""
    donor_name = sanitize_recipient_name(donor_name)
    effective_phone = contact_number or requester_phone or "Attending Hospital Dispatch"
    effective_requester = sanitize_recipient_name(requester_name) if requester_name else "Emergency Transfusion Coordinator"
    subject = f"🚨 URGENT: Blood Donation Needed ({blood_type}) - Emergency Dispatch"

    text_body = f"""URGENT CLINICAL MOBILIZATION NOTICE

Hello {donor_name},

An urgent transfusion request requires your compatible Group {blood_type} blood.
You were identified as an enrolled voluntary donor in close proximity.

Requester / Contact: {effective_requester}
Emergency Hotline / Phone: {effective_phone}
{f"Verified Requester Email: {requester_email}" if requester_email else ""}
Patient / Case: {patient_name}
Facility: {hospital}, {hospital_city}
Proximity Distance: ~{distance_km:.1f} km
Clinical Message: {custom_message or 'Immediate voluntary blood donation requested.'}

Please call the emergency hotline ({effective_phone}) immediately if you are able to donate.
BloodMatch Emergency Transfusion Network • Verified Clinical Dispatch Node
"""

    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="color-scheme" content="light dark">
      <meta name="supported-color-schemes" content="light dark">
      <title>Emergency Blood Donation Dispatch</title>
      <style>
        body {{ margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1A1D20; -webkit-font-smoothing: antialiased; }}
        .wrapper {{ width: 100%; background-color: #F5F1EF; padding: 32px 16px; box-sizing: border-box; }}
        .card {{ max-width: 540px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-top: 4px solid #D72638; border-radius: 18px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.04); }}
        .header {{ padding: 20px 24px 14px 24px; border-bottom: 1px solid #F5F1EF; }}
        .brand-pill {{ display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 800; color: #D72638; text-transform: uppercase; }}
        .content {{ padding: 24px; }}
        .title {{ font-size: 20px; font-weight: 900; color: #7A0C17; margin: 0 0 8px 0; }}
        .greeting {{ font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }}
        .paragraph {{ font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 16px 0; }}
        .audit-card {{ background: #FAF8F7; border: 1px solid #EAE3E0; border-radius: 14px; padding: 14px 16px; margin: 16px 0; }}
        .notice-box {{ background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 14px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 16px; }}
        .call-btn {{ display: block; width: 100%; box-sizing: border-box; text-align: center; padding: 12px 16px; background: #D72638; color: #FFFFFF !important; font-size: 13.5px; font-weight: 800; text-decoration: none; border-radius: 10px; margin-top: 14px; box-shadow: 0 2px 8px rgba(215, 38, 56, 0.25); }}
        .footer {{ border-top: 1px solid #F5F1EF; padding: 18px 24px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }}
        @media only screen and (max-width: 600px) {{
          .wrapper {{ padding: 12px 8px !important; }}
          .card {{ border-radius: 14px !important; width: 100% !important; }}
          .content {{ padding: 18px 12px !important; }}
          .header {{ padding: 16px 14px 12px 14px !important; }}
          .footer {{ padding: 14px 12px !important; }}
          .audit-card {{ padding: 12px 12px !important; }}
        }}
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div class="card">
          <div class="header"><span class="brand-pill">Urgent Transfusion Call</span></div>
          <div class="content">
            <h1 class="title">Emergency Blood Dispatch</h1>
            <div class="greeting">Hello, {donor_name}</div>
            <p class="paragraph">A critical transfusion requires your compatible <strong>Group {blood_type}</strong> blood. You were identified as an enrolled voluntary donor in close proximity to the attending medical facility.</p>
            <div class="audit-card">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">
                <tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600; width: 36%;">Requester / Contact</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; word-break: break-word;">{effective_requester}</td>
                </tr>
                {f'''<tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600;">Sender Email</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; word-break: break-word;">{requester_email}</td>
                </tr>''' if requester_email else ''}
                <tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600; vertical-align: top;">Facility / Location</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; word-break: break-word;">{hospital}, {hospital_city}</td>
                </tr>
                <tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600;">Proximity Distance</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #047857; font-weight: 800; text-align: right;">~{distance_km:.1f} km away</td>
                </tr>
                <tr>
                  <td style="padding: 7px 0; font-size: 11.5px; color: #75808A; font-weight: 600;">Emergency Hotline</td>
                  <td style="padding: 7px 0; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;"><a href="tel:{effective_phone}" style="color: #D72638; text-decoration: none; font-weight: 800;">{effective_phone}</a></td>
                </tr>
              </table>
              <a href="tel:{effective_phone}" class="call-btn">🚨 Call Emergency Hotline Now ({effective_phone})</a>
            </div>
            <div class="notice-box">
              <strong>Clinical Urgency Message:</strong> {custom_message or 'Please contact the emergency hotline number immediately if you are available for donation.'}
            </div>
          </div>
          <div class="footer">
            BloodMatch Emergency Transfusion Network • Verified Clinical Dispatch Node
            <div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Dispatch Ref: #{donor_email[:4]}-{int(distance_km*10)}</div>
          </div>
        </div>
      </div>
    </body>
    </html>
    """

    gas_payload = {
        "to": donor_email,
        "name": donor_name,
        "blood_type": blood_type,
        "patient_name": patient_name,
        "hospital": hospital,
        "hospital_city": hospital_city,
        "contact_number": effective_phone,
        "distance_km": distance_km,
        "custom_message": custom_message or "",
        "action": "emergency_donor_dispatch",
        "html_body": html_body,
        "subject": subject
    }
    if _dispatch_google_apps_script("emergency_donor_dispatch", gas_payload):
        return True

    return _dispatch_smtp(subject, donor_email, text_body, html_body)

def send_emergency_dispatch_confirmation_to_clinician(
    clinician_email: str,
    clinician_name: str,
    donor_name: str,
    donor_email: str,
    donor_blood_type: str,
    patient_name: str,
    hospital: str,
    contact_number: str,
    custom_message: Optional[str] = None
) -> bool:
    """Dispatches formal confirmation receipt to the attending clinician acknowledging voluntary donor mobilization."""
    clean_clinician = sanitize_recipient_name(clinician_name)
    clean_donor = sanitize_recipient_name(donor_name)
    clean_patient = sanitize_recipient_name(patient_name) if patient_name else "Emergency Transfusion Case"
    subject = f"✅ Emergency Alert Dispatched to Voluntary Donor: {clean_donor} ({donor_blood_type})"

    text_body = f"""EMERGENCY ALERT TRANSMISSION CONFIRMATION

Hello {clean_clinician},

This receipt confirms that your emergency blood mobilization alert has been successfully transmitted to voluntary donor {clean_donor}.

CASE & DISPATCH DETAILS:
- Target Voluntary Donor: {clean_donor} ({donor_email})
- Blood Group Requested: {donor_blood_type}
- Patient / Case Name: {clean_patient}
- Facility / Location: {hospital}
- Direct Call-Back Hotline: {contact_number}
- Urgent Message Sent: {custom_message or 'Immediate voluntary blood donation requested.'}
- Dispatch Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
- 24-Hour Donor Cooldown: ACTIVE (Repeat alert dispatches to this donor are locked for 24 hours across all devices to prevent alert fatigue)

BloodMatch Emergency Transfusion Network • Verified Clinical Dispatch Node
"""

    patient_row_html = f"""
                <tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600;">Patient / Case</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; word-break: break-word;">{clean_patient}</td>
                </tr>
    """ if clean_patient and clean_patient != "Emergency Transfusion Case" and clean_patient != "Emergency Transfusion Recipient" else ""

    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="color-scheme" content="light dark">
      <meta name="supported-color-schemes" content="light dark">
      <title>Emergency Alert Transmission Confirmation</title>
      <style>
        body {{ margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1A1D20; -webkit-font-smoothing: antialiased; }}
        .wrapper {{ width: 100%; background-color: #F5F1EF; padding: 32px 16px; box-sizing: border-box; }}
        .card {{ max-width: 540px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-top: 4px solid #16A34A; border-radius: 18px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.04); }}
        .header {{ padding: 20px 24px 14px 24px; border-bottom: 1px solid #F5F1EF; }}
        .brand-pill {{ display: inline-block; padding: 4px 10px; background: #E8F8EE; border: 1px solid #B8E8C8; border-radius: 100px; font-size: 11px; font-weight: 800; color: #1E7E34; text-transform: uppercase; }}
        .content {{ padding: 24px; }}
        .title {{ font-size: 20px; font-weight: 900; color: #155724; margin: 0 0 8px 0; }}
        .greeting {{ font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }}
        .paragraph {{ font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 16px 0; }}
        .audit-card {{ background: #FAF8F7; border: 1px solid #EAE3E0; border-radius: 14px; padding: 14px 16px; margin: 16px 0; }}
        .notice-box {{ background: #F4FBF7; border-left: 3px solid #16A34A; padding: 12px 14px; border-radius: 6px; font-size: 12px; color: #2E5A3D; line-height: 1.5; margin-top: 16px; }}
        .footer {{ border-top: 1px solid #F5F1EF; padding: 18px 24px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }}
        @media only screen and (max-width: 600px) {{
          .wrapper {{ padding: 12px 8px !important; }}
          .card {{ border-radius: 14px !important; width: 100% !important; }}
          .content {{ padding: 18px 12px !important; }}
          .header {{ padding: 16px 14px 12px 14px !important; }}
          .footer {{ padding: 14px 12px !important; }}
          .audit-card {{ padding: 12px 12px !important; }}
        }}
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div class="card">
          <div class="header">
            <span class="brand-pill">Alert Transmitted ✓</span>
          </div>
          <div class="content">
            <h1 class="title">Dispatch Confirmation</h1>
            <div class="greeting">Hello, {clean_clinician}</div>
            <p class="paragraph">Your emergency blood alert has been successfully transmitted to voluntary donor <strong>{clean_donor}</strong> for compatible <strong>Group {donor_blood_type}</strong> blood.</p>
            <div class="audit-card">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">
                <tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600; width: 36%; vertical-align: top;">Voluntary Donor</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; word-break: break-word;">{clean_donor}<br><span style="font-size: 10.5px; font-weight: 500; color: #5A626A;">({donor_email})</span></td>
                </tr>
                <tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600;">Blood Group</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #D72638; font-weight: 900; text-align: right;">Group {donor_blood_type}</td>
                </tr>
                {patient_row_html}
                <tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600; vertical-align: top;">Facility / Location</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; word-break: break-word;">{hospital}</td>
                </tr>
                <tr>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 11.5px; color: #75808A; font-weight: 600;">Direct Hotline</td>
                  <td style="padding: 7px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;"><a href="tel:{contact_number}" style="color: #1A1D20; text-decoration: none; font-weight: 800;">{contact_number}</a></td>
                </tr>
                <tr>
                  <td style="padding: 7px 0; font-size: 11.5px; color: #75808A; font-weight: 600;">Cooldown Status</td>
                  <td style="padding: 7px 0; font-size: 12px; color: #16A34A; font-weight: 800; text-align: right;">✓ 24h Cooldown Active</td>
                </tr>
              </table>
            </div>
            <div class="notice-box">
              <strong>Clinical Urgency Note Sent:</strong> {custom_message or 'Immediate voluntary blood donation requested.'}
              <div style="margin-top: 8px; font-size: 11px; color: #4B6354; line-height: 1.4;">
                To protect enrolled donors from excessive alerts, follow-up notifications to this donor are locked for 24 hours across all devices.
              </div>
            </div>
          </div>
          <div class="footer">
            BloodMatch Emergency Transfusion Network • Verified Clinical Dispatch Node
            <div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Dispatch Ref: #{donor_email[:4]}-CONFIRM</div>
          </div>
        </div>
      </div>
    </body>
    </html>
    """

    gas_payload = {
        "to": clinician_email,
        "name": clean_clinician,
        "donor_name": clean_donor,
        "donor_email": donor_email,
        "blood_type": donor_blood_type,
        "patient_name": clean_patient,
        "hospital": hospital,
        "contact_number": contact_number,
        "custom_message": custom_message or "",
        "action": "emergency_donor_dispatch_confirmation",
        "html_body": html_body,
        "subject": subject
    }
    if _dispatch_google_apps_script("emergency_donor_dispatch_confirmation", gas_payload):
        return True

    return _dispatch_smtp(subject, clinician_email, text_body, html_body)

def send_clinician_donor_roster_email(
    clinician_email: str,
    clinician_name: str,
    recipient_blood_type: str,
    roster_items: list,
    patient_name: Optional[str] = None,
    pdf_base64: Optional[str] = None,
    pdf_filename: Optional[str] = None,
    dispatch_id: Optional[str] = None
) -> bool:
    """Dispatches top proximity sorted compatible donor roster to the clinician for offline backup with optional attached PDF docket."""
    clinician_name = sanitize_recipient_name(clinician_name)
    subject = f"Clinical Emergency Donor Roster: {recipient_blood_type} Transfusion"
    
    rows_text = ""
    rows_html = ""
    for idx, d in enumerate(roster_items[:10], start=1):
        name = d.get("fullName", "Donor")
        btype = d.get("bloodType", "")
        phone = d.get("phone", "")
        dist = d.get("distanceKm", 0.0)
        loc = d.get("location", "")
        rows_text += f"#{idx} | {name} ({btype}) | ~{dist:.1f} km | {loc} | {phone}\n"
        call_link_html = f'''<div style="margin-top: 8px;">
            <a href="tel:{phone}" style="display: block; width: 100%; box-sizing: border-box; text-align: center; padding: 7px 12px; background: #1A1D20; color: #FFFFFF !important; text-decoration: none; border-radius: 8px; font-size: 11.5px; font-weight: 700;">
              📞 Call Donor: {phone}
            </a>
          </div>''' if phone else ''
        rows_html += f"""
        <div style="background: #FFFFFF; border: 1px solid #E8DFDC; border-radius: 12px; padding: 12px 14px; margin-bottom: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="vertical-align: middle;">
                <span style="display: inline-block; padding: 2px 7px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 6px; font-size: 11px; font-weight: 800; color: #D72638; margin-right: 6px;">#{idx}</span>
                <strong style="font-size: 13.5px; color: #1A1D20;">{name}</strong>
                <span style="display: inline-block; margin-left: 6px; padding: 2px 7px; background: #7A0C17; color: #FFFFFF; border-radius: 6px; font-size: 10.5px; font-weight: 800;">Group {btype}</span>
              </td>
              <td align="right" style="vertical-align: middle; white-space: nowrap;">
                <span style="font-size: 11px; font-weight: 700; color: #047857; background: #ECFDF5; border: 1px solid #A7F3D0; padding: 2px 8px; border-radius: 100px;">~{dist:.1f} km</span>
              </td>
            </tr>
            <tr>
              <td colspan="2" style="padding-top: 6px;">
                <div style="font-size: 11.5px; color: #5A626A; word-break: break-word;">
                  📍 <span>{loc or 'Delhi NCR Region'}</span>
                </div>
                {call_link_html}
              </td>
            </tr>
          </table>
        </div>
        """

    text_body = f"BloodMatch Emergency Transfusion Network\nRanked Compatible Donor Roster for Group {recipient_blood_type}\n\n{rows_text}\nGenerated for {clinician_name}."
    
    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="color-scheme" content="light dark">
      <meta name="supported-color-schemes" content="light dark">
      <title>Emergency Donor Roster</title>
      <style>
        body {{ margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1A1D20; -webkit-font-smoothing: antialiased; }}
        .wrapper {{ width: 100%; background-color: #F5F1EF; padding: 32px 16px; box-sizing: border-box; }}
        .card {{ max-width: 560px; width: 100%; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-top: 4px solid #D72638; border-radius: 18px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.04); }}
        .header {{ padding: 20px 24px 14px 24px; border-bottom: 1px solid #F5F1EF; }}
        .brand-pill {{ display: inline-block; padding: 4px 10px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 800; color: #D72638; text-transform: uppercase; }}
        .content {{ padding: 24px; }}
        .title {{ font-size: 20px; font-weight: 900; color: #1A1D20; margin: 0 0 8px 0; }}
        .audit-card {{ background: #FAF8F7; border: 1px solid #EAE3E0; border-radius: 14px; padding: 14px; margin: 16px 0; }}
        .footer {{ border-top: 1px solid #F5F1EF; padding: 18px 24px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }}
        @media only screen and (max-width: 600px) {{
          .wrapper {{ padding: 12px 8px !important; }}
          .card {{ border-radius: 14px !important; width: 100% !important; }}
          .content {{ padding: 18px 12px !important; }}
          .header {{ padding: 16px 14px 12px 14px !important; }}
          .footer {{ padding: 14px 12px !important; }}
          .audit-card {{ padding: 10px 8px !important; }}
        }}
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div class="card">
          <div class="header"><span class="brand-pill">Emergency Donor Roster</span></div>
          <div class="content">
            <h1 class="title">Compatible Donors (Group {recipient_blood_type})</h1>
            <p style="font-size: 13px; color: #5A626A; margin: 0 0 16px 0; line-height: 1.5;">The following voluntary donors have been verified and ranked by proximity to your search coordinates for emergency transfusion dispatch:</p>
            <div class="audit-card">
              {rows_html}
            </div>
          </div>
          <div class="footer">
            BloodMatch Transfusion Network • Clinical Telemetry Roster
          </div>
        </div>
      </div>
    </body>
    </html>
    """

    gas_payload = {
        "to": clinician_email,
        "name": clinician_name,
        "recipient_blood_type": recipient_blood_type,
        "patient_name": patient_name or "Emergency Transfusion Case",
        "roster_items": roster_items,
        "action": "clinician_donor_roster",
        "subject": subject,
        "text_body": text_body,
        "html_body": html_body
    }
    if pdf_base64:
        gas_payload["pdf_base64"] = pdf_base64
        gas_payload["pdf_filename"] = pdf_filename or f"BloodMatch_Emergency_Docket_{recipient_blood_type}.pdf"
    if dispatch_id:
        gas_payload["dispatch_id"] = dispatch_id

    if _dispatch_google_apps_script("clinician_donor_roster", gas_payload):
        return True

    attachments = []
    if pdf_base64:
        try:
            pdf_bytes = base64.b64decode(pdf_base64)
            attachments.append({
                "filename": pdf_filename or f"BloodMatch_Emergency_Docket_{recipient_blood_type}.pdf",
                "content_bytes": pdf_bytes,
                "mime_type": "application/pdf"
            })
        except Exception as b64_err:
            logger.warning(f"Could not decode pdf_base64 for SMTP attachment: {b64_err}")

    return _dispatch_smtp(subject, clinician_email, text_body, html_body, attachments=attachments if attachments else None)

def send_transfusion_fulfilled_emails(
    requester_email: Optional[str],
    requester_name: Optional[str],
    patient_name: str,
    blood_type: str,
    units_needed: int = 1,
    hospital: Optional[str] = "Emergency Trauma Network",
    donor_email: Optional[str] = None,
    donor_name: Optional[str] = None,
    selected_donors: Optional[list] = None,
    fulfilled_via_reserve: bool = False
) -> dict:
    """
    Sends concise, professional clinical completion & gratitude emails:
    1. If voluntary donors were selected:
       - Transmits heartfelt donor gratitude emails to each participating donor.
       - Transmits clinician fulfillment email citing all participating donors.
    2. If fulfilled via reserve / no donor selected:
       - Transmits clinician fulfillment email confirming closure via external clinical reserve.
       - Dispatches 0 donor emails.
    """
    results = {"requester_sent": False, "donors_sent": 0}
    if requester_name:
        requester_name = sanitize_recipient_name(requester_name)

    # Normalize donors list
    donors_to_notify = []
    if selected_donors and isinstance(selected_donors, list):
        for d in selected_donors:
            if isinstance(d, dict) and d.get("email") and "@" in d.get("email"):
                donors_to_notify.append({
                    "name": sanitize_recipient_name(d.get("name") or "Voluntary Donor"),
                    "email": d.get("email").strip().lower(),
                    "blood_type": d.get("blood_type") or blood_type
                })
    elif donor_email and "@" in donor_email:
        donors_to_notify.append({
            "name": sanitize_recipient_name(donor_name or "Voluntary Donor"),
            "email": donor_email.strip().lower(),
            "blood_type": blood_type
        })

    is_reserve = fulfilled_via_reserve or len(donors_to_notify) == 0

    # 1. Email to Requester / Clinician
    clean_req_title = requester_name or "Clinician"
    if requester_email and "@" in requester_email:
        if is_reserve:
            req_subject = f"Transfusion Demand Closed: {patient_name} ({blood_type}) - Fulfilled via Clinical Reserve"
            req_text = f"""Dear {clean_req_title},

Your emergency transfusion demand for patient {patient_name} ({blood_type}, {units_needed} Pints) at {hospital} has been marked as FULFILLED and closed via Alternative Clinical Reserve / External Stock.

No voluntary donor pledge was consumed for this delivery. The emergency ticket is officially closed in the triage registry.

BloodMatch Emergency Transfusion Network • Clinical Reserve Operations
"""
            req_html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #F8F9FA; margin: 0; padding: 20px; -webkit-font-smoothing: antialiased; }}
    .card {{ max-width: 540px; width: 100%; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E2E8F0; padding: 28px; box-shadow: 0 4px 12px rgba(0,0,0,0.04); box-sizing: border-box; }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; background: #EFF6FF; color: #1E40AF; font-size: 11px; font-weight: 700; text-transform: uppercase; margin-bottom: 12px; }}
    h2 {{ color: #1A1D20; font-size: 18px; margin: 0 0 12px; font-weight: 800; }}
    p {{ color: #4A5568; font-size: 13px; line-height: 1.6; margin: 0 0 14px; word-break: break-word; }}
    .box {{ background: #F0F9FF; border: 1px solid #BAE6FD; border-radius: 12px; padding: 14px; margin: 16px 0; font-size: 12px; color: #0369A1; word-break: break-word; }}
    .footer {{ font-size: 11px; color: #718096; margin-top: 20px; text-align: center; }}
    @media only screen and (max-width: 600px) {{
      body {{ padding: 10px 8px !important; }}
      .card {{ padding: 20px 14px !important; border-radius: 12px !important; }}
      h2 {{ font-size: 16.5px !important; }}
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">✓ Closed via Clinical Reserve</div>
    <h2>Emergency Request Fulfilled via Alternative Reserve</h2>
    <p>Dear {clean_req_title},</p>
    <p>Your emergency transfusion demand has been fulfilled through hospital reserve/external supply and logged in the clinical ledger.</p>
    <div class="box">
      <strong>Patient:</strong> {patient_name} ({blood_type}, {units_needed} Pints)<br>
      <strong>Facility:</strong> {hospital}<br>
      <strong>Fulfillment Source:</strong> Alternative Clinical Reserve / External Stock (No voluntary donor assigned)<br>
      <strong>Status:</strong> Case Logged &amp; Transfusion Completed
    </div>
    <p>The emergency request has been marked fulfilled and active live tracking is closed.</p>
    <div class="footer">BloodMatch Clinical Operations • Emergency Triage Registry</div>
  </div>
</body>
</html>"""
        else:
            donor_summary = ", ".join([f"{d['name']} ({d['blood_type']})" for d in donors_to_notify])
            req_subject = f"Transfusion Demand Fulfilled: {patient_name} ({blood_type})"
            req_text = f"""Dear {clean_req_title},

Your emergency transfusion demand for patient {patient_name} ({blood_type}, {units_needed} Pints) at {hospital} has been marked as FULFILLED.

Fulfilled By Contributing Lifesaver(s):
{donor_summary}

The emergency call has been closed and gratitude notifications have been transmitted to all participating lifesavers.

BloodMatch Emergency Transfusion Network • Clinical Operations
"""
            req_html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #F8F9FA; margin: 0; padding: 20px; -webkit-font-smoothing: antialiased; }}
    .card {{ max-width: 540px; width: 100%; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E2E8F0; padding: 28px; box-shadow: 0 4px 12px rgba(0,0,0,0.04); box-sizing: border-box; }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; background: #DEF7EC; color: #03543F; font-size: 11px; font-weight: 700; text-transform: uppercase; margin-bottom: 12px; }}
    h2 {{ color: #1A1D20; font-size: 18px; margin: 0 0 12px; font-weight: 800; }}
    p {{ color: #4A5568; font-size: 13px; line-height: 1.6; margin: 0 0 14px; word-break: break-word; }}
    .box {{ background: #F7FAFC; border: 1px solid #E2E8F0; border-radius: 12px; padding: 14px; margin: 16px 0; font-size: 12px; word-break: break-word; }}
    .footer {{ font-size: 11px; color: #718096; margin-top: 20px; text-align: center; }}
    @media only screen and (max-width: 600px) {{
      body {{ padding: 10px 8px !important; }}
      .card {{ padding: 20px 14px !important; border-radius: 12px !important; }}
      h2 {{ font-size: 16.5px !important; }}
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">✓ Transfusion Fulfilled</div>
    <h2>Emergency Request Successfully Closed</h2>
    <p>Dear {clean_req_title},</p>
    <p>Your emergency transfusion call has been successfully fulfilled and logged into the clinical ledger.</p>
    <div class="box">
      <strong>Patient:</strong> {patient_name} ({blood_type}, {units_needed} Pints)<br>
      <strong>Facility:</strong> {hospital}<br>
      <strong>Fulfilled By Lifesaver(s):</strong> {donor_summary}<br>
      <strong>Status:</strong> Case Logged &amp; Transfusion Completed
    </div>
    <p>Heartfelt gratitude notices have been dispatched to all participating voluntary lifesavers.</p>
    <div class="footer">BloodMatch Clinical Operations • Case Logged &amp; Fulfilled</div>
  </div>
</body>
</html>"""

        try:
            gas_req_payload = {
                "to": requester_email,
                "name": requester_name or "Clinician",
                "subject": req_subject,
                "text_body": req_text,
                "html_body": req_html,
                "action": "transfusion_fulfilled_requester"
            }
            if _dispatch_google_apps_script("transfusion_fulfilled_requester", gas_req_payload):
                results["requester_sent"] = True
            else:
                results["requester_sent"] = _dispatch_smtp(req_subject, requester_email, req_text, req_html)
        except Exception as exc:
            logger.warning(f"Could not send fulfillment email to requester: {exc}")

    # 2. Individual Emails to Each Fulfilling Donor
    for d in donors_to_notify:
        d_email = d["email"]
        d_name = d["name"]
        d_group = d.get("blood_type", blood_type)

        donor_subject = f"Thank You for Saving a Life: Blood Transfusion Completed"
        donor_text = f"""Dear {d_name},

Thank you! Your voluntary blood donation has fulfilled the urgent transfusion demand for patient {patient_name} ({blood_type}).

Your generosity and readiness made an immediate life-saving difference today.

With deepest gratitude,
BloodMatch Clinical Operations Network
"""
        donor_html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #F8F9FA; margin: 0; padding: 20px; -webkit-font-smoothing: antialiased; }}
    .card {{ max-width: 540px; width: 100%; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E2E8F0; padding: 28px; box-shadow: 0 4px 12px rgba(0,0,0,0.04); box-sizing: border-box; }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; background: #FDE8E8; color: #9B1C1C; font-size: 11px; font-weight: 700; text-transform: uppercase; margin-bottom: 12px; }}
    h2 {{ color: #1A1D20; font-size: 18px; margin: 0 0 12px; font-weight: 800; }}
    p {{ color: #4A5568; font-size: 13px; line-height: 1.6; margin: 0 0 14px; word-break: break-word; }}
    .box {{ background: #FDF2F2; border: 1px solid #FBD5D5; border-radius: 12px; padding: 14px; margin: 16px 0; font-size: 12px; color: #771D1D; word-break: break-word; }}
    .footer {{ font-size: 11px; color: #718096; margin-top: 20px; text-align: center; }}
    @media only screen and (max-width: 600px) {{
      body {{ padding: 10px 8px !important; }}
      .card {{ padding: 20px 14px !important; border-radius: 12px !important; }}
      h2 {{ font-size: 16.5px !important; }}
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">♥ Life-Saving Donor</div>
    <h2>Thank You for Your Blood Donation</h2>
    <p>Dear {d_name},</p>
    <p>We are writing to express our sincere clinical gratitude. Your voluntary donation has successfully fulfilled the urgent transfusion demand for patient <strong>{patient_name}</strong> ({blood_type}).</p>
    <div class="box">
      <strong>Transfusion Record:</strong> Patient {patient_name} • Group {blood_type}<br>
      <strong>Hospital Facility:</strong> {hospital}<br>
      <strong>Donor Attribution:</strong> {d_name} (Group {d_group})<br>
      <strong>Status:</strong> Successfully Transfused &amp; Completed
    </div>
    <p>Your selfless contribution and swift mobilization truly helped save a life today.</p>
    <div class="footer">BloodMatch Voluntary Donor Network • Clinical Gratitude Node</div>
  </div>
</body>
</html>"""
        try:
            gas_donor_payload = {
                "to": d_email,
                "name": d_name,
                "subject": donor_subject,
                "text_body": donor_text,
                "html_body": donor_html,
                "action": "transfusion_fulfilled_donor"
            }
            if _dispatch_google_apps_script("transfusion_fulfilled_donor", gas_donor_payload):
                results["donors_sent"] += 1
            elif _dispatch_smtp(donor_subject, d_email, donor_text, donor_html):
                results["donors_sent"] += 1
        except Exception as exc:
            logger.warning(f"Could not send thanks email to donor {d_email}: {exc}")

    return results

def send_live_tracking_match_email(
    clinician_email: str,
    clinician_name: str,
    patient_name: str,
    blood_type: str,
    request_id: str,
    donor_name: str,
    donor_blood_type: str,
    donor_phone: str,
    donor_email: str,
    donor_location: str
) -> bool:
    """
    Dispatches automated instant alert to the clinician/requester when Live Tracking detects
    a newly registered compatible voluntary donor.
    """
    clinician_name = sanitize_recipient_name(clinician_name) or "Emergency Clinician"
    donor_name = sanitize_recipient_name(donor_name)
    subject = f"🚨 Compatible Blood Arrived! Live Tracking Match for Patient {patient_name} ({blood_type})"

    text_body = f"""LIVE TRACKING ALERT: COMPATIBLE BLOOD HAS ARRIVED

Dear {clinician_name},

A certified voluntary donor matching your active emergency request has just registered into the BloodMatch network!

Patient: {patient_name} ({blood_type})
Emergency Request ID: {request_id}

MATCHED COMPATIBLE DONOR:
- Name: {donor_name}
- Blood Group: {donor_blood_type} (Compatible with {blood_type})
- Phone: {donor_phone}
- Email: {donor_email}
- Location: {donor_location}

You can contact this donor immediately or view their dossier on your Emergency Triage Board:
https://blood-match-software.bloodmatch-support.workers.dev/dashboard/emergency

BloodMatch Emergency Transfusion Network • Live Proximity Tracking Node
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #F8F9FA; margin: 0; padding: 20px; -webkit-font-smoothing: antialiased; }}
    .container {{ max-width: 560px; width: 100%; margin: 0 auto; background: #FFFFFF; border-radius: 16px; border: 1px solid #E2E8F0; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.06); }}
    .header {{ background: linear-gradient(135deg, #1A1D20 0%, #2D3748 100%); padding: 24px 28px; text-align: left; }}
    .brand {{ font-size: 11px; font-weight: 800; letter-spacing: 1.5px; color: #D72638; text-transform: uppercase; margin-bottom: 6px; }}
    .title {{ font-size: 18px; font-weight: 800; color: #FFFFFF; margin: 0; }}
    .content {{ padding: 24px; }}
    .radar-badge {{ display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 20px; background: #ECFDF5; color: #065F46; font-size: 11px; font-weight: 800; text-transform: uppercase; margin-bottom: 16px; border: 1px solid #A7F3D0; }}
    .patient-box {{ background: #FDF2F2; border-left: 4px solid #D72638; padding: 14px 16px; border-radius: 8px; margin-bottom: 18px; }}
    .donor-card {{ background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 12px; padding: 16px; margin-bottom: 18px; }}
    .donor-table {{ width: 100%; border-collapse: collapse; }}
    .donor-table td {{ padding: 7px 0; font-size: 12.5px; }}
    .donor-label {{ color: #718096; font-weight: 600; width: 35%; }}
    .donor-val {{ color: #1A1D20; font-weight: 700; word-break: break-word; }}
    .btn {{ display: inline-block; padding: 12px 20px; background: #D72638; color: #FFFFFF !important; font-size: 13px; font-weight: 700; text-decoration: none; border-radius: 10px; margin-top: 8px; text-align: center; box-sizing: border-box; }}
    .footer {{ background: #F8FAFC; padding: 16px 24px; font-size: 11px; color: #A0AEC0; text-align: center; border-top: 1px solid #EDF2F7; }}
    @media only screen and (max-width: 600px) {{
      body {{ padding: 8px !important; }}
      .header {{ padding: 18px 16px !important; }}
      .content {{ padding: 16px 12px !important; }}
      .btn {{ display: block !important; width: 100% !important; margin: 8px 0 !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">BloodMatch Emergency Operations</div>
      <div class="title">🚨 Compatible Blood Arrived (Live Tracking Alert)</div>
    </div>
    <div class="content">
      <div class="radar-badge">● Live Proximity Radar Match</div>
      <p style="font-size: 14px; color: #2D3748; line-height: 1.5; margin-top: 0;">
        Dear <strong>{clinician_name}</strong>,<br>
        Your active Live Tracking radar has detected that a compatible voluntary donor has just enrolled for patient <strong>{patient_name}</strong>!
      </p>

      <div class="patient-box">
        <div style="font-size: 11px; font-weight: 700; color: #9B1C1C; text-transform: uppercase;">Emergency Request #{request_id}</div>
        <div style="font-size: 14px; font-weight: 800; color: #1A1D20; margin-top: 2px;">Patient: {patient_name} &bull; Required Blood: <span style="color: #D72638;">{blood_type}</span></div>
      </div>

      <div class="donor-card">
        <div style="font-size: 12px; font-weight: 800; color: #1A1D20; text-transform: uppercase; margin-bottom: 10px; border-bottom: 1px solid #E2E8F0; padding-bottom: 6px;">
          Certified Compatible Donor Details
        </div>
        <table class="donor-table">
          <tr>
            <td class="donor-label">Donor Name</td>
            <td class="donor-val">{donor_name}</td>
          </tr>
          <tr>
            <td class="donor-label">Blood Group</td>
            <td class="donor-val" style="color: #059669;">{donor_blood_type} (Compatible with {blood_type})</td>
          </tr>
          <tr>
            <td class="donor-label">Contact Phone</td>
            <td class="donor-val"><a href="tel:{donor_phone}" style="color: #D72638; text-decoration: none;">{donor_phone}</a></td>
          </tr>
          <tr>
            <td class="donor-label">Email Address</td>
            <td class="donor-val"><a href="mailto:{donor_email}" style="color: #2563EB; text-decoration: none;">{donor_email}</a></td>
          </tr>
          <tr>
            <td class="donor-label">Location</td>
            <td class="donor-val">{donor_location}</td>
          </tr>
        </table>
      </div>

      <div style="text-align: center; margin-top: 18px;">
        <a href="tel:{donor_phone}" class="btn" style="background: #059669; margin-right: 8px;">📞 Call Donor Directly</a>
        <a href="https://blood-match-software.bloodmatch-support.workers.dev/dashboard/emergency" class="btn">View Triage Board</a>
      </div>
    </div>
    <div class="footer">
      BloodMatch Network &bull; Automated Live Tracking Dispatch &bull; Sync ID #{request_id}
    </div>
  </div>
</body>
</html>
"""

    gas_payload = {
        "to": clinician_email,
        "name": clinician_name,
        "patient_name": patient_name,
        "blood_type": blood_type,
        "request_id": request_id,
        "donor_name": donor_name,
        "donor_blood_type": donor_blood_type,
        "donor_phone": donor_phone,
        "donor_email": donor_email,
        "donor_location": donor_location,
        "action": "live_tracking_match_alert",
        "html_body": html_body,
        "subject": subject
    }

    if _dispatch_google_apps_script("live_tracking_match_alert", gas_payload):
        return True

    return _dispatch_smtp(subject, clinician_email, text_body, html_body)

