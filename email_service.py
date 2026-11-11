import os
import smtplib
import logging
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from jinja2 import Template

logger = logging.getLogger("BloodBackend.EmailService")

# Environment-based SMTP configuration (Zero hardcoded credentials)
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "security@bloodmatch.io").strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "BloodMatch Transfusion Network").strip()
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")

# Autonomous Google Apps Script Webhook Integration
DEFAULT_GOOGLE_APP_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzhmRKBulGYrdLIAaJDLnqbP6-nbyV6vwhhm-mF5GB2cKr6KuMb0CmAXls3A2obCCNG/exec"
GOOGLE_APP_SCRIPT_URL = os.getenv("GOOGLE_APP_SCRIPT_URL", DEFAULT_GOOGLE_APP_SCRIPT_URL).strip() or DEFAULT_GOOGLE_APP_SCRIPT_URL

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
  <title>Account Verification Code</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
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
        <div class="otp-container">
          <div class="otp-label">Single-Use Security Token</div>
          <div class="otp-code">{{ otp_code }}</div>
          <div class="otp-validity">⏱ Valid for 10 minutes • Single device session</div>
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
  <title>CRITICAL: Account Lockout Security Alert</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; margin: 0 auto; background: #FFFFFF; border: 1.5px solid #D72638; border-radius: 20px; overflow: hidden; }
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
        <div class="unlock-container">
          <div class="unlock-label">Emergency Reset / Unlock Code</div>
          <div class="unlock-code">{{ unlock_code }}</div>
          <div class="unlock-validity">⏱ Valid for 10 minutes • Clear lockout immediately</div>
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
  <title>Password Reset Code</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
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
        <div class="otp-container">
          <div class="otp-label">Password Recovery Token</div>
          <div class="otp-code">{{ otp_code }}</div>
          <div class="otp-validity">⏱ Valid for 10 minutes • Single-use</div>
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
  <title>Security Alert: Password Changed</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
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
    .notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 20px; }
    .notice-box strong { color: #D72638; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
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
          <div class="audit-row"><span class="audit-label">Timestamp</span><span class="audit-val">{{ timestamp }}</span></div>
          <div class="audit-row"><span class="audit-label">Terminal / Device</span><span class="audit-val">{{ browser }}</span></div>
          <div class="audit-row"><span class="audit-label">Origin Network IP</span><span class="audit-val">{{ ip_address }}</span></div>
        </div>
        <div class="notice-box"><strong>Important:</strong> If you did not make this change, your credentials may be compromised. Lock down your terminal and report this incident to your facility trauma administrator immediately.</div>
      </div>
      <div class="footer">BloodMatch Clinical Security Service • Real-Time Transfusion Defense</div>
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
  <title>Two-Factor Authentication Challenge</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
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
    .audit-card { background: #FAF8F7; border: 1px solid #D9C7C2; border-radius: 14px; padding: 14px 18px; margin: 20px 0; font-size: 12px; }
    .audit-row { display: flex; justify-content: space-between; padding: 5px 0; color: #5A626A; }
    .audit-val { color: #1A1D20; font-weight: 700; }
    .notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 20px; }
    .notice-box strong { color: #D72638; }
    .footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="header"><span class="brand-pill">Step-Up 2FA Challenge</span></div>
      <div class="content">
        <h1 class="title">Two-Factor Authentication</h1>
        <div class="greeting">Hello, {{ name }}</div>
        <p class="paragraph">A sign-in attempt was initiated from a new or protected workstation. Please submit the following single-use 6-digit code in the login portal to complete authentication:</p>
        <div class="otp-container">
          <div class="otp-label">2FA Login Code</div>
          <div class="otp-code">{{ otp_code }}</div>
          <div class="otp-validity">⏱ Valid for 10 minutes • Device Step-Up</div>
        </div>
        <div class="audit-card">
          <div class="audit-row"><span>Attempted Terminal:</span><span class="audit-val">{{ device_name }}</span></div>
          <div class="audit-row"><span>Source IP Address:</span><span class="audit-val">{{ ip_address }}</span></div>
        </div>
        <div class="notice-box"><strong>Security Notice:</strong> If you did not initiate this sign-in attempt, your credentials may be known to an unauthorized party. Change your password immediately.</div>
      </div>
      <div class="footer">BloodMatch Transfusion Network • Autonomous Threat Defense Node</div>
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
  <title>Welcome to BloodMatch Transfusion Network</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
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

NEW_SESSION_HTML_FALLBACK = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>New Session Login Advisory</title>
  <style>
    body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1A1D20; }
    .wrapper { width: 100%; background-color: #F5F1EF; padding: 36px 16px; box-sizing: border-box; }
    .card { max-width: 520px; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; }
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
          <div class="audit-title">New Session Telemetry</div>
          <div class="audit-row"><span class="audit-label">Workstation</span><span class="audit-val">{{ device_name }}</span></div>
          <div class="audit-row"><span class="audit-label">Origin Network IP</span><span class="audit-val">{{ ip_address }}</span></div>
          <div class="audit-row"><span class="audit-label">Location</span><span class="audit-val">{{ location }}</span></div>
          <div class="audit-row"><span class="audit-label">Timestamp</span><span class="audit-val">{{ timestamp }}</span></div>
        </div>
        <div class="notice-box">
          <strong>Security Notice:</strong> If this was not you, someone may have compromised your credentials. Log into your dashboard and remotely revoke this workstation in Security Settings immediately.
        </div>
      </div>
      <div class="footer">BloodMatch Emergency Transfusion Network • Automated Session Registry<br>Real-Time Transfusion Node Monitor</div>
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

jinja_session_html = Template(NEW_SESSION_HTML_FALLBACK)
jinja_session_text = Template(NEW_SESSION_TEXT_TEMPLATE)

def _dispatch_google_apps_script(action: str, payload: dict) -> bool:
    """Dispatches transactional email payload to autonomous Google Apps Script webhook."""
    if not GOOGLE_APP_SCRIPT_URL:
        return False
    try:
        data = {
            "action": action,
            **payload
        }
        resp = requests.post(GOOGLE_APP_SCRIPT_URL, json=data, timeout=12)
        if resp.status_code in (200, 302):
            try:
                res_json = resp.json()
                if res_json.get("success"):
                    logger.info(f"[GAS WEBHOOK SUCCESS] Dispatched {action} to {payload.get('to')}")
                    return True
                else:
                    logger.warning(f"[GAS WEBHOOK WARNING] Webhook returned error: {res_json.get('error')}")
            except Exception:
                # 200/302 response processed by Google Apps Script successfully
                logger.info(f"[GAS WEBHOOK SUCCESS] Dispatched {action} to {payload.get('to')} (HTTP {resp.status_code})")
                return True
        logger.warning(f"[GAS WEBHOOK WARNING] HTTP status {resp.status_code}: {resp.text[:120]}")
        return False
    except Exception as exc:
        logger.error(f"[GAS WEBHOOK ERROR] Failed to dispatch {action} to {GOOGLE_APP_SCRIPT_URL}: {exc}")
        return False

def _dispatch_smtp(subject: str, recipient_email: str, text_body: str, html_body: str) -> bool:
    """Internal helper to dispatch MIME multipart emails via SMTP."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg["To"] = recipient_email

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

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
