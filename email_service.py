import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

# ==========================================
# JINJA2 EMAIL TEMPLATES
# ==========================================

EMAIL_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Your BloodMatch Account</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0B0E14; color: #E2E8F0; margin: 0; padding: 0; }
    .container { max-width: 580px; margin: 40px auto; background: #111726; border: 1px solid #1E293B; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6); }
    .header { background: linear-gradient(135deg, #7F1D1D 0%, #DC2626 100%); padding: 32px 24px; text-align: center; }
    .header h1 { margin: 0; color: #FFFFFF; font-size: 26px; letter-spacing: -0.5px; font-weight: 800; }
    .header p { margin: 8px 0 0 0; color: #FEE2E2; font-size: 13px; letter-spacing: 1px; text-transform: uppercase; }
    .content { padding: 36px 32px; }
    .greeting { font-size: 18px; font-weight: 600; color: #F8FAFC; margin-bottom: 12px; }
    .message { font-size: 15px; line-height: 1.6; color: #94A3B8; margin-bottom: 28px; }
    .otp-box { background: #06090F; border: 2px dashed #DC2626; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0; }
    .otp-code { font-family: 'Courier New', Courier, monospace; font-size: 38px; font-weight: 800; letter-spacing: 12px; color: #EF4444; display: inline-block; margin: 0; }
    .timer-alert { margin-top: 12px; font-size: 13px; color: #CBD5E1; font-weight: 500; }
    .guidance-box { background: rgba(30, 41, 59, 0.5); border-left: 4px solid #DC2626; padding: 14px 18px; border-radius: 6px; margin-top: 24px; font-size: 13px; color: #94A3B8; line-height: 1.5; }
    .footer { border-top: 1px solid #1E293B; padding: 24px; text-align: center; font-size: 12px; color: #64748B; background: #0D121D; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🩸 BloodMatch Emergency Network</h1>
      <p>Clinical Account Authentication Token</p>
    </div>
    <div class="content">
      <div class="greeting">Hello, {{ name }}</div>
      <div class="message">Thank you for registering with the BloodMatch Transfusion Network. Please use the following single-use verification token to activate your clinical profile.</div>
      <div class="otp-box">
        <div class="otp-code">{{ otp_code }}</div>
        <div class="timer-alert">⏱ Valid for 10 minutes (Strict 30s resend cooldown)</div>
      </div>
      <div class="guidance-box">
        <strong>Security Notice:</strong> Never share this verification token with anyone. BloodMatch staff will never ask for your authentication codes.
      </div>
    </div>
    <div class="footer">
      BloodMatch Clinical Transfusion Systems &bull; Automated Dispatch Node<br>
      If you did not request this account registration, you can safely ignore this notification.
    </div>
  </div>
</body>
</html>
"""

EMAIL_TEXT_TEMPLATE = """
BloodMatch Emergency Transfusion Network
Clinical Account Verification

Hello, {{ name }}

Your 6-digit verification code is: {{ otp_code }}

This code is valid for 10 minutes. A strict 30-second cooldown applies before new tokens may be requested.
If you did not initiate this registration, please disregard this email.
"""

LOCKOUT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CRITICAL: Account Lockout Security Alert</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0B0E14; color: #E2E8F0; margin: 0; padding: 0; }
    .container { max-width: 580px; margin: 40px auto; background: #111726; border: 1px solid #EF4444; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(220, 38, 38, 0.2); }
    .header { background: linear-gradient(135deg, #991B1B 0%, #450A0A 100%); padding: 32px 24px; text-align: center; border-bottom: 2px solid #EF4444; }
    .header h1 { margin: 0; color: #FFFFFF; font-size: 24px; font-weight: 800; }
    .header p { margin: 8px 0 0 0; color: #FCA5A5; font-size: 13px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; }
    .content { padding: 36px 32px; }
    .greeting { font-size: 18px; font-weight: 700; color: #F8FAFC; margin-bottom: 12px; }
    .message { font-size: 15px; line-height: 1.6; color: #CBD5E1; margin-bottom: 24px; }
    .unlock-box { background: #06090F; border: 2px solid #EF4444; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0; }
    .unlock-code { font-family: 'Courier New', Courier, monospace; font-size: 40px; font-weight: 900; letter-spacing: 14px; color: #F87171; display: inline-block; margin: 0; }
    .timer-alert { margin-top: 12px; font-size: 13px; color: #FCA5A5; font-weight: 600; }
    .guidance-box { background: rgba(69, 10, 10, 0.4); border-left: 4px solid #EF4444; padding: 16px 20px; border-radius: 6px; margin-top: 24px; font-size: 13px; color: #FECACA; line-height: 1.6; }
    .footer { border-top: 1px solid #1E293B; padding: 24px; text-align: center; font-size: 12px; color: #64748B; background: #0D121D; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚨 CRITICAL SECURITY ALERT</h1>
      <p>Account Locked &bull; Multiple Failed Login Attempts</p>
    </div>
    <div class="content">
      <div class="greeting">Attention, {{ name }}</div>
      <div class="message">Your BloodMatch clinical account was automatically locked after <strong>3 consecutive failed password attempts</strong> to safeguard transfusion authorization records from unauthorized brute-force scripts.</div>
      <div class="unlock-box">
        <div class="unlock-code">{{ unlock_code }}</div>
        <div class="timer-alert">⏱ Emergency Unlock Code expires in 10 minutes</div>
      </div>
      <div class="guidance-box">
        <strong>Immediate Security Action:</strong> If this attempt was NOT initiated by you, your credentials may be compromised. Use this emergency unlock code to unlock your account and immediately update your clinical password.
      </div>
    </div>
    <div class="footer">
      BloodMatch Autonomous Threat Mitigation Node &bull; Transfusion Zero-Trust Infrastructure<br>
      This is an automated cryptographic alert. Do not reply to this dispatch.
    </div>
  </div>
</body>
</html>
"""

LOCKOUT_TEXT_TEMPLATE = """
CRITICAL SECURITY ALERT: Account Locked

Hello, {{ name }}

Your BloodMatch clinical account was locked after 3 consecutive failed login attempts.
Your 6-digit emergency reset/unlock code is: {{ unlock_code }}

This unlock code is valid for 10 minutes.
If you did not perform these login attempts, immediately unlock your account and change your security credentials.
"""

RESET_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Password Reset Request</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0B0E14; color: #E2E8F0; margin: 0; padding: 0; }
    .container { max-width: 580px; margin: 40px auto; background: #111726; border: 1px solid #3B82F6; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6); }
    .header { background: linear-gradient(135deg, #1E3A8A 0%, #2563EB 100%); padding: 32px 24px; text-align: center; }
    .header h1 { margin: 0; color: #FFFFFF; font-size: 24px; font-weight: 800; }
    .header p { margin: 8px 0 0 0; color: #DBEAFE; font-size: 13px; letter-spacing: 1px; text-transform: uppercase; }
    .content { padding: 36px 32px; }
    .greeting { font-size: 18px; font-weight: 600; color: #F8FAFC; margin-bottom: 12px; }
    .message { font-size: 15px; line-height: 1.6; color: #94A3B8; margin-bottom: 24px; }
    .otp-box { background: #06090F; border: 2px dashed #3B82F6; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0; }
    .otp-code { font-family: 'Courier New', Courier, monospace; font-size: 38px; font-weight: 800; letter-spacing: 12px; color: #60A5FA; display: inline-block; margin: 0; }
    .timer-alert { margin-top: 12px; font-size: 13px; color: #93C5FD; font-weight: 500; }
    .guidance-box { background: rgba(30, 58, 138, 0.3); border-left: 4px solid #3B82F6; padding: 14px 18px; border-radius: 6px; margin-top: 24px; font-size: 13px; color: #BFDBFE; line-height: 1.5; }
    .footer { border-top: 1px solid #1E293B; padding: 24px; text-align: center; font-size: 12px; color: #64748B; background: #0D121D; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔐 BloodMatch Security</h1>
      <p>Password Reset Verification Code</p>
    </div>
    <div class="content">
      <div class="greeting">Hello, {{ name }}</div>
      <div class="message">We received a request to reset the password for your BloodMatch clinical account. Please enter the following 6-digit verification code to proceed:</div>
      <div class="otp-box">
        <div class="otp-code">{{ otp_code }}</div>
        <div class="timer-alert">⏱ Valid for 10 minutes (30-second resend limit)</div>
      </div>
      <div class="guidance-box">
        <strong>Important:</strong> If you did not request a password reset, your credentials may be exposed. We recommend contacting facility security immediately.
      </div>
    </div>
    <div class="footer">
      BloodMatch Transfusion Network &bull; Automated Security Service<br>
      If you did not initiate this request, you can safely disregard this email.
    </div>
  </div>
</body>
</html>
"""

RESET_TEXT_TEMPLATE = """
BloodMatch Transfusion Network - Password Reset Request

Hello, {{ name }}

Your 6-digit password reset verification code is: {{ otp_code }}

This code is valid for 10 minutes.
If you did not request this, please contact clinical security immediately.
"""

CHANGED_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Notice: Password Successfully Changed</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0B0E14; color: #E2E8F0; margin: 0; padding: 0; }
    .container { max-width: 580px; margin: 40px auto; background: #111726; border: 1px solid #10B981; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(16, 185, 129, 0.2); }
    .header { background: linear-gradient(135deg, #065F46 0%, #10B981 100%); padding: 32px 24px; text-align: center; }
    .header h1 { margin: 0; color: #FFFFFF; font-size: 24px; font-weight: 800; }
    .header p { margin: 8px 0 0 0; color: #D1FAE5; font-size: 13px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }
    .content { padding: 36px 32px; }
    .greeting { font-size: 18px; font-weight: 700; color: #F8FAFC; margin-bottom: 12px; }
    .message { font-size: 15px; line-height: 1.6; color: #CBD5E1; margin-bottom: 24px; }
    .audit-card { background: #06090F; border: 1px solid #1E293B; border-radius: 12px; padding: 20px; margin: 20px 0; }
    .audit-item { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1E293B; font-size: 14px; }
    .audit-item:last-child { border-bottom: none; }
    .audit-label { color: #94A3B8; font-weight: 500; }
    .audit-value { color: #F1F5F9; font-weight: 600; font-family: monospace; }
    .guidance-box { background: rgba(6, 95, 70, 0.3); border-left: 4px solid #10B981; padding: 16px 20px; border-radius: 6px; margin-top: 24px; font-size: 13px; color: #A7F3D0; line-height: 1.6; }
    .footer { border-top: 1px solid #1E293B; padding: 24px; text-align: center; font-size: 12px; color: #64748B; background: #0D121D; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>✅ Security Audit Confirmation</h1>
      <p>Password Successfully Updated</p>
    </div>
    <div class="content">
      <div class="greeting">Hello, {{ name }}</div>
      <div class="message">The password for your BloodMatch clinical account was successfully updated. Any active account lockouts have been automatically cleared.</div>
      <div class="audit-card">
        <div class="audit-item">
          <span class="audit-label">Timestamp (UTC):</span>
          <span class="audit-value">{{ timestamp }}</span>
        </div>
        <div class="audit-item">
          <span class="audit-label">Client Device / Agent:</span>
          <span class="audit-value">{{ device_info }}</span>
        </div>
        <div class="audit-item">
          <span class="audit-label">Origin IP Address:</span>
          <span class="audit-value">{{ ip_address }}</span>
        </div>
      </div>
      <div class="guidance-box">
        <strong>Audit Warning:</strong> If you did NOT initiate this password change, your account has been compromised. Please immediately lock your clinical credentials and notify security operations.
      </div>
    </div>
    <div class="footer">
      BloodMatch Autonomous Threat Mitigation Node &bull; Transfusion Zero-Trust Infrastructure<br>
      This is an automated audit receipt.
    </div>
  </div>
</body>
</html>
"""

CHANGED_TEXT_TEMPLATE = """
Security Audit Notice: Password Successfully Changed

Hello, {{ name }}

The password for your BloodMatch account was updated at {{ timestamp }}.
Client Device: {{ device_info }}
Origin IP: {{ ip_address }}

If you did not make this change, please report this unauthorized activity immediately.
"""

# Compile Jinja2 Templates
jinja_html_template = Template(EMAIL_HTML_TEMPLATE)
jinja_text_template = Template(EMAIL_TEXT_TEMPLATE)
jinja_lockout_html = Template(LOCKOUT_HTML_TEMPLATE)
jinja_lockout_text = Template(LOCKOUT_TEXT_TEMPLATE)
jinja_reset_html = Template(RESET_HTML_TEMPLATE)
jinja_reset_text = Template(RESET_TEXT_TEMPLATE)
jinja_changed_html = Template(CHANGED_HTML_TEMPLATE)
jinja_changed_text = Template(CHANGED_TEXT_TEMPLATE)

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
    rendered_html = jinja_html_template.render(name=recipient_name, otp_code=otp_code)
    rendered_text = jinja_text_template.render(name=recipient_name, otp_code=otp_code)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(f"[SIMULATED EMAIL DISPATCH] Recipient: {recipient_email} | Name: {recipient_name} | OTP: {otp_code}")
        return True
    return _dispatch_smtp(f"Your BloodMatch Verification Code: {otp_code}", recipient_email, rendered_text, rendered_html)

def send_lockout_alert_email(recipient_email: str, recipient_name: str, unlock_code: str) -> bool:
    rendered_html = jinja_lockout_html.render(name=recipient_name, unlock_code=unlock_code)
    rendered_text = jinja_lockout_text.render(name=recipient_name, unlock_code=unlock_code)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(f"[CRITICAL LOCKOUT SIMULATION] Recipient: {recipient_email} | Name: {recipient_name} | Unlock Code: {unlock_code}")
        return True
    return _dispatch_smtp(f"🚨 URGENT: BloodMatch Account Locked - Emergency Reset Code: {unlock_code}", recipient_email, rendered_text, rendered_html)

def send_password_reset_email(recipient_email: str, recipient_name: str, otp_code: str) -> bool:
    """Dispatches the 6-digit password reset verification code."""
    rendered_html = jinja_reset_html.render(name=recipient_name, otp_code=otp_code)
    rendered_text = jinja_reset_text.render(name=recipient_name, otp_code=otp_code)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(f"[PASSWORD RESET CODE DISPATCH] Recipient: {recipient_email} | Name: {recipient_name} | Reset OTP: {otp_code} (10m expiry)")
        return True
    return _dispatch_smtp(f"BloodMatch Password Reset Verification Code: {otp_code}", recipient_email, rendered_text, rendered_html)

TWO_FACTOR_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Two-Factor Authentication Challenge</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0B0E14; color: #E2E8F0; margin: 0; padding: 0; }
    .container { max-width: 580px; margin: 40px auto; background: #111726; border: 1px solid #6366F1; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(99, 102, 241, 0.2); }
    .header { background: linear-gradient(135deg, #4338CA 0%, #6366F1 100%); padding: 32px 24px; text-align: center; }
    .header h1 { margin: 0; color: #FFFFFF; font-size: 24px; font-weight: 800; }
    .header p { margin: 8px 0 0 0; color: #E0E7FF; font-size: 13px; letter-spacing: 1px; text-transform: uppercase; font-weight: 600; }
    .content { padding: 36px 32px; }
    .greeting { font-size: 18px; font-weight: 700; color: #F8FAFC; margin-bottom: 12px; }
    .message { font-size: 15px; line-height: 1.6; color: #94A3B8; margin-bottom: 24px; }
    .otp-box { background: #06090F; border: 2px dashed #6366F1; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0; }
    .otp-code { font-family: 'Courier New', Courier, monospace; font-size: 38px; font-weight: 800; letter-spacing: 12px; color: #818CF8; display: inline-block; margin: 0; }
    .timer-alert { margin-top: 12px; font-size: 13px; color: #C7D2FE; font-weight: 500; }
    .audit-card { background: #06090F; border: 1px solid #1E293B; border-radius: 12px; padding: 16px; margin: 20px 0; font-size: 13px; }
    .audit-row { display: flex; justify-content: space-between; padding: 6px 0; color: #94A3B8; }
    .audit-val { color: #F1F5F9; font-weight: 600; }
    .guidance-box { background: rgba(67, 56, 202, 0.2); border-left: 4px solid #6366F1; padding: 14px 18px; border-radius: 6px; margin-top: 24px; font-size: 13px; color: #C7D2FE; line-height: 1.5; }
    .footer { border-top: 1px solid #1E293B; padding: 24px; text-align: center; font-size: 12px; color: #64748B; background: #0D121D; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ Two-Factor Authentication</h1>
      <p>Security Step-Up Verification</p>
    </div>
    <div class="content">
      <div class="greeting">Hello, {{ name }}</div>
      <div class="message">A sign-in attempt was initiated from a new or protected device. Please submit the following single-use 6-digit 2FA token to complete authentication:</div>
      <div class="otp-box">
        <div class="otp-code">{{ otp_code }}</div>
        <div class="timer-alert">⏱ Valid for 10 minutes</div>
      </div>
      <div class="audit-card">
        <div class="audit-row"><span>Attempted Terminal:</span><span class="audit-val">{{ device_name }}</span></div>
        <div class="audit-row"><span>Source IP Address:</span><span class="audit-val">{{ ip_address }}</span></div>
      </div>
      <div class="guidance-box">
        <strong>Security Notice:</strong> If you did not initiate this login attempt, your credentials may be known to an unauthorized party. Change your password immediately.
      </div>
    </div>
    <div class="footer">
      BloodMatch Transfusion Network &bull; Autonomous Threat Defense Node<br>
      Do not share this authentication token with anyone.
    </div>
  </div>
</body>
</html>
"""

TWO_FACTOR_TEXT_TEMPLATE = """
BloodMatch Two-Factor Authentication Challenge

Hello, {{ name }}

Your 6-digit login verification code is: {{ otp_code }}
Attempted Device: {{ device_name }}
Source IP: {{ ip_address }}

This code is valid for 10 minutes.
If you did not initiate this sign-in, please change your password immediately.
"""

jinja_2fa_html = Template(TWO_FACTOR_HTML_TEMPLATE)
jinja_2fa_text = Template(TWO_FACTOR_TEXT_TEMPLATE)

def send_password_changed_notification(
    recipient_email: str,
    recipient_name: str,
    timestamp: str,
    device_info: str,
    ip_address: str
) -> bool:
    """Dispatches the security audit confirmation email upon successful password update."""
    rendered_html = jinja_changed_html.render(
        name=recipient_name,
        timestamp=timestamp,
        device_info=device_info,
        ip_address=ip_address
    )
    rendered_text = jinja_changed_text.render(
        name=recipient_name,
        timestamp=timestamp,
        device_info=device_info,
        ip_address=ip_address
    )

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(
            f"[SECURITY AUDIT CONFIRMATION] Recipient: {recipient_email} | Password Changed at: {timestamp} | Device: {device_info} | IP: {ip_address}"
        )
        return True
    return _dispatch_smtp("✅ Security Notice: BloodMatch Password Successfully Updated", recipient_email, rendered_text, rendered_html)

def send_2fa_login_email(
    recipient_email: str,
    recipient_name: str,
    otp_code: str,
    device_name: str,
    ip_address: str
) -> bool:
    """Dispatches 2FA step-up login verification email."""
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
    return _dispatch_smtp(f"🛡️ BloodMatch 2FA Login Code: {otp_code}", recipient_email, rendered_text, rendered_html)

