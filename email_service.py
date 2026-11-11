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

EMAIL_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Your BloodMatch Account</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #0B0E14;
      color: #E2E8F0;
      margin: 0;
      padding: 0;
    }
    .container {
      max-width: 580px;
      margin: 40px auto;
      background: #111726;
      border: 1px solid #1E293B;
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
    }
    .header {
      background: linear-gradient(135deg, #7F1D1D 0%, #DC2626 100%);
      padding: 32px 24px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      color: #FFFFFF;
      font-size: 26px;
      letter-spacing: -0.5px;
      font-weight: 800;
    }
    .header p {
      margin: 8px 0 0 0;
      color: #FEE2E2;
      font-size: 13px;
      letter-spacing: 1px;
      text-transform: uppercase;
    }
    .content {
      padding: 36px 32px;
    }
    .greeting {
      font-size: 18px;
      font-weight: 600;
      color: #F8FAFC;
      margin-bottom: 12px;
    }
    .message {
      font-size: 15px;
      line-height: 1.6;
      color: #94A3B8;
      margin-bottom: 28px;
    }
    .otp-box {
      background: #06090F;
      border: 2px dashed #DC2626;
      border-radius: 12px;
      padding: 24px;
      text-align: center;
      margin: 24px 0;
    }
    .otp-code {
      font-family: 'Courier New', Courier, monospace;
      font-size: 38px;
      font-weight: 800;
      letter-spacing: 12px;
      color: #EF4444;
      display: inline-block;
      margin: 0;
    }
    .timer-alert {
      margin-top: 12px;
      font-size: 13px;
      color: #CBD5E1;
      font-weight: 500;
    }
    .guidance-box {
      background: rgba(30, 41, 59, 0.5);
      border-left: 4px solid #DC2626;
      padding: 14px 18px;
      border-radius: 6px;
      margin-top: 24px;
      font-size: 13px;
      color: #94A3B8;
      line-height: 1.5;
    }
    .footer {
      border-top: 1px solid #1E293B;
      padding: 24px;
      text-align: center;
      font-size: 12px;
      color: #64748B;
      background: #0D121D;
    }
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
      <div class="message">
        Thank you for registering with the BloodMatch Transfusion Network. Please use the following single-use verification token to activate your clinical profile.
      </div>

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
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #0B0E14;
      color: #E2E8F0;
      margin: 0;
      padding: 0;
    }
    .container {
      max-width: 580px;
      margin: 40px auto;
      background: #111726;
      border: 1px solid #EF4444;
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 20px 40px rgba(220, 38, 38, 0.2);
    }
    .header {
      background: linear-gradient(135deg, #991B1B 0%, #450A0A 100%);
      padding: 32px 24px;
      text-align: center;
      border-bottom: 2px solid #EF4444;
    }
    .header h1 {
      margin: 0;
      color: #FFFFFF;
      font-size: 24px;
      font-weight: 800;
    }
    .header p {
      margin: 8px 0 0 0;
      color: #FCA5A5;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
    }
    .content {
      padding: 36px 32px;
    }
    .greeting {
      font-size: 18px;
      font-weight: 700;
      color: #F8FAFC;
      margin-bottom: 12px;
    }
    .message {
      font-size: 15px;
      line-height: 1.6;
      color: #CBD5E1;
      margin-bottom: 24px;
    }
    .unlock-box {
      background: #06090F;
      border: 2px solid #EF4444;
      border-radius: 12px;
      padding: 24px;
      text-align: center;
      margin: 24px 0;
    }
    .unlock-code {
      font-family: 'Courier New', Courier, monospace;
      font-size: 40px;
      font-weight: 900;
      letter-spacing: 14px;
      color: #F87171;
      display: inline-block;
      margin: 0;
    }
    .timer-alert {
      margin-top: 12px;
      font-size: 13px;
      color: #FCA5A5;
      font-weight: 600;
    }
    .guidance-box {
      background: rgba(69, 10, 10, 0.4);
      border-left: 4px solid #EF4444;
      padding: 16px 20px;
      border-radius: 6px;
      margin-top: 24px;
      font-size: 13px;
      color: #FECACA;
      line-height: 1.6;
    }
    .footer {
      border-top: 1px solid #1E293B;
      padding: 24px;
      text-align: center;
      font-size: 12px;
      color: #64748B;
      background: #0D121D;
    }
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
      <div class="message">
        Your BloodMatch clinical account was automatically locked after <strong>3 consecutive failed password attempts</strong> to safeguard transfusion authorization records from unauthorized brute-force scripts.
      </div>

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

jinja_html_template = Template(EMAIL_HTML_TEMPLATE)
jinja_text_template = Template(EMAIL_TEXT_TEMPLATE)
jinja_lockout_html = Template(LOCKOUT_HTML_TEMPLATE)
jinja_lockout_text = Template(LOCKOUT_TEXT_TEMPLATE)

def send_verification_email(recipient_email: str, recipient_name: str, otp_code: str) -> bool:
    """
    Renders Jinja2 HTML email and dispatches it via SMTP.
    If SMTP credentials are not configured, logs simulated dispatch for local resilience.
    """
    rendered_html = jinja_html_template.render(name=recipient_name, otp_code=otp_code)
    rendered_text = jinja_text_template.render(name=recipient_name, otp_code=otp_code)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(
            f"[SIMULATED EMAIL DISPATCH] Recipient: {recipient_email} | Name: {recipient_name} | OTP: {otp_code} | "
            f"(Live dispatch dormant: Configure SMTP_HOST, SMTP_USER, SMTP_PASSWORD in environment)"
        )
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Your BloodMatch Verification Code: {otp_code}"
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg["To"] = recipient_email

        msg.attach(MIMEText(rendered_text, "plain", "utf-8"))
        msg.attach(MIMEText(rendered_html, "html", "utf-8"))

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

        logger.info(f"Verification email successfully sent to {recipient_email} via SMTP ({SMTP_HOST}).")
        return True
    except Exception as exc:
        logger.error(f"Failed to dispatch verification email to {recipient_email}: {exc}")
        return False

def send_lockout_alert_email(recipient_email: str, recipient_name: str, unlock_code: str) -> bool:
    """
    Renders Jinja2 emergency security lockout email and dispatches it via SMTP.
    If SMTP credentials are not configured, logs simulated dispatch for local resilience.
    """
    rendered_html = jinja_lockout_html.render(name=recipient_name, unlock_code=unlock_code)
    rendered_text = jinja_lockout_text.render(name=recipient_name, unlock_code=unlock_code)

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        logger.info(
            f"[CRITICAL LOCKOUT SIMULATION] Recipient: {recipient_email} | Name: {recipient_name} | "
            f"Emergency Unlock Code: {unlock_code} (Valid for 10 minutes) | "
            f"(Live dispatch dormant: Configure SMTP_HOST, SMTP_USER, SMTP_PASSWORD in environment)"
        )
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 URGENT: BloodMatch Account Locked - Emergency Reset Code: {unlock_code}"
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg["To"] = recipient_email

        msg.attach(MIMEText(rendered_text, "plain", "utf-8"))
        msg.attach(MIMEText(rendered_html, "html", "utf-8"))

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

        logger.info(f"Lockout security alert email successfully sent to {recipient_email} via SMTP ({SMTP_HOST}).")
        return True
    except Exception as exc:
        logger.error(f"Failed to dispatch lockout alert email to {recipient_email}: {exc}")
        return False
