# BloodMatch Google Apps Script Webhook Deployment Guide

This directory contains the production-grade Google Apps Script email engine (`Code.gs`) powering all transactional emails for the BloodMatch Emergency Transfusion Network.

## File Location
- **Google Apps Script Source**: `D:\BloodProject\BloodBackend\google_apps_script\Code.gs`

---

## Supported Automated Email Templates
1. **Account Registration OTP (`otp_verification`)**: 6-digit clinical verification token.
2. **Adaptive 2FA Login OTP (`2fa_login`)**: Step-up authentication code with workstation name & IP.
3. **New Login Session Security Alert (`new_login_session`)**: Instant alert when a new browser, device, or workstation accesses the account.
4. **Password Reset Code (`password_reset`)**: Single-use 6-digit recovery code.
5. **Password Changed Confirmation (`password_changed`)**: Security audit trail with timestamp, browser, and network IP.
6. **Account Lockout Emergency Alert (`account_lockout`)**: Emergency unlock token after 3 consecutive failed attempts.
7. **Profile Verified Welcome & Activation (`welcome_thankyou`)**: Formal onboarding confirmation once registration OTP is completed.

---

### Testing Directly in Google Apps Script Editor

If you want to test email sending directly from inside the editor before deploying:
1. Select **`myFunction`** or **`testEmailWebhook`** from the function dropdown (located next to the **Debug** button in the top toolbar).
2. Click **Run**.
3. Google will ask you to authorize access for the first time:
   - Click **Review permissions** $\rightarrow$ select your Google account $\rightarrow$ click **Advanced** $\rightarrow$ click **Go to BloodMatch (unsafe)** $\rightarrow$ click **Allow**.
4. Check your Gmail inbox: you will receive a test BloodMatch 6-digit verification code email!

---

## Deployment Steps in Google Apps Script

1. **Open the Google Apps Script Editor**:
   - Go to [script.google.com](https://script.google.com) and open your `BloodMatch` project (as shown in your browser tab).
2. **Paste the Code**:
   - Open `Code.gs` in the editor.
   - Replace any existing code with the complete contents of `D:\BloodProject\BloodBackend\google_apps_script\Code.gs`.
3. **Deploy as a Web App**:
   - Click the blue **Deploy** button (top right) -> **New deployment**.
   - Select type: **Web app** (via the gear icon next to "Select type").
   - Set **Description**: `BloodMatch Production Email Webhook v2`.
   - Set **Execute as**: `Me (your_email@gmail.com)`.
   - Set **Who has access**: `Anyone`. *(Important: Must be set to Anyone so the backend API can deliver payloads without OAuth prompt).*
   - Click **Deploy**.
4. **Grant Permissions**:
   - If prompted, click **Authorize access**, select your Google account, click **Advanced** -> **Go to BloodMatch (unsafe)**, and click **Allow** (authorizes `MailApp.sendEmail`).
5. **Copy the Web App URL**:
   - Copy the generated Web App URL (starts with `https://script.google.com/macros/s/.../exec`).
6. **Save to `.env`**:
   - Update `GOOGLE_APP_SCRIPT_URL` in `D:\BloodProject\BloodBackend\.env` with this URL:
     ```env
     GOOGLE_APP_SCRIPT_URL=https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec
     ```

