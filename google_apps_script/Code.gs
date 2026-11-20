/**
 * =========================================================================
 * BLOODMATCH EMERGENCY TRANSFUSION NETWORK
 * Autonomous Google Apps Script Email Delivery Webhook (Code.gs)
 * =========================================================================
 * 
 * Capabilities:
 * 1. Account Registration OTP Verification (`otp_verification` / `verification`)
 * 2. Adaptive 2FA Step-Up Login Code (`2fa_login` / `step_up_otp`)
 * 3. New Login Device / Session Security Advisory (`new_login_session` / `session_alert`)
 * 4. Password Reset Recovery Token (`password_reset`)
 * 5. Password Changed Confirmation with Audit Trail (`password_changed`)
 * 6. Account Lockout Emergency Reset Alert (`account_lockout` / `lockout_alert`)
 * 7. Verified Profile Welcome & Activation Notification (`welcome_thankyou` / `welcome`)
 * 
 * Deployment:
 * - Deploy as Web App -> Execute as: Me -> Who has access: Anyone
 */

// Global sender configuration
var SENDER_NAME = "BloodMatch Transfusion Network";

/**
 * =========================================================================
 * TOOLBAR TEST RUNNER & MYFUNCTION COMPATIBILITY
 * When you click the "Run" button in the Google Apps Script editor, this runs.
 * =========================================================================
 */
function myFunction() {
  return testEmailWebhook();
}

function testFulfillRequesterEmail() {
  var currentEmail = Session.getActiveUser().getEmail();
  var recipient = currentEmail ? currentEmail : "test@bloodmatch.io";
  
  Logger.log("Testing Transfusion Fulfilled Requester Email to: " + recipient);
  
  var mockEvent = {
    postData: {
      contents: JSON.stringify({
        action: "transfusion_fulfilled_requester",
        to: recipient,
        name: "Farhan Khalid",
        patient_name: "Emergency Patient",
        blood_type: "B+",
        units_needed: 2,
        hospital: "Emergency Trauma Network, Delhi NCR",
        donor_name: "Priority Lifesaver",
        fulfilled_via_reserve: false
      })
    }
  };
  
  var result = doPost(mockEvent);
  return result.getContent();
}

function testFulfillDonorEmail() {
  var currentEmail = Session.getActiveUser().getEmail();
  var recipient = currentEmail ? currentEmail : "test@bloodmatch.io";
  
  Logger.log("Testing Transfusion Fulfilled Donor Gratitude Email to: " + recipient);
  
  var mockEvent = {
    postData: {
      contents: JSON.stringify({
        action: "transfusion_fulfilled_donor",
        to: recipient,
        name: "Priority Lifesaver",
        patient_name: "Emergency Patient",
        blood_type: "B+",
        hospital: "Emergency Trauma Network, Delhi NCR",
        donor_blood_type: "B+"
      })
    }
  };
  
  var result = doPost(mockEvent);
  return result.getContent();
}

function testEmailWebhook() {
  var currentEmail = Session.getActiveUser().getEmail();
  var recipient = currentEmail ? currentEmail : "test@bloodmatch.io";
  
  Logger.log("Initiating BloodMatch test verification email to: " + recipient);
  
  var mockEvent = {
    postData: {
      contents: JSON.stringify({
        action: "otp_verification",
        to: recipient,
        name: "Farhan Khalid",
        otp_code: "839201"
      })
    }
  };
  
  var result = doPost(mockEvent);
  var output = result.getContent();
  Logger.log("Execution Output: " + output);
  return output;
}

/**
 * HTTP GET Handler (Health Check & Connectivity Ping)
 */
function doGet(e) {
  var responseData = {
    status: "online",
    service: "BloodMatch Google Apps Script Webhook Node",
    timestamp: new Date().toISOString(),
    version: "2.0.0",
    actionsSupported: [
      "otp_verification",
      "2fa_login",
      "new_login_session",
      "password_reset",
      "password_changed",
      "account_lockout",
      "welcome_thankyou",
      "clinician_donor_roster",
      "transfusion_fulfilled_requester",
      "transfusion_fulfilled_donor",
      "emergency_donor_dispatch",
      "emergency_donor_dispatch_confirmation",
      "live_tracking_match_alert"
    ]
  };
  
  Logger.log("[BloodMatch Gateway] Health check passed. Webhook operational.");
  return ContentService.createTextOutput(JSON.stringify(responseData))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * HTTP POST Handler (Transactional Email Dispatch)
 */
function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return errorResponse("Missing POST body payload");
    }

    var payload = JSON.parse(e.postData.contents);
    var action = (payload.action || payload.type || "").toLowerCase().trim();
    var to = (payload.to || payload.recipient_email || payload.email || "").trim();
    var name = (payload.name || payload.recipient_name || "Clinician").trim();

    if (!to) {
      return errorResponse("Missing recipient email address ('to')");
    }

    var emailData = null;
    if (payload.html_body && payload.subject) {
      emailData = {
        subject: payload.subject,
        textBody: payload.text_body || "",
        htmlBody: payload.html_body
      };
    } else {
      emailData = buildEmailContent(action, name, payload);
    }
    if (!emailData) {
      return errorResponse("Unsupported or unrecognized action: " + action);
    }

    // Dispatch via Google Apps Script MailApp engine with optional PDF attachment
    var mailOptions = {
      to: to,
      subject: emailData.subject,
      body: emailData.textBody,
      htmlBody: emailData.htmlBody,
      name: SENDER_NAME
    };

    if (payload.pdf_base64) {
      try {
        var pdfBytes = Utilities.base64Decode(payload.pdf_base64);
        var filename = payload.pdf_filename || ("BloodMatch_Emergency_Docket_" + (payload.recipient_blood_type || "") + ".pdf");
        var pdfBlob = Utilities.newBlob(pdfBytes, "application/pdf", filename);
        mailOptions.attachments = [pdfBlob];
      } catch (attachErr) {
        Logger.log("[Attachment Warning] Failed to attach PDF docket: " + attachErr);
      }
    }

    MailApp.sendEmail(mailOptions);

    var successData = {
      success: true,
      action: action,
      recipient: to,
      dispatchedAt: new Date().toISOString()
    };

    return ContentService.createTextOutput(JSON.stringify(successData))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    return errorResponse(err.toString());
  }
}

/**
 * Helper to build JSON error response
 */
function errorResponse(message) {
  var errorData = {
    success: false,
    error: message,
    timestamp: new Date().toISOString()
  };
  return ContentService.createTextOutput(JSON.stringify(errorData))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Template Router & Builder
 */
function buildEmailContent(action, name, payload) {
  switch (action) {
    case "verification":
    case "otp_verification":
      return buildVerificationEmail(name, payload);

    case "2fa_login":
    case "step_up_otp":
      return build2FALoginEmail(name, payload);

    case "new_login_session":
    case "session_alert":
      return buildNewSessionEmail(name, payload);

    case "password_reset":
      return buildPasswordResetEmail(name, payload);

    case "password_changed":
      return buildPasswordChangedEmail(name, payload);

    case "account_lockout":
    case "lockout_alert":
      return buildLockoutEmail(name, payload);

    case "welcome":
    case "welcome_thankyou":
      return buildWelcomeEmail(name, payload);

    case "donor_thankyou":
    case "donor_registration":
      return buildDonorThankYouEmail(name, payload);

    case "transfusion_fulfilled_requester":
    case "transfusion_fulfilled":
    case "request_fulfilled":
      if (payload.html_body && payload.subject) {
        return {
          subject: payload.subject,
          textBody: payload.text_body || "",
          htmlBody: payload.html_body
        };
      }
      return buildTransfusionFulfilledRequesterEmail(name, payload);

    case "transfusion_fulfilled_donor":
    case "donor_gratitude":
      if (payload.html_body && payload.subject) {
        return {
          subject: payload.subject,
          textBody: payload.text_body || "",
          htmlBody: payload.html_body
        };
      }
      return buildTransfusionFulfilledDonorEmail(name, payload);

    case "emergency_donor_dispatch":
      if (payload.html_body && payload.subject) {
        return {
          subject: payload.subject,
          textBody: payload.text_body || "",
          htmlBody: payload.html_body
        };
      }
      return buildEmergencyDonorDispatchEmail(name, payload);

    case "emergency_donor_dispatch_confirmation":
      if (payload.html_body && payload.subject) {
        return {
          subject: payload.subject,
          textBody: payload.text_body || "",
          htmlBody: payload.html_body
        };
      }
      return buildEmergencyDonorDispatchConfirmationEmail(name, payload);

    case "live_tracking_match_alert":
      if (payload.html_body && payload.subject) {
        return {
          subject: payload.subject,
          textBody: payload.text_body || "",
          htmlBody: payload.html_body
        };
      }
      return buildLiveTrackingMatchAlertEmail(name, payload);

    case "clinician_donor_roster":
      if (payload.html_body && payload.subject) {
        return {
          subject: payload.subject,
          textBody: payload.text_body || "",
          htmlBody: payload.html_body
        };
      }
      return buildClinicianDonorRosterEmail(name, payload);

    default:
      return null;
  }
}

// =========================================================================
// EMAIL TEMPLATE IMPLEMENTATIONS (MINIMAL, ZERO BUTTONS, BLOODMATCH UI SYSTEM)
// =========================================================================

/**
 * 1. Account Registration Verification Code
 */
function buildVerificationEmail(name, payload) {
  var code = payload.otp_code || payload.code || "------";
  var subject = "BloodMatch Verification Code: " + code;
  
  var textBody = 
    "BloodMatch Emergency Transfusion Network\n" +
    "Account Verification Code\n\n" +
    "Hello, " + name + ",\n\n" +
    "Thank you for registering with the BloodMatch Transfusion Network. Please use the following single-use verification code in the application to activate your clinical profile:\n\n" +
    "Verification Code: " + code + "\n" +
    "(Valid for 10 minutes • Single device session)\n\n" +
    "Security Notice: Never share this verification token with anyone. BloodMatch personnel will never ask for your authentication codes.\n\n" +
    "BloodMatch Emergency Transfusion Network • Automated Clinical Dispatch Node";

  var htmlContent =
    '<div class="header"><span class="brand-pill">BloodMatch Clinical Network</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Account Verification Code</h1>' +
      '<div class="greeting">Hello, ' + escapeHtml(name) + '</div>' +
      '<p class="paragraph">Thank you for registering with the BloodMatch Transfusion Network. Please use the following single-use verification code in the application to activate your clinical profile.</p>' +
      '<div class="otp-container">' +
        '<div class="otp-label">Single-Use Security Token</div>' +
        '<div class="otp-code">' + escapeHtml(code) + '</div>' +
        '<div class="otp-validity">⏱ Valid for 10 minutes • Single device session</div>' +
      '</div>' +
      '<div class="notice-box">' +
        '<strong>Security Notice:</strong> Never share this verification token with anyone. BloodMatch personnel will never ask for your authentication codes.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Automated Clinical Dispatch Node<br>' +
      'If you did not request this registration, please disregard this email.' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Account Verification Code")
  };
}

/**
 * 2. Adaptive Two-Factor Authentication (2FA) Step-Up Login Code
 */
function build2FALoginEmail(name, payload) {
  var code = payload.otp_code || payload.code || "------";
  var device = payload.device_name || payload.browser || "Unknown Terminal";
  var ip = payload.ip_address || "Encrypted LAN Node";
  var subject = "BloodMatch 2FA Login Code: " + code;

  var textBody = 
    "BloodMatch Emergency Transfusion Network\n" +
    "Two-Factor Authentication Step-Up\n\n" +
    "Hello, " + name + ",\n\n" +
    "An authentication attempt was detected on your account requiring two-factor authorization.\n\n" +
    "Attempted Terminal: " + device + "\n" +
    "Network IP: " + ip + "\n\n" +
    "Two-Factor Security Code: " + code + "\n" +
    "(Valid for 10 minutes • Single-use authentication)\n\n" +
    "Security Notice: If you did not initiate this login attempt, please secure your account credentials immediately.\n\n" +
    "BloodMatch Emergency Transfusion Network • Automated Security Gate";

  var htmlContent =
    '<div class="header"><span class="brand-pill">BloodMatch Security Gate</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Two-Factor Authentication</h1>' +
      '<div class="greeting">Hello, ' + escapeHtml(name) + '</div>' +
      '<p class="paragraph">An authentication attempt was detected on your account from a workstation requiring step-up two-factor verification. Enter the security code below to complete sign in.</p>' +
      '<div class="otp-container">' +
        '<div class="otp-label">Two-Factor Security Code</div>' +
        '<div class="otp-code">' + escapeHtml(code) + '</div>' +
        '<div class="otp-validity">⏱ Valid for 10 minutes • Single-use authorization</div>' +
      '</div>' +
      '<div class="audit-card">' +
        '<div class="audit-title" style="margin-bottom: 12px;">Access Request Telemetry</div>' +
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Workstation</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(device) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Network IP</td>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">' + escapeHtml(ip) + '</td>' +
          '</tr>' +
        '</table>' +
      '</div>' +
      '<div class="notice-box">' +
        '<strong>Security Notice:</strong> If you did not initiate this login request, change your password immediately to protect your clinical account.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Automated Security Gate<br>' +
      'Tier-4 Encrypted • 256-Bit TLS Verification Node' +
      '<div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Security Dispatch #' + new Date().getTime().toString(36).toUpperCase() + ' • ' + (new Date().toISOString()) + '</div>' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Two-Factor Authentication")
  };
}

/**
 * 3. New Login Session / Active Device Security Advisory
 */
function buildNewSessionEmail(name, payload) {
  var device = payload.device_name || payload.browser || "Unknown Terminal";
  var ip = payload.ip_address || "Encrypted Node";
  var location = payload.location || "Authorized Clinical Facility";
  var timestamp = payload.timestamp || new Date().toUTCString();
  var subject = "Security Notice: New Session Login on BloodMatch";

  var textBody = 
    "BloodMatch Emergency Transfusion Network\n" +
    "Security Advisory: New Device Session\n\n" +
    "Hello, " + name + ",\n\n" +
    "Your BloodMatch clinical account was accessed from a new active session or device:\n\n" +
    "Workstation: " + device + "\n" +
    "Network IP: " + ip + "\n" +
    "Location: " + location + "\n" +
    "Timestamp: " + timestamp + "\n\n" +
    "If this was you, no further action is necessary. If you do not recognize this activity, navigate to Settings > Active Terminal Sessions to remotely revoke this device immediately.\n\n" +
    "BloodMatch Emergency Transfusion Network • Automated Security Gate";

  var htmlContent =
    '<div class="header"><span class="brand-pill">BloodMatch Security Advisory</span></div>' +
    '<div class="content">' +
      '<h1 class="title">New Active Session Detected</h1>' +
      '<div class="greeting">Hello, ' + escapeHtml(name) + '</div>' +
      '<p class="paragraph">Your BloodMatch account was authenticated from a new workstation session. Review the access telemetry below to ensure this session was authorized by you.</p>' +
      '<div class="audit-card">' +
        '<div class="audit-title" style="margin-bottom: 12px;">New Session Telemetry</div>' +
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Workstation</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(device) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Origin Network IP</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">' + escapeHtml(ip) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Location</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(location) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Timestamp</td>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">' + escapeHtml(timestamp) + '</td>' +
          '</tr>' +
        '</table>' +
      '</div>' +
      '<div class="notice-box">' +
        '<strong>Security Notice:</strong> If this was not you, someone may have compromised your credentials. Log into your dashboard and remotely revoke this workstation in Security Settings immediately.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Automated Session Registry<br>' +
      'Real-Time Transfusion Node Monitor' +
      '<div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Session Dispatch #' + new Date().getTime().toString(36).toUpperCase() + ' • ' + (payload.timestamp || new Date().toISOString()) + '</div>' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "New Session Login Advisory")
  };
}

/**
 * 4. Password Reset Recovery Code
 */
function buildPasswordResetEmail(name, payload) {
  var code = payload.otp_code || payload.code || "------";
  var subject = "BloodMatch Password Reset Verification Code: " + code;

  var textBody = 
    "BloodMatch Emergency Transfusion Network\n" +
    "Password Reset Verification Code\n\n" +
    "Hello, " + name + ",\n\n" +
    "We received an authentication request to reset your clinical account password. Enter the following 6-digit recovery code in the password recovery modal to verify your identity and set a new password:\n\n" +
    "Password Recovery Token: " + code + "\n" +
    "(Valid for 10 minutes • Single-use)\n\n" +
    "Security Notice: If you did not request a password reset, your credentials may be targeted. Please notify your facility network administrator immediately.\n\n" +
    "BloodMatch Emergency Transfusion Network • Automated Security Gate";

  var htmlContent =
    '<div class="header"><span class="brand-pill">BloodMatch Security Center</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Password Reset Code</h1>' +
      '<div class="greeting">Hello, ' + escapeHtml(name) + '</div>' +
      '<p class="paragraph">We received an authentication request to reset your clinical account password. Enter the following 6-digit recovery code in the password recovery modal to verify your identity and set a new password.</p>' +
      '<div class="otp-container">' +
        '<div class="otp-label">Password Recovery Token</div>' +
        '<div class="otp-code">' + escapeHtml(code) + '</div>' +
        '<div class="otp-validity">⏱ Valid for 10 minutes • Single-use</div>' +
      '</div>' +
      '<div class="notice-box">' +
        '<strong>Security Notice:</strong> If you did not request a password reset, your credentials may be targeted. Please notify your facility network administrator immediately.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Automated Security Gate<br>' +
      '256-Bit Transfusion Protocol Verification Node' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Password Reset Code")
  };
}

/**
 * 5. Password Changed Confirmation with Audit Trail
 */
function buildPasswordChangedEmail(name, payload) {
  var timestamp = payload.timestamp || new Date().toUTCString();
  var device = payload.device_info || payload.browser || "Authenticated Terminal";
  var ip = payload.ip_address || "Encrypted Network Node";
  var subject = "Security Notice: BloodMatch Password Successfully Updated";

  var textBody = 
    "BloodMatch Emergency Transfusion Network\n" +
    "Security Password Updated\n\n" +
    "Hello, " + name + ",\n\n" +
    "This automated security advisory confirms that the access password for your clinical account has been updated successfully. Active sessions have been audited and cryptographic tokens regenerated.\n\n" +
    "Timestamp: " + timestamp + "\n" +
    "Terminal / Device: " + device + "\n" +
    "Origin Network IP: " + ip + "\n\n" +
    "Important: If you did not make this change, your credentials may be compromised. Lock down your terminal and report this incident to your facility trauma administrator immediately.\n\n" +
    "BloodMatch Emergency Transfusion Network • Automated Security Gate";

  var htmlContent =
    '<div class="header"><span class="brand-pill">BloodMatch Security Alert</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Security Password Updated</h1>' +
      '<div class="greeting">Hello, ' + escapeHtml(name) + '</div>' +
      '<p class="paragraph">This automated security advisory confirms that the access password for your clinical account has been updated successfully. Active sessions have been audited and cryptographic tokens regenerated.</p>' +
      '<div class="audit-card">' +
        '<div class="audit-title" style="margin-bottom: 12px;">Security Event Audit Trail</div>' +
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Timestamp</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">' + escapeHtml(timestamp) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Terminal / Device</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(device) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Origin Network IP</td>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right; font-family: monospace;">' + escapeHtml(ip) + '</td>' +
          '</tr>' +
        '</table>' +
      '</div>' +
      '<div class="notice-box">' +
        '<strong>Important:</strong> If you did not make this change, your credentials may be compromised. Lock down your terminal and report this incident to your facility trauma administrator immediately.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Automated Security Gate<br>' +
      'Tier-4 Encrypted • HIPAA Compliant' +
      '<div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Audit Ref: #' + (payload.timestamp || new Date().toISOString()) + '</div>' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Security Password Updated")
  };
}

/**
 * 6. Account Lockout Emergency Reset Alert
 */
function buildLockoutEmail(name, payload) {
  var unlockCode = payload.unlock_code || payload.code || "------";
  var subject = "🚨 URGENT: BloodMatch Account Locked - Emergency Reset Code: " + unlockCode;

  var textBody = 
    "BloodMatch Emergency Transfusion Network\n" +
    "SECURITY LOCKOUT ALERT: 3 Consecutive Failed Attempts\n\n" +
    "Hello, " + name + ",\n\n" +
    "Your BloodMatch clinical account has been temporarily locked after 3 consecutive failed login attempts to safeguard critical trauma transfusion data.\n\n" +
    "Emergency Unlock Token: " + unlockCode + "\n" +
    "(Valid for 15 minutes • Single-use)\n\n" +
    "Please enter this unlock token in the application or reset your password immediately.\n\n" +
    "BloodMatch Emergency Transfusion Network • Autonomous Security Guard";

  var htmlContent =
    '<div class="header"><span class="brand-pill" style="color: #7A0C17; background: #FFE8E8; border-color: #F8B4B4;">Security Alert • Lockout Active</span></div>' +
    '<div class="content">' +
      '<h1 class="title" style="color: #7A0C17;">Account Temporarily Locked</h1>' +
      '<div class="greeting">Hello, ' + escapeHtml(name) + '</div>' +
      '<p class="paragraph">Your BloodMatch clinical account has been locked after 3 consecutive failed login attempts to protect critical patient transfusion protocols against unauthorized intrusion.</p>' +
      '<div class="otp-container" style="background: #FFF5F5; border-color: #D72638;">' +
        '<div class="otp-label" style="color: #7A0C17;">Emergency Account Unlock Token</div>' +
        '<div class="otp-code">' + escapeHtml(unlockCode) + '</div>' +
        '<div class="otp-validity">⏱ Valid for 15 minutes • Single-use unlock</div>' +
      '</div>' +
      '<div class="notice-box">' +
        '<strong>Recommended Action:</strong> If this was an unauthorized attempt, immediately reset your password and notify your medical center IT coordinator.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Automated Threat Prevention<br>' +
      'Zero-Trust Transfusion Protocol Protection' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Account Lockout Alert")
  };
}

/**
 * 7. Verified Profile Welcome & Activation
 */
function buildWelcomeEmail(name, payload) {
  var memberId = payload.member_id || payload.custom_id || "";
  var subject = "Welcome to BloodMatch Emergency Transfusion Network";

  var textBody = 
    "BloodMatch Emergency Transfusion Network\n" +
    "Profile Verified & Activated\n\n" +
    "Welcome, " + name + ",\n\n" +
    "Your profile has been successfully verified and activated on the BloodMatch platform. You now have full access to your personal dashboard, 8-group cross-match matrix, and donor coordination services.\n\n" +
    (memberId ? "Member ID: " + memberId + "\n\n" : "") +
    "Thank you for being part of the BloodMatch community.\n\n" +
    "BloodMatch Emergency Transfusion Network";

  var htmlContent =
    '<div class="header"><span class="brand-pill">BloodMatch Network Welcome</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Profile Verified & Activated</h1>' +
      '<div class="greeting">Welcome, ' + escapeHtml(name) + '</div>' +
      '<p class="paragraph">Your profile has been successfully verified and activated on the BloodMatch platform. You now have full access to your personal dashboard, 8-group cross-match matrix, and donor coordination services.</p>' +
      (memberId ? '<div class="notice-box" style="background: #FDF9F8; border-color: #D72638; color: #1A1D20;"><strong>Your Unique Member ID:</strong> <span style="font-family: monospace; font-weight: 700; color: #D72638;">' + escapeHtml(memberId) + '</span></div>' : '') +
      '<div class="notice-box" style="background: #F0FDF4; border-color: #10B981; color: #166534;">' +
        '<strong>Account Ready:</strong> You are all set. You can now log into your account to manage your profile and view compatibility insights anytime.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network<br>' +
      'If you have questions or need assistance, contact our support team.' +
      '<div style="font-size: 10px; color: #A0AEC0; margin-top: 6px;">Registration Ref: #' + new Date().getTime().toString(36).toUpperCase() + '</div>' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Welcome to BloodMatch")
  };
}

/**
 * 8. Voluntary Blood Donor Thank You & Standby Advisory
 */
function buildDonorThankYouEmail(name, payload) {
  var bloodType = payload.blood_type || "Donor";
  var location = payload.location || payload.city || "your registered locality";
  var subject = "Thank You for Registering as a Voluntary Blood Donor - BloodMatch";

  var textBody = 
    "BloodMatch Emergency Transfusion Network\n" +
    "Voluntary Blood Donor Registration\n\n" +
    "Hello, " + name + ",\n\n" +
    "Thank you for registering as a voluntary blood donor with BloodMatch.\n\n" +
    "Your voluntary pledge to donate Group " + bloodType + " blood has been verified and enrolled into our live emergency transfusion directory for " + location + ".\n\n" +
    "If an emergency transfusion request matching your blood group arises in your area, our clinical coordination team will notify you immediately.\n\n" +
    "Thank you for your noble commitment to saving lives.\n\n" +
    "BloodMatch Emergency Transfusion Network";

  var htmlContent =
    '<div class="header"><span class="brand-pill">BloodMatch Voluntary Donor Network</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Thank You, Lifesaver!</h1>' +
      '<div class="greeting">Hello, ' + escapeHtml(name) + '</div>' +
      '<p class="paragraph">Thank you for registering as a certified voluntary blood donor with the BloodMatch Emergency Transfusion Network.</p>' +
      '<div class="notice-box" style="background: #FDF9F8; border-color: #D72638; color: #1A1D20;">' +
        '<strong>Pledge Enrolled:</strong> Group <span style="font-weight: 800; color: #D72638;">' + escapeHtml(bloodType) + '</span> • Area: <strong>' + escapeHtml(location) + '</strong>' +
      '</div>' +
      '<div class="notice-box" style="background: #F0FDF4; border-color: #10B981; color: #166534;">' +
        '<strong>Standby Protocol:</strong> If an emergency transfusion request matching your blood group arises in your area, our clinical coordination team will contact you directly to mobilize emergency assistance.' +
      '</div>' +
      '<p class="paragraph" style="margin-top: 18px;">Your readiness to donate in critical emergencies is an invaluable service to patients and local hospitals.</p>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network<br>' +
      'Clinical Voluntary Donor Registry' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Voluntary Donor Registration Confirmed")
  };
}

/**
 * 9. Transfusion Fulfilled Requester Notification
 */
function buildTransfusionFulfilledRequesterEmail(name, payload) {
  var patientName = payload.patient_name || "Emergency Patient";
  var bloodType = payload.blood_type || "RBC";
  var units = payload.units_needed || 1;
  var hospital = payload.hospital || "Emergency Trauma Network";
  var donorName = payload.donor_name || (payload.fulfilled_via_reserve ? "Alternative Clinical Reserve / External Stock" : "Voluntary Donor Network");
  var subject = payload.subject || ("✓ Transfusion Fulfilled: Emergency Request Closed (" + patientName + " - Group " + bloodType + ")");

  var textBody =
    "BloodMatch Emergency Transfusion Network\n" +
    "Transfusion Fulfilled: Case Successfully Closed\n\n" +
    "Dear " + name + ",\n\n" +
    "Your emergency transfusion call has been successfully fulfilled and logged into the active clinical ledger.\n\n" +
    "Patient: " + patientName + " (" + bloodType + ", " + units + " Pints)\n" +
    "Facility: " + hospital + "\n" +
    "Fulfilled By Lifesaver(s): " + donorName + "\n" +
    "Status: Case Logged & Transfusion Completed\n\n" +
    "Heartfelt gratitude notices have been dispatched to all participating voluntary lifesavers.\n\n" +
    "BloodMatch Emergency Transfusion Network • Case Logged & Fulfilled";

  var htmlContent =
    '<div class="header"><span class="brand-pill" style="color: #065F46; background: #ECFDF5; border-color: #A7F3D0;">✓ Transfusion Fulfilled</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Emergency Request Successfully Closed</h1>' +
      '<div class="greeting">Dear ' + escapeHtml(name) + ',</div>' +
      '<p class="paragraph">Your emergency transfusion call has been successfully fulfilled and logged into the active clinical ledger.</p>' +
      '<div class="audit-card">' +
        '<div class="audit-title" style="color: #065F46; margin-bottom: 12px;">Transfusion Completion Summary</div>' +
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Patient / Case</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(patientName) + ' (' + escapeHtml(bloodType) + ', ' + escapeHtml(units) + ' Pts)</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Hospital Facility</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(hospital) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Fulfilled By Lifesaver(s)</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #065F46; font-weight: 700; text-align: right;">' + escapeHtml(donorName) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Clinical Status</td>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #065F46; font-weight: 700; text-align: right;">Case Logged &amp; Transfusion Completed</td>' +
          '</tr>' +
        '</table>' +
      '</div>' +
      '<div class="notice-box" style="background: #F0FDF4; border-color: #10B981; color: #166534;">' +
        '<strong>Lifesaver Acknowledgement:</strong> Sincere gratitude notices have been dispatched to all participating voluntary lifesavers.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Case Logged &amp; Fulfilled<br>' +
      'Automated Clinical Dispatch Gateway' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Transfusion Request Fulfilled")
  };
}

/**
 * 10. Transfusion Fulfilled Donor Gratitude Notice
 */
function buildTransfusionFulfilledDonorEmail(name, payload) {
  var patientName = payload.patient_name || "Emergency Patient";
  var bloodType = payload.blood_type || "RBC";
  var donorGroup = payload.donor_blood_type || payload.blood_type || "Donor";
  var hospital = payload.hospital || "Emergency Trauma Network";
  var subject = payload.subject || "Thank You for Saving a Life: Blood Transfusion Completed";

  var textBody =
    "BloodMatch Emergency Transfusion Network\n" +
    "Thank You for Your Voluntary Blood Donation\n\n" +
    "Dear " + name + ",\n\n" +
    "We are writing to express our sincere clinical gratitude. Your voluntary donation has successfully fulfilled the urgent transfusion demand for patient " + patientName + " (" + bloodType + ").\n\n" +
    "Transfusion Record: Patient " + patientName + " • Group " + bloodType + "\n" +
    "Hospital Facility: " + hospital + "\n" +
    "Donor Attribution: " + name + " (Group " + donorGroup + ")\n" +
    "Status: Successfully Transfused & Completed\n\n" +
    "Your selfless contribution and swift mobilization truly helped save a life today.\n\n" +
    "With deepest gratitude,\n" +
    "BloodMatch Voluntary Donor Network";

  var htmlContent =
    '<div class="header"><span class="brand-pill" style="color: #7A0C17; background: #FFF0F1; border-color: #FFD4D7;">♥ Life-Saving Donor</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Thank You for Your Blood Donation</h1>' +
      '<div class="greeting">Dear ' + escapeHtml(name) + ',</div>' +
      '<p class="paragraph">We are writing to express our sincere clinical gratitude. Your voluntary blood donation has successfully fulfilled the urgent transfusion demand for patient <strong>' + escapeHtml(patientName) + '</strong> (' + escapeHtml(bloodType) + ').</p>' +
      '<div class="audit-card">' +
        '<div class="audit-title" style="margin-bottom: 12px;">Transfusion Honor Roll</div>' +
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Transfusion Record</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">Patient ' + escapeHtml(patientName) + ' • Group ' + escapeHtml(bloodType) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Hospital Facility</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(hospital) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Donor Attribution</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #D72638; font-weight: 700; text-align: right;">' + escapeHtml(name) + ' (' + escapeHtml(donorGroup) + ')</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Status</td>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #065F46; font-weight: 700; text-align: right;">Successfully Transfused &amp; Completed</td>' +
          '</tr>' +
        '</table>' +
      '</div>' +
      '<div class="notice-box" style="background: #FDF9F8; border-color: #D72638; color: #1A1D20;">' +
        '<strong>Life-Saving Impact:</strong> Your selfless contribution and swift mobilization truly helped save a life today. The clinical team and patient family extend their deepest thanks.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Voluntary Donor Network • Clinical Gratitude Node<br>' +
      'Certified Voluntary Donor Registry' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Thank You, Lifesaver")
  };
}

/**
 * 11. Emergency Donor Dispatch Alert
 */
function buildEmergencyDonorDispatchEmail(name, payload) {
  var patientName = payload.patient_name || "Emergency Patient";
  var bloodType = payload.recipient_blood_type || payload.blood_type || "Compatible";
  var facility = payload.hospital || payload.facility || "Emergency Trauma Center";
  var contactName = payload.contact_name || "Attending Clinician";
  var contactPhone = payload.contact_phone || payload.phone || "Emergency Desk";
  var subject = payload.subject || ("🚨 URGENT BLOOD ALERT: Compatible " + bloodType + " Needed Immediately");

  var textBody =
    "BloodMatch Emergency Transfusion Network\n" +
    "URGENT TRANSFUSION MOBILIZATION CALL\n\n" +
    "Dear " + name + ",\n\n" +
    "An urgent clinical transfusion call has been matched to your verified standby pledge.\n\n" +
    "Recipient Blood Type: " + bloodType + "\n" +
    "Patient / Case: " + patientName + "\n" +
    "Facility / Location: " + facility + "\n" +
    "Emergency Contact: " + contactName + " (" + contactPhone + ")\n\n" +
    "If you are available to donate, please call the emergency contact immediately.\n\n" +
    "BloodMatch Emergency Transfusion Network";

  var htmlContent =
    '<div class="header"><span class="brand-pill" style="color: #7A0C17; background: #FFF0F1; border-color: #FFD4D7;">🚨 Emergency Blood Alert</span></div>' +
    '<div class="content">' +
      '<h1 class="title" style="color: #D72638;">Immediate Transfusion Mobilization</h1>' +
      '<div class="greeting">Dear ' + escapeHtml(name) + ',</div>' +
      '<p class="paragraph">An emergency transfusion call in your area has been matched to your verified standby donor pledge for Group <strong>' + escapeHtml(bloodType) + '</strong>.</p>' +
      '<div class="audit-card">' +
        '<div class="audit-title" style="color: #D72638; margin-bottom: 12px;">Emergency Case Details</div>' +
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Target Blood Group</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #D72638; font-weight: 800; text-align: right;">Group ' + escapeHtml(bloodType) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Patient / Case</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(patientName) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Hospital Facility</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(facility) + '</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Emergency Coordinator</td>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(contactName) + ' • ' + escapeHtml(contactPhone) + '</td>' +
          '</tr>' +
        '</table>' +
      '</div>' +
      '<div class="notice-box" style="background: #FFF5F5; border-color: #D72638; color: #1A1D20;">' +
        '<strong>Direct Call:</strong> If you are able to assist, please call <strong>' + escapeHtml(contactPhone) + '</strong> immediately.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Rapid Mobilization<br>' +
      'Autonomous Clinical Coordination Node' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Emergency Blood Alert")
  };
}

/**
 * 12. Emergency Donor Dispatch Confirmation (Clinician Receipt)
 */
function buildEmergencyDonorDispatchConfirmationEmail(name, payload) {
  var donorName = payload.donor_name || "Voluntary Donor";
  var donorEmail = payload.donor_email || "";
  var patientName = payload.patient_name || "Emergency Patient";
  var bloodType = payload.recipient_blood_type || payload.blood_type || "RBC";
  var subject = payload.subject || ("Alert Dispatched: Emergency Notice Sent to " + donorName);

  var textBody =
    "BloodMatch Emergency Transfusion Network\n" +
    "Emergency Alert Dispatch Confirmation\n\n" +
    "Dear " + name + ",\n\n" +
    "An urgent transfusion alert has been successfully transmitted to voluntary lifesaver " + donorName + " (" + donorEmail + ") for patient " + patientName + " (" + bloodType + ").\n\n" +
    "BloodMatch Emergency Transfusion Network • Coordination Node";

  var htmlContent =
    '<div class="header"><span class="brand-pill" style="color: #065F46; background: #ECFDF5; border-color: #A7F3D0;">✓ Dispatch Confirmed</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Emergency Alert Transmitted</h1>' +
      '<div class="greeting">Dear ' + escapeHtml(name) + ',</div>' +
      '<p class="paragraph">An emergency transfusion mobilization alert has been successfully dispatched to voluntary lifesaver <strong>' + escapeHtml(donorName) + '</strong>.</p>' +
      '<div class="notice-box" style="background: #F0FDF4; border-color: #10B981; color: #166534;">' +
        '<strong>Recipient:</strong> ' + escapeHtml(donorName) + ' (' + escapeHtml(donorEmail) + ')<br>' +
        '<strong>Patient / Case:</strong> ' + escapeHtml(patientName) + ' (Group ' + escapeHtml(bloodType) + ')' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Dispatch Receipt' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Alert Dispatch Confirmed")
  };
}

/**
 * 13. Live Tracking Match Alert
 */
function buildLiveTrackingMatchAlertEmail(name, payload) {
  var donorName = payload.donor_name || "Compatible Voluntary Donor";
  var donorGroup = payload.donor_blood_type || "Compatible";
  var patientName = payload.patient_name || "Emergency Patient";
  var patientGroup = payload.recipient_blood_type || payload.blood_type || "Patient";
  var location = payload.location || payload.city || "your area";
  var distanceKm = payload.distance_km != null ? payload.distance_km : 0;
  var subject = payload.subject || ("⚡ Live Match Alert: Compatible Donor " + donorName + " (" + donorGroup + ") Enrolled");

  var textBody =
    "BloodMatch Emergency Transfusion Network\n" +
    "Live Proximity Match Alert\n\n" +
    "Dear " + name + ",\n\n" +
    "A compatible voluntary blood donor has just registered or mobilized near your emergency request location.\n\n" +
    "Matched Donor: " + donorName + " (Group " + donorGroup + ")\n" +
    "Patient / Case: " + patientName + " (Group " + patientGroup + ")\n" +
    "Proximity: " + distanceKm + " km (" + location + ")\n\n" +
    "Access your BloodMatch triage dashboard to view details and contact this lifesaver.\n\n" +
    "BloodMatch Emergency Transfusion Network";

  var htmlContent =
    '<div class="header"><span class="brand-pill" style="color: #7A0C17; background: #FFF0F1; border-color: #FFD4D7;">⚡ Live Proximity Match</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Compatible Donor Detected</h1>' +
      '<div class="greeting">Dear ' + escapeHtml(name) + ',</div>' +
      '<p class="paragraph">A compatible voluntary lifesaver has just registered in proximity to your emergency request for <strong>' + escapeHtml(patientName) + '</strong>.</p>' +
      '<div class="audit-card">' +
        '<div class="audit-title" style="color: #D72638; margin-bottom: 12px;">Live Match Overview</div>' +
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Matched Lifesaver</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(donorName) + ' (Group ' + escapeHtml(donorGroup) + ')</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Recipient Case</td>' +
            '<td style="padding: 8px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; color: #1A1D20; font-weight: 700; text-align: right;">' + escapeHtml(patientName) + ' (Group ' + escapeHtml(patientGroup) + ')</td>' +
          '</tr>' +
          '<tr>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #75808A; font-weight: 500; text-align: left;">Proximity Distance</td>' +
            '<td style="padding: 8px 0; font-size: 12px; color: #065F46; font-weight: 700; text-align: right;">~' + escapeHtml(distanceKm) + ' km (' + escapeHtml(location) + ')</td>' +
          '</tr>' +
        '</table>' +
      '</div>' +
      '<div class="notice-box" style="background: #FDF9F8; border-color: #D72638; color: #1A1D20;">' +
        '<strong>Triage Action:</strong> Open your BloodMatch Emergency Requests dashboard to review contact information and mobilize donation.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Proximity Radar Alert' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Live Donor Match Alert")
  };
}

/**
 * 14. Clinician Donor Roster & Docket Notification
 */
function buildClinicianDonorRosterEmail(name, payload) {
  var patientName = payload.patient_name || "Emergency Patient";
  var bloodType = payload.recipient_blood_type || payload.blood_type || "RBC";
  var donorCount = payload.donor_count || 1;
  var subject = payload.subject || ("Ranked Voluntary Donor Roster: " + patientName + " (" + bloodType + ")");

  var textBody =
    "BloodMatch Emergency Transfusion Network\n" +
    "Ranked Voluntary Donor Roster & Emergency PDF Docket\n\n" +
    "Dear " + name + ",\n\n" +
    "The ranked proximity donor roster for patient " + patientName + " (" + bloodType + ") is attached to this transmission with " + donorCount + " matched donor(s).\n\n" +
    "BloodMatch Emergency Transfusion Network";

  var htmlContent =
    '<div class="header"><span class="brand-pill">Ranked Donor Roster</span></div>' +
    '<div class="content">' +
      '<h1 class="title">Emergency Transfusion Docket</h1>' +
      '<div class="greeting">Dear ' + escapeHtml(name) + ',</div>' +
      '<p class="paragraph">The ranked voluntary donor roster for patient <strong>' + escapeHtml(patientName) + '</strong> (Group ' + escapeHtml(bloodType) + ') has been generated and attached as an official clinical PDF docket.</p>' +
      '<div class="notice-box" style="background: #F0FDF4; border-color: #10B981; color: #166534;">' +
        '<strong>PDF Attachment Included:</strong> View the attached PDF document for complete donor contact numbers and geospatial rankings.' +
      '</div>' +
    '</div>' +
    '<div class="footer">' +
      'BloodMatch Emergency Transfusion Network • Clinical Dispatch Node' +
    '</div>';

  return {
    subject: subject,
    textBody: textBody,
    htmlBody: wrapHtmlFrame(htmlContent, "Emergency Transfusion Docket")
  };
}

// =========================================================================
// HTML FRAME & UTILITIES (SHARED STYLES ACCROSS ALL TEMPLATES)
// =========================================================================

function wrapHtmlFrame(contentHtml, pageTitle) {
  return '<!DOCTYPE html>' +
    '<html lang="en">' +
    '<head>' +
      '<meta charset="UTF-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
      '<title>' + escapeHtml(pageTitle) + '</title>' +
      '<style>' +
        'body { margin: 0; padding: 0; background-color: #F5F1EF; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1A1D20; -webkit-font-smoothing: antialiased; }' +
        '.wrapper { width: 100%; background-color: #F5F1EF; padding: 40px 16px; box-sizing: border-box; }' +
        '.card { max-width: 520px; margin: 0 auto; background: #FFFFFF; border: 1px solid #D9C7C2; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04); }' +
        '.header { padding: 28px 32px 20px 32px; border-bottom: 1px solid #F5F1EF; }' +
        '.brand-pill { display: inline-block; padding: 4px 12px; background: #FFF0F1; border: 1px solid #FFD4D7; border-radius: 100px; font-size: 11px; font-weight: 700; color: #D72638; letter-spacing: 0.5px; text-transform: uppercase; }' +
        '.content { padding: 32px; }' +
        '.title { font-size: 22px; font-weight: 900; color: #1A1D20; margin: 0 0 10px 0; letter-spacing: -0.3px; }' +
        '.greeting { font-size: 14px; font-weight: 700; color: #1A1D20; margin-bottom: 8px; }' +
        '.paragraph { font-size: 13px; line-height: 1.6; color: #5A626A; margin: 0 0 20px 0; }' +
        '.otp-container { background: #FDF9F8; border: 1.5px dashed #D72638; border-radius: 14px; padding: 22px 16px; text-align: center; margin: 22px 0; }' +
        '.otp-label { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }' +
        '.otp-code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 38px; font-weight: 900; letter-spacing: 10px; color: #D72638; display: inline-block; margin: 0; line-height: 1; }' +
        '.otp-validity { margin-top: 10px; font-size: 12px; color: #7A0C17; font-weight: 600; }' +
        '.audit-card { background: #FAF8F7; border: 1px solid #D9C7C2; border-radius: 14px; padding: 18px 20px; margin: 20px 0; }' +
        '.audit-title { font-size: 11px; font-weight: 800; color: #7A0C17; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }' +
        '.audit-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #F0EAE7; font-size: 12px; }' +
        '.audit-row:last-child { border-bottom: none; }' +
        '.audit-label { color: #75808A; font-weight: 500; }' +
        '.audit-val { color: #1A1D20; font-weight: 700; font-family: "SFMono-Regular", Consolas, monospace; }' +
        '.notice-box { background: #FFF5F5; border-left: 3px solid #D72638; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #5A626A; line-height: 1.5; margin-top: 24px; }' +
        '.notice-box strong { color: #D72638; }' +
        '.footer { border-top: 1px solid #F5F1EF; padding: 20px 32px; background: #FAF8F7; font-size: 11px; color: #8C949D; line-height: 1.5; text-align: center; }' +
      '</style>' +
    '</head>' +
    '<body>' +
      '<div class="wrapper">' +
        '<div class="card">' +
          contentHtml +
        '</div>' +
      '</div>' +
    '</body>' +
    '</html>';
}

function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

