// ============================================================
// SOCIAL ENGINEERING ANALYSIS SERVICE (#8)
// ============================================================

function analyzeSocialEngineering({
  subject = "",
  plainText = "",
  html = ""
}) {
  // ----------------------------------------------------------
  // COMBINE + CLEAN EMAIL CONTENT
  // ----------------------------------------------------------

  const text = `${subject} ${plainText} ${html}`
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .toLowerCase()
    .trim();

  // ----------------------------------------------------------
  // REQUIRED SOCIAL ENGINEERING SIGNALS
  // ----------------------------------------------------------

  const signals = {
    urgency: false,
    fear_or_threat: false,
    credential_request: false,
    password_or_otp_request: false,
    financial_request: false,
    account_verification: false,
    account_takeover: false,
    suspicious_cta: false
  };

  const risk_reasons = [];

  // ----------------------------------------------------------
  // 1. URGENCY
  // ----------------------------------------------------------

  const urgencyPatterns = [
    /\burgent\b/,
    /\bimmediately\b/,
    /\basap\b/,
    /\bact now\b/,
    /\bwithin \d+ (hour|hours|minute|minutes)\b/,
    /\blast warning\b/,
    /\btime[- ]sensitive\b/,
    /\bdo not delay\b/,
    /\bwithout delay\b/
  ];

  signals.urgency = urgencyPatterns.some((pattern) =>
    pattern.test(text)
  );

  if (signals.urgency) {
    risk_reasons.push("Urgent action language detected");
  }

  // ----------------------------------------------------------
  // 2. FEAR / THREAT
  // ----------------------------------------------------------

  const fearThreatPatterns = [
    /\baccount (will be|has been) suspended\b/,
    /\baccount (will be|has been) locked\b/,
    /\baccount (will be|has been) disabled\b/,
    /\baccess (will be|has been) revoked\b/,
    /\blegal action\b/,
    /\bsecurity threat\b/,
    /\bunauthorized activity\b/,
    /\bsecurity alert\b/,
    /\baction will be taken\b/,
    /\byou will lose access\b/,
    /\bpermanently (suspended|disabled|locked)\b/
  ];

  signals.fear_or_threat = fearThreatPatterns.some((pattern) =>
    pattern.test(text)
  );

  if (signals.fear_or_threat) {
    risk_reasons.push("Fear or threat language detected");
  }

  // ----------------------------------------------------------
  // 3. CREDENTIAL REQUEST
  // ----------------------------------------------------------

  const credentialPatterns = [
    /\benter your credentials\b/,
    /\bprovide your credentials\b/,
    /\bsubmit your credentials\b/,
    /\bshare your credentials\b/,
    /\bcredential(s)? required\b/,
    /\busername and password\b/,
    /\blogin details\b/,
    /\bsign[- ]in details\b/,
    /\baccount credentials\b/
  ];

  signals.credential_request = credentialPatterns.some((pattern) =>
    pattern.test(text)
  );

  if (signals.credential_request) {
    risk_reasons.push("Credentials requested");
  }

  // ----------------------------------------------------------
  // 4. PASSWORD / OTP REQUEST
  // ----------------------------------------------------------

  const passwordOtpPatterns = [
    /\benter your password\b/,
    /\bprovide your password\b/,
    /\bshare your password\b/,
    /\bpassword\b/,
    /\bpasscode\b/,
    /\botp\b/,
    /\bone[- ]time password\b/,
    /\bsecurity code\b/,
    /\bverification code\b/,
    /\bpin\b/
  ];

  signals.password_or_otp_request = passwordOtpPatterns.some(
    (pattern) => pattern.test(text)
  );

  if (signals.password_or_otp_request) {
    risk_reasons.push(
      "Password or OTP/security code requested"
    );
  }

  // ----------------------------------------------------------
  // 5. FINANCIAL REQUEST
  // ----------------------------------------------------------

  const financialPatterns = [
    /\bpayment\b/,
    /\bpay now\b/,
    /\bmake a payment\b/,
    /\bbank account\b/,
    /\bbank transfer\b/,
    /\bwire transfer\b/,
    /\btransfer money\b/,
    /\binvoice\b/,
    /\btransaction\b/,
    /\brefund\b/,
    /\bfee\b/,
    /\bcrypto\b/,
    /\bwallet\b/,
    /\bsend money\b/
  ];

  signals.financial_request = financialPatterns.some((pattern) =>
    pattern.test(text)
  );

  if (signals.financial_request) {
    risk_reasons.push(
      "Financial or payment-related request detected"
    );
  }

  // ----------------------------------------------------------
  // 6. ACCOUNT VERIFICATION
  // ----------------------------------------------------------

  const verificationPatterns = [
    /\bverify your account\b/,
    /\bverify account\b/,
    /\baccount verification\b/,
    /\bconfirm your account\b/,
    /\bconfirm account\b/,
    /\bverify your identity\b/,
    /\bconfirm your identity\b/,
    /\bsecurity verification\b/,
    /\bverification required\b/,
    /\bverify your information\b/,
    /\bconfirm your information\b/
  ];

  signals.account_verification = verificationPatterns.some(
    (pattern) => pattern.test(text)
  );

  if (signals.account_verification) {
    risk_reasons.push("Account verification requested");
  }

  // ----------------------------------------------------------
  // 7. ACCOUNT TAKEOVER
  // ----------------------------------------------------------

  const takeoverPatterns = [
    /\breset your password\b/,
    /\bchange your password\b/,
    /\bsecure your account\b/,
    /\brecover your account\b/,
    /\brestore access\b/,
    /\bunlock your account\b/,
    /\baccount takeover\b/,
    /\bunauthorized login\b/,
    /\bsuspicious login\b/,
    /\bnew login detected\b/,
    /\baccount compromised\b/,
    /\bprotect your account\b/
  ];

  signals.account_takeover = takeoverPatterns.some((pattern) =>
    pattern.test(text)
  );

  if (signals.account_takeover) {
    risk_reasons.push(
      "Account takeover indicators detected"
    );
  }

  // ----------------------------------------------------------
  // 8. SUSPICIOUS CTA
  // ----------------------------------------------------------

  const ctaPatterns = [
    // Direct action requests
    /\bclick here\b/,
    /\bclick (the )?(link|button)\b/,
    /\bclick below\b/,
    /\bverify now\b/,
    /\bconfirm now\b/,
    /\bactivate now\b/,
    /\bupdate now\b/,
    /\breset now\b/,
    /\bopen the link\b/,
    /\bdownload now\b/,
    /\bcomplete verification\b/,
    /\btake action\b/,
    /\bclick to verify\b/,
    /\bclick to confirm\b/,

    // External communication / social-platform CTAs
    /\bjoin (our|the) telegram\b/,
    /\btelegram group\b/,
    /\bdedicated telegram group\b/,
    /\bjoin (our|the) (whatsapp|discord|signal) group\b/,
    /\bcontact us\b/,
    /\bconnect with us\b/,
    /\bvisit our website\b/,
    /\bvisit (our|the) website\b/,
    /\bfollow us\b/,

    // Action-oriented business communication
    /\bfor more seamless communication\b/,
    /\bdiscuss the details\b/,
    /\bdiscuss further\b/,
    /\bexplore (this|the) opportunity\b/,
    /\bmove forward\b/
  ];

  signals.suspicious_cta = ctaPatterns.some((pattern) =>
    pattern.test(text)
  );

  if (signals.suspicious_cta) {
    risk_reasons.push("Suspicious call-to-action detected");
  }

  // ----------------------------------------------------------
  // CONTEXTUAL SOCIAL ENGINEERING INDICATORS
  // ----------------------------------------------------------

  const businessOpportunityPatterns = [
    /\bstrategic partnership\b/,
    /\bpartnership opportunity\b/,
    /\bcollaboration opportunity\b/,
    /\bupcoming listings\b/,
    /\bliquidity solutions\b/,
    /\bexplore (this|the) opportunity\b/,
    /\bmove forward\b/
  ];

  const externalCommunicationPatterns = [
    /\btelegram\b/,
    /\bwhatsapp\b/,
    /\bdiscord\b/,
    /\bsignal\b/,
    /\bjoin (our|the) .*group\b/,
    /\bdedicated .*group\b/
  ];

  const hasBusinessOpportunity = businessOpportunityPatterns.some(
    (pattern) => pattern.test(text)
  );

  const hasExternalCommunication =
    externalCommunicationPatterns.some(
      (pattern) => pattern.test(text)
    );

  // ----------------------------------------------------------
  // SOCIAL ENGINEERING RISK SCORE
  // ----------------------------------------------------------

  const weights = {
    urgency: 10,
    fear_or_threat: 15,
    credential_request: 15,
    password_or_otp_request: 15,
    financial_request: 15,
    account_verification: 10,
    account_takeover: 10,
    suspicious_cta: 20
  };

  let risk_score = 0;

  // Base score from required signals
  for (const [signal, weight] of Object.entries(weights)) {
    if (signals[signal]) {
      risk_score += weight;
    }
  }

  // ----------------------------------------------------------
  // CONTEXT-AWARE SCORING
  // ----------------------------------------------------------
  // Business persuasion + suspicious CTA
  // increases social-engineering risk.
  // ----------------------------------------------------------

  if (signals.suspicious_cta && hasBusinessOpportunity) {
    risk_score += 15;
    risk_reasons.push(
      "Business opportunity persuasion detected"
    );
  }

  // External communication channel + suspicious CTA
  // indicates an attempt to move communication elsewhere.
  if (signals.suspicious_cta && hasExternalCommunication) {
    risk_score += 15;
    risk_reasons.push(
      "External communication channel encouraged"
    );
  }

  // ----------------------------------------------------------
  // KEEP SCORE BETWEEN 0 AND 100
  // ----------------------------------------------------------

  risk_score = Math.min(100, Math.max(0, risk_score));

  // ----------------------------------------------------------
  // RISK LEVEL
  // ----------------------------------------------------------

  let risk_level = "LOW";

  if (risk_score >= 70) {
    risk_level = "CRITICAL";
  } else if (risk_score >= 50) {
    risk_level = "HIGH";
  } else if (risk_score >= 30) {
    risk_level = "MEDIUM";
  }

  // ----------------------------------------------------------
  // FINAL #8 OUTPUT
  // ----------------------------------------------------------

  return {
    signals,
    risk_score,
    risk_level,
    risk_reasons
  };
}

// ============================================================
// EXPORT
// ============================================================

module.exports = {
  analyzeSocialEngineering
};