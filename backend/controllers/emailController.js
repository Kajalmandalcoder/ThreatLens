const path = require("path");
const mongoose = require("mongoose");

const { parseEmailWithPython } = require("../services/emailParserService");
const { runHeaderForensics } = require("../services/headerForensicsService");
const { runMLPrediction } = require("../services/mlService");
const { analyzeUrls } = require("../services/urlIntelligenceService");
const { analyzeNetworkAndDomains } = require("../services/intelligenceService");
const { analyzeAttachments } = require("../services/attachmentIntelligenceService");

const Email = require("../models/email");

function buildTechnicalReasons({
  mlResult,
  headerForensics,
  urlIntelligence,
  ipIntelligence,
  domainIntelligence,
  attachmentIntelligence
}) {
  const reasons = [];
  const actions = [];

  if (mlResult?.prediction !== "THREAT") {
  return {
    technicalReasons: [],
    recommendedActions: []
  };
}

  const add = (type, reason, action) => {
  const formattedReason = `${type}: ${reason}`;

  if (!reasons.includes(formattedReason)) {
    reasons.push(formattedReason);
  }

  if (action && !actions.includes(action)) {
    actions.push(action);
  }
};

  // =========================
  // HEADER FORENSICS
  // =========================

  const identity = headerForensics?.identity_analysis || {};
  const auth = headerForensics?.authentication_matrix || {};

  if (identity.is_spoofed === true) {
    add(
      "SPOOFING",
      "Sender identity appears to be spoofed.",
      "Verify the sender through an independent trusted channel."
    );
  }

  if (
    identity.anomalies?.some(
      (a) => a.type === "RETURN_PATH_MISMATCH"
    )
  ) {
    add(
      "RETURN_PATH_MISMATCH",
      "Return-Path domain does not align with the sender domain.",
      "Verify the sender and email origin before trusting the message."
    );
  }

  if (String(auth.dmarc || "").toUpperCase() === "FAIL") {
    add(
      "DMARC_FAILURE",
      "DMARC authentication failed for the sender domain.",
      "Treat sender identity with caution and verify the message independently."
    );
  }

  if (String(auth.spf || "").toUpperCase() === "FAIL") {
    add(
      "SPF_FAILURE",
      "SPF authentication failed.",
      "Verify the sender before taking action."
    );
  }

  if (String(auth.dkim || "").toUpperCase() === "FAIL") {
    add(
      "DKIM_FAILURE",
      "DKIM authentication failed.",
      "Verify the message source before trusting it."
    );
  }

  // =========================
  // URL INTELLIGENCE
  // =========================

  const suspiciousUrls =
    urlIntelligence?.urls?.filter(
      (u) =>
        Number(u.risk_score || 0) >= 30 ||
        (u.indicators || []).some(
          (indicator) =>
            /suspicious|malicious|obfuscat|shortener|ip address|punycode/i.test(
              indicator
            )
        )
    ) || [];

  if (suspiciousUrls.length > 0) {
    const indicators = [
      ...new Set(
        suspiciousUrls.flatMap((u) => u.indicators || [])
      )
    ];

    add(
      "SUSPICIOUS_URL",
      `URL intelligence detected elevated-risk URL indicators: ${indicators.join(
        "; "
      )}`,
      "Do not click elevated-risk links until their destination is independently verified."
    );
  }

  // IMPORTANT:
  // Mere presence of URLs is NOT a reason.

  // =========================
  // IP INTELLIGENCE
  // =========================

  const ipSignals = ipIntelligence?.signals || {};
  const originData = ipIntelligence?.origin_ip_data || {};

  if (ipSignals.ip_origin_is_vpn_proxy === true) {
    add(
      "VPN_PROXY_ORIGIN",
      "The apparent origin IP is associated with VPN/proxy infrastructure.",
      "Verify the sender through an independent trusted channel."
    );
  }

  if (ipSignals.ip_origin_is_hosting === true) {
    add(
      "HOSTING_ORIGIN",
      "The apparent origin IP belongs to hosting infrastructure.",
      "Treat the sender origin with caution and verify independently."
    );
  }

  // =========================
  // DOMAIN INTELLIGENCE
  // =========================

  const domainSignals = domainIntelligence?.signals || {};
  const lookalike = domainIntelligence?.lookalike_analysis || {};

  if (lookalike.is_lookalike === true) {
    add(
      "LOOKALIKE_DOMAIN",
      `A lookalike domain was detected${
        lookalike.matched_brand
          ? ` resembling ${lookalike.matched_brand}`
          : ""
      }.`,
      "Do not trust links or sender identity until the domain is verified."
    );
  }

  if (domainSignals.reply_to_mismatch === true) {
    add(
      "REPLY_TO_MISMATCH",
      "Reply-To domain does not align with the sender identity.",
      "Verify the intended recipient and sender before replying."
    );
  }

  if (domainSignals.from_missing_mx === true) {
    add(
      "SENDER_DOMAIN_MX_MISSING",
      "The sender domain does not have a valid MX record.",
      "Verify the sender domain independently."
    );
  }

  // =========================
  // ATTACHMENT INTELLIGENCE
  // =========================

  const attachmentSummary =
    attachmentIntelligence?.summary || {};

  if (attachmentSummary.has_executable_types === true) {
    add(
      "EXECUTABLE_ATTACHMENT",
      "The email contains an attachment with an executable file type.",
      "Do not open or execute the attachment."
    );
  }

  if (attachmentSummary.has_macros_or_scripts === true) {
    add(
      "MACRO_OR_SCRIPT_ATTACHMENT",
      "The email contains an attachment capable of running macros or scripts.",
      "Do not open the attachment unless its source is independently verified."
    );
  }

  if (attachmentSummary.has_high_risk_files === true) {
    add(
      "HIGH_RISK_ATTACHMENT",
      "Attachment intelligence classified one or more files as high risk.",
      "Do not open the attachment until it has been verified."
    );
  }

  // IMPORTANT:
  // Mere presence of an attachment is NOT a reason.

  // =========================
  // ML RESULT
  // =========================

  // Only use ML's own reasons when it classified the email as THREAT.
  // Do not manufacture suspicious reasons for SAFE emails.
  if (mlResult?.prediction === "THREAT") {
    for (const reason of mlResult.technicalReasons || []) {
      if (reason === "CREDENTIAL_REQUEST") {
        add(
          "CREDENTIAL_REQUEST",
          "The message contains indicators of a request for credentials or security codes.",
          "Do not share passwords, OTPs, or security codes."
        );
      }

      if (reason === "URGENCY") {
        add(
          "URGENCY",
          "The message uses urgency or account-pressure language.",
          "Verify the request independently before taking action."
        );
      }

      if (reason === "FINANCIAL_REQUEST") {
        add(
          "FINANCIAL_REQUEST",
          "The message contains indicators of a financial or payment request.",
          "Independently verify payment or money-transfer requests."
        );
      }
    }
  }

  return {
    technicalReasons: reasons,
    recommendedActions: actions
  };
}
/**
 * Ingest, parse, forensic-analyze, and store an incoming EML file.
 */
async function analyzeEmail(req, res) {
  console.log("🚀 analyzeEmail controller hit");

  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Please upload an .eml file"
      });
    }

    if (path.extname(req.file.originalname).toLowerCase() !== ".eml") {
      return res.status(400).json({
        success: false,
        message: "Only .eml files are allowed"
      });
    }

    // 1. Python Email Parser
    const parsedEmail = await parseEmailWithPython(req.file.path);
    console.log("✅ Python parser completed");

    // 2. ML Threat Prediction
    let mlResult = null;
    try {
      const htmlText = (parsedEmail.body?.html || "")
  .replace(/<style[\s\S]*?<\/style>/gi, " ")
  .replace(/<script[\s\S]*?<\/script>/gi, " ")
  .replace(/<[^>]+>/g, " ")
  .replace(/&nbsp;/gi, " ")
  .replace(/\s+/g, " ")
  .trim();

const emailText = [
  parsedEmail.headers?.subject || "",
  parsedEmail.body?.plainText || ""
].join(" ").trim();

      mlResult = await runMLPrediction(emailText);
      console.log("🤖 ML prediction completed");
    } catch (mlErr) {
      console.warn("⚠️ ML prediction failed or skipped:", mlErr.message);
    }

    // 3. Header Forensics
    const headerForensics = await runHeaderForensics(req.file.path);
    console.log("✅ Header Forensics completed");
    console.log("Header Risk Score:", headerForensics.header_risk_score);

    // 4. URL Intelligence
    const rawLinks = (parsedEmail.links || [])
      .map((link) => (typeof link === "string" ? link : link.url))
      .filter(Boolean);
    const senderEmail = parsedEmail.headers?.from || "";

    console.log("🔎 URLs found:", rawLinks.length);
    const urlIntelligence = await analyzeUrls(rawLinks, senderEmail);
    console.log("✅ URL Intelligence completed");
    console.log("URL Risk Summary:", urlIntelligence.summary);

    // 5. IP + Domain Intelligence
    const intelligenceData = await analyzeNetworkAndDomains(parsedEmail, headerForensics);
    console.log("✅ IP & Domain Intelligence completed");

    // 6. Attachment Intelligence
    const rawAttachments = parsedEmail.attachments || [];
    const attachmentIntelligence = await analyzeAttachments(rawAttachments);
    console.log("✅ Attachment Intelligence completed");

    // 7. Merge all findings into the email document
    // 7. Build evidence-based technical reasoning
const explainability = buildTechnicalReasons({
  mlResult,
  headerForensics,
  urlIntelligence,
  ipIntelligence: intelligenceData.ipIntelligence,
  domainIntelligence: intelligenceData.domainIntelligence,
  attachmentIntelligence
});

// Merge all findings into the email document
parsedEmail.mlAnalysis = {
  ...(mlResult || {}),
  technicalReasons: explainability.technicalReasons,
  recommendedActions: explainability.recommendedActions
};
    parsedEmail.headerForensics = headerForensics;
    parsedEmail.urlIntelligence = urlIntelligence;
    parsedEmail.domainIntelligence = intelligenceData.domainIntelligence;
    parsedEmail.ipIntelligence = intelligenceData.ipIntelligence;
    parsedEmail.intelligenceSignals = intelligenceData.intelligenceSignals;

    // Explicit attachment intelligence mapping
    parsedEmail.attachmentIntelligence = {
      summary: attachmentIntelligence.summary,
      attachments: attachmentIntelligence.attachments || []
    };

    // 8. Save full record to MongoDB
    console.log("💾 About to save to MongoDB");
    console.log("Database:", mongoose.connection.name);
    console.log("Collection:", Email.collection.name);

    const caseId =
        `CASE-${new Date().getFullYear()}-${new mongoose.Types.ObjectId()
            .toString()
            .slice(-6)
            .toUpperCase()}`;

    parsedEmail.caseId = caseId;

    const savedEmail = await Email.create(parsedEmail);
    console.log("✅ SAVED:", savedEmail._id);
    console.log("✅ Full forensic document saved to MongoDB:", savedEmail._id.toString());

    // 9. Response
    return res.status(200).json({
      success: true,
      message: "Email parsed, analyzed, and stored successfully",
      emailId: savedEmail._id.toString(),
      summary: {
        mlPrediction: mlResult?.prediction || null,
        mlConfidence: mlResult?.confidence || null,
        headerRiskScore: headerForensics.header_risk_score,
        urlRiskStatus: urlIntelligence.summary?.overall_status || "LOW",
        urlMaxScore: urlIntelligence.summary?.max_risk_score || 0,
        isLookalikeDomain: intelligenceData.domainIntelligence?.lookalike_analysis?.is_lookalike || false,
        hasPublicOriginIp: intelligenceData.ipIntelligence?.routing_summary?.has_public_origin || false,
        attachmentRiskStatus: attachmentIntelligence.summary.overall_status,
        attachmentMaxScore: attachmentIntelligence.summary.max_attachment_risk_score,
        totalAttachments: attachmentIntelligence.summary.total_attachments
      }
    });
  } catch (error) {
    console.error("❌ Email analysis pipeline failed:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to analyze and save email",
      error: error.message
    });
  }
}

/**
 * Retrieve all emails for summary dashboard views.
 */
async function getAllEmails(req, res) {
  try {
    const emails = await Email.find().select("caseId headers.subject headers.from headers.date createdAt")
      // .select("headers.subject headers.from headers.date threatAnalysis urlIntelligence headerForensics mlAnalysis attachmentIntelligence createdAt")
      .sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      count: emails.length,
      data: emails
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Failed to fetch emails",
      error: error.message
    });
  }
}

/**
 * Retrieve a single email with full forensic subdocuments.
 */
async function getEmailById(req, res) {
  try {
    const email = await Email.findById(req.params.id);

    if (!email) {
      return res.status(404).json({
        success: false,
        message: "Email record not found"
      });
    }

    return res.status(200).json({
      success: true,
      data: email
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Failed to fetch email details",
      error: error.message
    });
  }
}

module.exports = {
  analyzeEmail,
  getAllEmails,
  getEmailById
};