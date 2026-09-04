const path = require("path");
const mongoose = require("mongoose");

const { parseEmailWithPython } = require("../services/emailParserService");
const { runHeaderForensics } = require("../services/headerForensicsService");
const { runMLPrediction } = require("../services/mlService");
const { analyzeUrls } = require("../services/urlIntelligenceService");
const { analyzeNetworkAndDomains } = require("../services/intelligenceService");

const Email = require("../models/email");

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
      const emailText = [
        parsedEmail.headers?.subject || "",
        parsedEmail.body?.plainText || ""
      ].join(" ");

      mlResult = await runMLPrediction(emailText);
      console.log("🤖 ML prediction completed");
    } catch (mlErr) {
      console.warn(
        "⚠️ ML prediction failed or skipped:",
        mlErr.message
      );
    }

    // 3. Header Forensics
    const headerForensics =
      await runHeaderForensics(req.file.path);

    console.log("✅ Header Forensics completed");
    console.log(
      "Header Risk Score:",
      headerForensics.header_risk_score
    );

    // 4. URL Intelligence
    const rawLinks = (parsedEmail.links || [])
      .map((link) =>
        typeof link === "string" ? link : link.url
      )
      .filter(Boolean);

    const senderEmail =
      parsedEmail.headers?.from || "";

    console.log(
      "🔎 URLs found:",
      rawLinks.length
    );

    const urlIntelligence =
      await analyzeUrls(
        rawLinks,
        senderEmail
      );

    console.log(
      "✅ URL Intelligence completed"
    );

    console.log(
      "URL Risk Summary:",
      urlIntelligence.summary
    );

    // 5. IP + Domain Intelligence
    const intelligenceData =
      await analyzeNetworkAndDomains(
        parsedEmail,
        headerForensics
      );

    console.log(
      "✅ IP & Domain Intelligence completed"
    );

    // 6. Merge all findings
    parsedEmail.mlAnalysis = mlResult;

    parsedEmail.headerForensics =
      headerForensics;

    parsedEmail.urlIntelligence =
      urlIntelligence;

    parsedEmail.domainIntelligence =
      intelligenceData.domainIntelligence;

    parsedEmail.ipIntelligence =
      intelligenceData.ipIntelligence;

    parsedEmail.intelligenceSignals =
      intelligenceData.intelligenceSignals;

    // 7. Save full record to MongoDB
    console.log("💾 About to save to MongoDB");
    console.log(
      "Database:",
      mongoose.connection.name
    );

    console.log(
      "Collection:",
      Email.collection.name
    );

    const savedEmail =
      await Email.create(parsedEmail);

    console.log(
      "✅ SAVED:",
      savedEmail._id
    );

    console.log(
      "✅ Full forensic document saved to MongoDB:",
      savedEmail._id.toString()
    );

    // 8. Response
    return res.status(200).json({
      success: true,
      message:
        "Email parsed, analyzed, and stored successfully",

      emailId:
        savedEmail._id.toString(),

      summary: {
        mlPrediction:
          mlResult?.prediction || null,

        mlConfidence:
          mlResult?.confidence || null,

        headerRiskScore:
          headerForensics.header_risk_score,

        urlRiskStatus:
          urlIntelligence.summary?.overall_status || null,

        urlMaxScore:
          urlIntelligence.summary?.max_risk_score || 0,

        isLookalikeDomain:
          intelligenceData
            .domainIntelligence
            ?.lookalike_analysis
            ?.is_lookalike || false,

        hasPublicOriginIp:
          intelligenceData
            .ipIntelligence
            ?.routing_summary
            ?.has_public_origin || false
      }
    });

  } catch (error) {
    console.error(
      "❌ Email analysis pipeline failed:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Failed to analyze and save email",
      error: error.message
    });
  }
}

/**
 * Retrieve all emails for summary dashboard views.
 */
async function getAllEmails(req, res) {
  try {
    const emails = await Email.find()
      .select(
        "headers.subject headers.from headers.date threatAnalysis urlIntelligence headerForensics mlAnalysis createdAt"
      )
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
    const email =
      await Email.findById(req.params.id);

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