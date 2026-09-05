const path = require("path");

const { parseEmailWithPython } = require("../services/emailParserService");
const { runHeaderForensics } = require("../services/headerForensicsService");
const { runMLPrediction } = require("../services/mlService");

const Email = require("../models/email");


async function analyzeEmail(req, res) {

    console.log("🚀 analyzeEmail controller hit");

    try {

        // =========================================
        // CHECK UPLOADED FILE
        // =========================================

        if (!req.file) {

            return res.status(400).json({
                success: false,
                message: "Please upload an .eml file"
            });

        }


        // =========================================
        // CHECK FILE EXTENSION
        // =========================================

        if (
            path.extname(req.file.originalname).toLowerCase() !== ".eml"
        ) {

            return res.status(400).json({
                success: false,
                message: "Only .eml files are allowed"
            });

        }


        // =========================================
        // STEP 1: PYTHON EMAIL PARSER
        // =========================================

        const parsedEmail = await parseEmailWithPython(
            req.file.path
        );

        console.log("✅ Python parser completed");

        // =========================================
// STEP 2: ML THREAT PREDICTION
// =========================================

const emailText = [
    parsedEmail.headers?.subject || "",
    parsedEmail.body?.plainText || ""
].join(" ");

const mlResult = await runMLPrediction(emailText);

console.log("🤖 ML prediction completed");
console.log("Prediction:", mlResult.prediction);
console.log("Confidence:", mlResult.confidence);

// Add ML result to parsed email
parsedEmail.mlAnalysis = mlResult;

        // =========================================
        // STEP 2: HEADER FORENSICS
        // =========================================

        const headerForensics = await runHeaderForensics(
            req.file.path
        );

        console.log("✅ Header Forensics completed");

        console.log(
            "Header Risk Score:",
            headerForensics.header_risk_score
        );


        // =========================================
        // STEP 3: ADD HEADER FORENSICS TO EMAIL
        // =========================================

        parsedEmail.headerForensics = headerForensics;


        // =========================================
        // STEP 4: SAVE EVERYTHING TO MONGODB
        // =========================================

        const savedEmail = await Email.create({
    ...parsedEmail,
    mlAnalysis: {
        success: mlResult.success,
        prediction: mlResult.prediction,
        confidence: mlResult.confidence,
        raw_label: mlResult.raw_label
    }
});
        console.log(
            "✅ Email saved to MongoDB:",
            savedEmail._id.toString()
        );


        // =========================================
        // STEP 5: RESPONSE
        // =========================================

        return res.status(200).json({

            success: true,

            message: "Email parsed, analyzed and saved successfully",

            emailId: savedEmail._id.toString(),

            headerRiskScore:
                headerForensics.header_risk_score

        });

    }

    catch (error) {

        console.error(
            "❌ Email analysis failed:",
            error
        );

        return res.status(500).json({

            success: false,

            message: "Failed to analyze and save email",

            error: error.message

        });

    }
}


module.exports = {
    analyzeEmail
};