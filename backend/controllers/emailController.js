const path = require("path");
const { parseEmailWithPython } = require("../services/emailParserService");
const Email = require("../models/email");

async function analyzeEmail(req, res) {
    console.log("🚀 analyzeEmail controller hit");
    try {
        // Check uploaded file
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: "Please upload an .eml file"
            });
        }

        // Check extension
        if (
            path.extname(req.file.originalname).toLowerCase() !== ".eml"
        ) {
            return res.status(400).json({
                success: false,
                message: "Only .eml files are allowed"
            });
        }

        // -----------------------------
        // STEP 1: PYTHON PARSER
        // -----------------------------
        const parsedEmail = await parseEmailWithPython(
            req.file.path
        );

        console.log("Python parser completed");

        // -----------------------------
        // STEP 2: SAVE TO MONGODB
        // -----------------------------
        const savedEmail = await Email.create(parsedEmail);

        console.log(
            "Email saved to MongoDB:",
            savedEmail._id.toString()
        );

        // -----------------------------
        // STEP 3: RESPONSE
        // -----------------------------
        return res.status(200).json({
            success: true,
            message: "Email parsed and saved successfully",
            // data: savedEmail
            emailId: savedEmail._id.toString()
        });

    } catch (error) {

        console.error(
            "Email analysis failed:",
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