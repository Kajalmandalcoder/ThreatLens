const path = require("path");
const { parseEmailWithPython } = require("../services/emailParserService");

async function analyzeEmail(req, res) {
    try {
        // Check if file was uploaded
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: "Please upload an .eml file"
            });
        }

        // Make sure it is an EML file
        if (path.extname(req.file.originalname).toLowerCase() !== ".eml") {
            return res.status(400).json({
                success: false,
                message: "Only .eml files are allowed"
            });
        }

        // Send file to Python parser
        const parsedEmail = await parseEmailWithPython(
            req.file.path
        );

        // Return parsed email
        res.status(200).json({
            success: true,
            message: "Email parsed successfully",
            data: parsedEmail
        });

    } catch (error) {

        console.error("Email analysis failed:", error);

        res.status(500).json({
            success: false,
            message: "Failed to analyze email",
            error: error.message
        });
    }
}

module.exports = {
    analyzeEmail
};