const express = require("express");
const multer = require("multer");
const path = require("path");

const {
    analyzeEmail,
    getAllEmails,
    getEmailById
} = require("../controllers/emailController");

const router = express.Router();

// Store uploaded files temporarily in email_parser/emails
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, "../../email_parser/emails"));
    },

    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (path.extname(file.originalname).toLowerCase() !== ".eml") {
            return cb(new Error("Only .eml files are allowed"));
        }
        cb(null, true);
    }
});

// POST /api/emails/analyze
router.post(
    "/analyze",

    (req, res, next) => {
        console.log("\n==============================");
        console.log("📨 ANALYZE REQUEST RECEIVED");
        console.log("➡️ Method:", req.method);
        console.log("➡️ URL:", req.originalUrl);
        console.log("==============================\n");
        next();
    },

    upload.single("email"),

    (req, res, next) => {
        console.log("\n📦 MULTER COMPLETED");

        if (req.file) {
            console.log("✅ File received");
            console.log("📄 Name:", req.file.originalname);
            console.log("📏 Size:", req.file.size);
            console.log("📍 Path:", req.file.path);
        } else {
            console.log("❌ NO FILE RECEIVED");
        }

        console.log("==============================\n");

        next();
    },

    analyzeEmail
);

// GET /api/emails - Fetch list of analyzed emails for dashboards
router.get("/", getAllEmails);

// GET /api/emails/:id - Fetch full forensics (URL, Header, IP, Domain) for case details
router.get("/:id", getEmailById);

module.exports = router;