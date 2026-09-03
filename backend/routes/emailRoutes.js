const express = require("express");
const multer = require("multer");
const path = require("path");

const {
    analyzeEmail
} = require("../controllers/emailController");



const router = express.Router();

// Store uploaded files temporarily
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
// router.post(
//     // "/analyze",
//     // upload.single("email"),
//     // analyzeEmail

//     "/analyze",
//     (req, res, next) => {
//         console.log("📨 /analyze route hit");
//         next();
//     },
//     upload.single("email"),
//     (req, res, next) => {
//         console.log("📦 Multer completed:", req.file?.originalname);
//         next();
//     },
//     analyzeEmail
// );

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

module.exports = router;