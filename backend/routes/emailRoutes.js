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
router.post(
    "/analyze",
    upload.single("email"),
    analyzeEmail
);

module.exports = router;