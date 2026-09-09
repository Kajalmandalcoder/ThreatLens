const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const {
    analyzeEmail,
    getAllEmails,
    getEmailById,
    getCampaignCorrelations
} = require("../controllers/emailController");

const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();


// ============================================================
// UPLOAD DIRECTORY
// ============================================================

const uploadDir = path.resolve(
    __dirname,
    "../../email_parser/emails"
);

console.log("📁 EML upload directory:", uploadDir);

// Make sure directory exists
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, {
        recursive: true
    });

    console.log("✅ Created upload directory");
}


// ============================================================
// MULTER STORAGE
// ============================================================

const storage = multer.diskStorage({

    destination: (req, file, cb) => {

        console.log("📂 Multer destination:", uploadDir);

        cb(null, uploadDir);
    },

    filename: (req, file, cb) => {

        const safeName =
            `${Date.now()}-email.eml`;

        console.log("📝 Multer filename:", safeName);

        cb(null, safeName);
    }

});


// ============================================================
// MULTER UPLOAD
// ============================================================

const upload = multer({

    storage,

    limits: {
        fileSize: 20 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {

        console.log(
            "📄 Incoming file:",
            file.originalname
        );

        console.log(
            "📌 Incoming mimetype:",
            file.mimetype
        );

        const ext = path
            .extname(file.originalname)
            .toLowerCase();

        if (ext !== ".eml") {

            console.error(
                "❌ Invalid file extension:",
                ext
            );

            return cb(
                new Error(
                    "Only .eml files are allowed"
                )
            );
        }

        cb(null, true);
    }

});


// ============================================================
// POST /api/emails/analyze
// ============================================================

router.post(
    "/analyze",

    // --------------------------------------------------------
    // ROUTE LOGGER
    // --------------------------------------------------------

    (req, res, next) => {

        console.log("\n========================================");
        console.log("📨 ANALYZE ROUTE HIT");
        console.log("➡️ Method:", req.method);
        console.log("➡️ URL:", req.originalUrl);
        console.log(
            "➡️ Content-Type:",
            req.headers["content-type"]
        );
        console.log("========================================\n");

        next();
    },


    // --------------------------------------------------------
    // AUTH
    // --------------------------------------------------------

    authMiddleware,


    // --------------------------------------------------------
    // MULTER
    // --------------------------------------------------------

    (req, res, next) => {

        console.log("🔐 Authentication passed");
        console.log("📤 Starting multer upload...");

        upload.single("email")(
            req,
            res,
            (err) => {

                if (err) {

                    console.error(
                        "\n❌ MULTER ERROR"
                    );

                    console.error(
                        "Message:",
                        err.message
                    );

                    console.error(
                        "Full error:",
                        err
                    );

                    console.error(
                        "================================\n"
                    );

                    return res.status(400).json({
                        success: false,
                        error: err.message
                    });
                }

                next();
            }
        );
    },


    // --------------------------------------------------------
    // FILE CHECK
    // --------------------------------------------------------

    (req, res, next) => {

        console.log("\n📦 MULTER COMPLETED");

        if (!req.file) {

            console.error(
                "❌ NO FILE RECEIVED"
            );

            console.error(
                "➡️ req.body:",
                req.body
            );

            console.error(
                "➡️ Expected field name: email"
            );

            console.log(
                "================================\n"
            );

            return res.status(400).json({
                success: false,
                error:
                    "No .eml file received. " +
                    "Make sure FormData field name is 'email'."
            });
        }


        console.log(
            "✅ FILE RECEIVED"
        );

        console.log(
            "📄 Original name:",
            req.file.originalname
        );

        console.log(
            "📄 Saved filename:",
            req.file.filename
        );

        console.log(
            "📏 Size:",
            req.file.size,
            "bytes"
        );

        console.log(
            "📍 Saved path:",
            req.file.path
        );

        console.log(
            "📦 MIME:",
            req.file.mimetype
        );

        console.log(
            "✅ File exists:",
            fs.existsSync(req.file.path)
        );

        console.log(
            "================================\n"
        );

        next();
    },


    // --------------------------------------------------------
    // CONTROLLER
    // --------------------------------------------------------

    analyzeEmail
);


// ============================================================
// GET ALL EMAILS
// GET /api/emails
// ============================================================

router.get(
    "/",
    authMiddleware,
    getAllEmails
);


// ============================================================
// GET CAMPAIGN CORRELATIONS
// GET /api/emails/case/:caseId/correlations
// ============================================================

router.get(
    "/case/:caseId/correlations",
    authMiddleware,
    getCampaignCorrelations
);


// ============================================================
// GET EMAIL BY ID
// GET /api/emails/:id
// ============================================================

router.get(
    "/:id",
    authMiddleware,
    getEmailById
);


// ============================================================
// EXPORT
// ============================================================

module.exports = router;