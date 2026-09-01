const express = require("express");

const {
    signup,
    verifyOTP,
    login
} = require("../controllers/authController");

const router = express.Router();


// =========================
// SIGNUP
// =========================

router.post("/signup", signup);
router.post("/login", login);


// =========================
// VERIFY OTP
// =========================

router.post("/verify-otp", verifyOTP);


module.exports = router;