const express = require("express");

const {
    signup,
    verifyOTP,
    login,
    forgotPassword,
    verifyResetOTP,
    resetPassword
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

router.post("/forgot-password", forgotPassword);

router.post("/verify-reset-otp", verifyResetOTP);

router.post("/reset-password", resetPassword);


module.exports = router;