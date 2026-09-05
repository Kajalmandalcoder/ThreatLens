const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const User = require("../models/User");
const { sendOTPEmail, sendPasswordResetOTPEmail } = require("../services/emailService");

const investigatorEmails = [
    "aryajiya396@gmail.com",
    "deepika032btit24@igdtuw.ac.in"
];

// =========================
// GENERATE OTP
// =========================

function generateOTP() {
    return crypto.randomInt(100000, 1000000).toString();
}


// =========================
// SIGNUP
// =========================

const signup = async (req, res) => {

    try {

        const { name, email, password } = req.body;

        // Check fields
        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required."
            });
        }

        // Password validation
        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must be at least 6 characters."
            });
        }

        const normalizedEmail = email.toLowerCase().trim();
        const role = investigatorEmails.includes(normalizedEmail)? "investigator": "user";

        // Check existing user
        let user = await User.findOne({
            email: normalizedEmail
        });

        // Already verified
        if (user && user.isVerified) {
            return res.status(400).json({
                message: "An account with this email already exists."
            });
        }

        // Generate OTP
        const otp = generateOTP();

        // Hash OTP
        const otpHash = await bcrypt.hash(otp, 10);

        // OTP valid for 5 minutes
        const otpExpires = new Date(
            Date.now() + 5 * 60 * 1000
        );

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);


        // =========================
        // CREATE / UPDATE USER
        // =========================

        if (user) {

            user.name = name;
            user.password = hashedPassword;
            user.role = role;
            user.otpHash = otpHash;
            user.otpExpires = otpExpires;

        } else {

            user = new User({
                name,
                email: normalizedEmail,
                password: hashedPassword,
                role: role,
                isVerified: false,
                otpHash,
                otpExpires
            });

        }

        await user.save();


        // =========================
        // SEND OTP EMAIL
        // =========================

        console.log("OTP:", otp);
        console.log("Sending OTP to:", normalizedEmail);

        await sendOTPEmail(normalizedEmail, otp);

        res.status(200).json({
            message: "OTP sent successfully."
        });


    } catch (error) {

        console.error("Signup error:", error);

        res.status(500).json({
            message: "Something went wrong while signing up."
        });

    }
};


// =========================
// VERIFY OTP
// =========================

const verifyOTP = async (req, res) => {

    try {

        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                message: "Email and OTP are required."
            });
        }

        const normalizedEmail = email.toLowerCase().trim();

        const user = await User.findOne({
            email: normalizedEmail
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found."
            });
        }


        // No OTP
        if (!user.otpHash || !user.otpExpires) {
            return res.status(400).json({
                message: "No OTP request found."
            });
        }


        // OTP expired
        if (user.otpExpires < new Date()) {

            return res.status(400).json({
                message: "OTP has expired. Please request a new one."
            });

        }


        // Compare OTP
        const isValidOTP = await bcrypt.compare(
            otp,
            user.otpHash
        );


        if (!isValidOTP) {

            return res.status(400).json({
                message: "Invalid OTP."
            });

        }


        // =========================
        // VERIFY USER
        // =========================

        user.isVerified = true;
        user.otpHash = null;
        user.otpExpires = null;

        await user.save();


        // =========================
        // GENERATE JWT
        // =========================

        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1d"
            }
        );


        res.status(200).json({
            message: "Email verified successfully.",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });


    } catch (error) {

        console.error("OTP verification error:", error);

        res.status(500).json({
            message: "Something went wrong while verifying OTP."
        });

    }
};

// =========================
// FORGOT PASSWORD
// =========================

const forgotPassword = async (req, res) => {

    try {

        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                message: "Email is required."
            });
        }

        const normalizedEmail = email.toLowerCase().trim();

        const user = await User.findOne({
            email: normalizedEmail
        });

        if (!user) {
            return res.status(404).json({
                message: "No account found with this email."
            });
        }

        if (!user.isVerified) {
            return res.status(403).json({
                message: "Please verify your email first."
            });
        }

        // Generate OTP
        const otp = generateOTP();

        // Hash OTP
        const otpHash = await bcrypt.hash(otp, 10);

        // OTP valid for 5 minutes
        const otpExpires = new Date(
            Date.now() + 5 * 60 * 1000
        );

        user.resetOtpHash = otpHash;
        user.resetOtpExpires = otpExpires;
        user.resetOtpVerified = false;

        await user.save();

        console.log("Password reset OTP:", otp);
        console.log("Sending reset OTP to:", normalizedEmail);

        await sendPasswordResetOTPEmail(normalizedEmail, otp);

        res.status(200).json({
            message: "OTP sent successfully."
        });

    } catch (error) {

        console.error("Forgot password error:", error);

        res.status(500).json({
            message: "Something went wrong while sending OTP."
        });
    }
};


// =========================
// VERIFY RESET OTP
// =========================

const verifyResetOTP = async (req, res) => {

    try {

        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                message: "Email and OTP are required."
            });
        }

        const normalizedEmail = email.toLowerCase().trim();

        const user = await User.findOne({
            email: normalizedEmail
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found."
            });
        }

        if (!user.resetOtpHash || !user.resetOtpExpires) {
            return res.status(400).json({
                message: "No password reset request found."
            });
        }

        // Check expiry
        if (user.resetOtpExpires < new Date()) {

            user.resetOtpHash = null;
            user.resetOtpExpires = null;
            user.resetOtpVerified = false;

            await user.save();

            return res.status(400).json({
                message: "OTP has expired. Please request a new one."
            });
        }

        // Compare OTP
        const isValidOTP = await bcrypt.compare(
            otp,
            user.resetOtpHash
        );

        if (!isValidOTP) {
            return res.status(400).json({
                message: "Invalid OTP."
            });
        }

        user.resetOtpVerified = true;

        await user.save();

        res.status(200).json({
            message: "OTP verified successfully."
        });

    } catch (error) {

        console.error("Reset OTP verification error:", error);

        res.status(500).json({
            message: "Something went wrong while verifying OTP."
        });
    }
};


// =========================
// RESET PASSWORD
// =========================

const resetPassword = async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and new password are required."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must be at least 6 characters."
            });
        }

        const normalizedEmail = email.toLowerCase().trim();

        const user = await User.findOne({
            email: normalizedEmail
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found."
            });
        }

        // OTP must be verified first
        if (!user.resetOtpVerified) {
            return res.status(403).json({
                message: "Please verify OTP first."
            });
        }

        // Make sure OTP has not expired
        if (
            !user.resetOtpExpires ||
            user.resetOtpExpires < new Date()
        ) {

            user.resetOtpHash = null;
            user.resetOtpExpires = null;
            user.resetOtpVerified = false;

            await user.save();

            return res.status(400).json({
                message: "OTP has expired. Please request a new one."
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(
            password,
            10
        );

        user.password = hashedPassword;

        // Clear reset OTP data
        user.resetOtpHash = null;
        user.resetOtpExpires = null;
        user.resetOtpVerified = false;

        await user.save();

        res.status(200).json({
            message: "Password reset successfully."
        });

    } catch (error) {

        console.error("Reset password error:", error);

        res.status(500).json({
            message: "Something went wrong while resetting password."
        });
    }
};

// =========================
// LOGIN
// =========================

const login = async (req, res) => {

    try {

        const { email, password } = req.body;

        // Check fields
        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required."
            });
        }

        const normalizedEmail = email.toLowerCase().trim();

        // Find user in MongoDB
        const user = await User.findOne({
            email: normalizedEmail
        });

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Check email verification
        if (!user.isVerified) {
            return res.status(403).json({
                message: "Please verify your email before logging in."
            });
        }

        // Compare password
        const isPasswordValid = await bcrypt.compare(
            password,
            user.password
        );

        if (!isPasswordValid) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Generate JWT
        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1d"
            }
        );

        res.status(200).json({
            message: "Login successful.",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {

        console.error("Login error:", error);

        res.status(500).json({
            message: "Something went wrong while logging in."
        });

    }
};


module.exports = {
    signup,
    login,
    verifyOTP,
    forgotPassword,
    verifyResetOTP,
    resetPassword
};