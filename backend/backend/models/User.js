const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true
        },

        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true
        },

        password: {
            type: String,
            required: true
        },

        role: {
            type: String,
            enum: ["user", "investigator"],
            default: "user"
        },

        isVerified: {
            type: Boolean,
            default: false
        },

        otpHash: {
            type: String,
            default: null
        },

        otpExpires: {
            type: Date,
            default: null
        },

        resetOtpHash: {
            type: String,
            default: null
        },

        resetOtpExpires: {
            type: Date,
            default: null
        },

        resetOtpVerified: {
            type: Boolean,
            default: false
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model("User", userSchema);