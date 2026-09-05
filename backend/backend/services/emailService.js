const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function sendOTPEmail(email, otp) {
    await transporter.sendMail({
        from: `"ThreatLens" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "ThreatLens - Email Verification OTP",

        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px;">

                <h2>Welcome to ThreatLens</h2>

                <p>
                    Thanks for creating your ThreatLens account.
                    Please use the OTP below to verify your email address.
                </p>

                <div style="
                    font-size: 32px;
                    font-weight: bold;
                    letter-spacing: 8px;
                    margin: 25px 0;
                ">
                    ${otp}
                </div>

                <p>
                    This OTP is valid for <strong>5 minutes</strong>.
                </p>

                <p>
                    If you didn't request this, you can safely ignore this email.
                </p>

                <p>
                    — ThreatLens Team
                </p>

            </div>
        `
    });
}

async function sendPasswordResetOTPEmail(email, otp) {
    await transporter.sendMail({
        from: `"ThreatLens" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "ThreatLens - Password Reset OTP",

        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px;">

                <h2>Reset your ThreatLens password</h2>

                <p>
                    We received a request to reset your ThreatLens password.
                    Use the OTP below to continue.
                </p>

                <div style="
                    font-size: 32px;
                    font-weight: bold;
                    letter-spacing: 8px;
                    margin: 25px 0;
                ">
                    ${otp}
                </div>

                <p>
                    This OTP is valid for <strong>5 minutes</strong>.
                </p>

                <p>
                    If you didn't request a password reset,
                    you can safely ignore this email.
                </p>

                <p>
                    — ThreatLens Team
                </p>

            </div>
        `
    });
}

module.exports = {
    sendOTPEmail,
    sendPasswordResetOTPEmail
};