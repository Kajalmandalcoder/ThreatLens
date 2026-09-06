document.addEventListener("DOMContentLoaded", () => {

    lucide.createIcons();

    const emailStep = document.getElementById("emailStep");
    const otpStep = document.getElementById("otpStep");
    const passwordStep = document.getElementById("passwordStep");
    const successStep = document.getElementById("successStep");

    const emailForm = document.getElementById("emailForm");
    const otpForm = document.getElementById("otpForm");
    const passwordForm = document.getElementById("passwordForm");

    const emailInput = document.getElementById("email");
    const otpInput = document.getElementById("otp");
    const newPassword = document.getElementById("newPassword");
    const confirmPassword = document.getElementById("confirmPassword");

    const otpEmail = document.getElementById("otpEmail");
    const resendOtp = document.getElementById("resendOtp");

    let userEmail = "";
    let verifiedOtp = "";


    // =========================
    // SHOW STEP
    // =========================

    function showStep(step) {

        document.querySelectorAll(".step").forEach(item => {
            item.classList.remove("active");
        });

        step.classList.add("active");

        lucide.createIcons();
    }


    // =========================
    // SEND OTP
    // =========================

    emailForm.addEventListener("submit", async (e) => {

        e.preventDefault();

        userEmail = emailInput.value.trim();

        if (!userEmail) {
            alert("Please enter your email.");
            return;
        }

        try {

            const response = await fetch(
                "http://localhost:5001/api/auth/forgot-password",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        email: userEmail
                    })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                alert(data.message || "Unable to send OTP.");
                return;
            }

            otpEmail.textContent = userEmail;

            showStep(otpStep);

        } catch (error) {

            console.error("Send OTP error:", error);

            alert("Server error. Please try again.");

        }

    });


    // =========================
    // VERIFY OTP
    // =========================

    otpForm.addEventListener("submit", async (e) => {

        e.preventDefault();

        const otp = otpInput.value.trim();

        if (otp.length !== 6) {
            alert("Please enter the 6-digit OTP.");
            return;
        }

        try {

            const response = await fetch(
                "http://localhost:5001/api/auth/verify-reset-otp",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        email: userEmail,
                        otp: otp
                    })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                alert(data.message || "Invalid OTP.");
                return;
            }

            verifiedOtp = otp;

            showStep(passwordStep);

        } catch (error) {

            console.error("OTP verification error:", error);

            alert("Server error. Please try again.");

        }

    });


    // =========================
    // RESET PASSWORD
    // =========================

    passwordForm.addEventListener("submit", async (e) => {

        e.preventDefault();

        const password = newPassword.value;
        const confirm = confirmPassword.value;

        // Password validation
        if (password.length < 8) {
            alert("Password must contain at least 8 characters.");
            return;
        }

        if (password !== confirm) {
            alert("Passwords do not match.");
            return;
        }

        try {

            const response = await fetch(
                "http://localhost:5001/api/auth/reset-password",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        email: userEmail,
                        password: password
                    })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                alert(data.message || "Password reset failed.");
                return;
            }

            showStep(successStep);

        } catch (error) {

            console.error("Password reset error:", error);

            alert("Server error. Please try again.");

        }

    });


    // =========================
    // RESEND OTP
    // =========================

    resendOtp.addEventListener("click", async () => {

        if (!userEmail) {
            alert("Please enter your email first.");
            return;
        }

        try {

            const response = await fetch(
                "http://localhost:5001/api/auth/forgot-password",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        email: userEmail
                    })
                }
            );

            const data = await response.json();

            if (response.ok) {

                alert("New OTP sent.");

                otpInput.value = "";

            } else {

                alert(data.message || "Unable to resend OTP.");

            }

        } catch (error) {

            console.error("Resend OTP error:", error);

            alert("Server error. Please try again.");

        }

    });


    // =========================
    // PASSWORD VISIBILITY
    // =========================

    const toggleNewPassword =
        document.getElementById("toggleNewPassword");

    if (toggleNewPassword) {

        toggleNewPassword.addEventListener("click", function () {

            if (newPassword.type === "password") {

                newPassword.type = "text";

                this.innerHTML =
                    '<i data-lucide="eye-off"></i>';

            } else {

                newPassword.type = "password";

                this.innerHTML =
                    '<i data-lucide="eye"></i>';

            }

            lucide.createIcons();

        });

    }

});