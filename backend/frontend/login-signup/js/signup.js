lucide.createIcons();


// =========================
// ELEMENTS
// =========================

const signupForm = document.getElementById("signupForm");

const otpSection = document.getElementById("otpSection");

const verifyOtpBtn = document.getElementById("verifyOtpBtn");

const otpInput = document.getElementById("otp");


// Store email temporarily
let signupEmail = "";


// =========================
// SIGNUP
// =========================

signupForm.addEventListener("submit", async function (e) {

    e.preventDefault();

    const name = document.getElementById("name").value.trim();

    const email = document.getElementById("email").value.trim();

    const password = document.getElementById("password").value;


    // Basic validation

    if (!name || !email || !password) {

        alert("Please fill all fields.");

        return;
    }


    try {

        const response = await fetch(
            "http://localhost:5000/api/auth/signup",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    name: name,
                    email: email,
                    password: password
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            alert(data.message);

            return;
        }


        // Save email for OTP verification

        signupEmail = email;


        alert("OTP has been sent to your email.");


        // Hide signup form

        signupForm.style.display = "none";


        // Show OTP section

        otpSection.style.display = "block";


        lucide.createIcons();

    }

    catch (error) {

        console.error("Signup error:", error);

        alert(
            "Unable to connect to ThreatLens server."
        );

    }

});


// =========================
// VERIFY OTP
// =========================

verifyOtpBtn.addEventListener("click", async function () {

    const otp = otpInput.value.trim();


    if (!otp) {

        alert("Please enter the OTP.");

        return;
    }


    if (!/^\d{6}$/.test(otp)) {

        alert("OTP must be exactly 6 digits.");

        return;
    }


    try {

        const response = await fetch(
            "http://localhost:5000/api/auth/verify-otp",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    email: signupEmail,
                    otp: otp
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            alert(data.message);

            return;
        }


        // =========================
        // SAVE JWT
        // =========================

        localStorage.setItem(
            "token",
            data.token
        );

        localStorage.setItem(
            "user",
            JSON.stringify(data.user)
        );


        alert("Email verified successfully!");


        // =========================
        // REDIRECT
        // =========================

        if (data.user.role === "investigator") {

            window.location.href =
                "../investigator/dash_invest.html";

        } else {

            window.location.href =
                "../user/dash_user.html";

        }
            }

    catch (error) {

        console.error(
            "OTP verification error:",
            error
        );

        alert(
            "Unable to connect to ThreatLens server."
        );

    }

});