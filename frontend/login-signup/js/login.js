lucide.createIcons();

const loginForm = document.getElementById("loginForm");

loginForm.addEventListener("submit", async function (e) {

    e.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    try {

        const response = await fetch(
            "http://localhost:5001/api/auth/login",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    email: email,
                    password: password
                })
            }
        );
        
        const data = await response.json();

        console.log("LOGIN RESPONSE:", data);
        console.log("ROLE:", data.user?.role);

        if (!response.ok) {
            alert(data.message);
            return;
        }

        // Save JWT
        localStorage.setItem("token", data.token);

        // Save user
        localStorage.setItem(
            "user",
            JSON.stringify(data.user)
        );

        alert("Login successful!");

        if (data.user.role === "investigator") {

            window.location.href =
                "../investigator/dash_invest.html";

        } else {

            window.location.href =
                "../user/dash_user.html";

        }

    } catch (error) {

        console.error("Login error:", error);

        alert("Unable to connect to server.");

    }

});