// ==========================================
// LOAD HEADER
// ==========================================

fetch("components/header.html")
    .then(response => response.text())
    .then(data => {

        // Header load karo
        document.getElementById("header").innerHTML = data;

        // Lucide icons
        lucide.createIcons();

        // ==========================================
        // DYNAMIC USER PROFILE
        // ==========================================

        const token = localStorage.getItem("token");

        if (token) {

            try {

                const payload = JSON.parse(
                    atob(token.split(".")[1])
                );

                const name =
                    payload.name ||
                    payload.email?.split("@")[0] ||
                    "User";

                const profileName =
                    document.getElementById("profileName");

                const profileAvatar =
                    document.getElementById("profileAvatar");

                const profileWorkspace =
                    document.getElementById("profileWorkspace");


                // User name
                if (profileName) {
                    profileName.textContent = name;
                }


                // User initials
                if (profileAvatar) {

                    const initials = name
                        .split(" ")
                        .map(word => word.charAt(0))
                        .join("")
                        .substring(0, 2)
                        .toUpperCase();

                    profileAvatar.textContent = initials;
                }


                // Workspace
                if (profileWorkspace) {
                    profileWorkspace.textContent =
                        "Personal workspace";
                }

            } catch (error) {

                console.error(
                    "Profile load nahi hua:",
                    error
                );

            }

        }


        // ==========================================
        // DARK / LIGHT MODE
        // ==========================================

        const themeToggle = document.getElementById("themeToggle");
        const themeText = document.getElementById("themeText");

        // Saved theme check
        const savedTheme = localStorage.getItem("theme");

        if (savedTheme === "dark") {

            document.body.classList.add("dark-mode");

            themeText.textContent = "Light";

        } else {

            document.body.classList.remove("dark-mode");

            themeText.textContent = "Dark";
        }


        // Theme button
        if (themeToggle) {

            themeToggle.addEventListener("click", function () {

                document.body.classList.toggle("dark-mode");

                const isDark =
                    document.body.classList.contains("dark-mode");


                if (isDark) {

                    themeText.textContent = "Light";

                    localStorage.setItem("theme", "dark");

                } else {

                    themeText.textContent = "Dark";

                    localStorage.setItem("theme", "light");
                }

            });

        }


        // ==========================================
        // HELP MODAL
        // ==========================================

        const helpBtn = document.getElementById("helpBtn");

        const helpModal = document.getElementById("helpModal");

        const closeModal = document.getElementById("closeModal");

        const gotIt = document.getElementById("gotIt");


        // ==========================================
        // OPEN MODAL
        // ==========================================

        if (helpBtn && helpModal) {

            helpBtn.addEventListener("click", function () {

                helpModal.style.display = "flex";

            });

        }


        // ==========================================
        // CLOSE USING X
        // ==========================================

        if (closeModal && helpModal) {

            closeModal.addEventListener("click", function () {

                helpModal.style.display = "none";

            });

        }


        // ==========================================
        // CLOSE USING GOT IT
        // ==========================================

        if (gotIt && helpModal) {

            gotIt.addEventListener("click", function () {

                helpModal.style.display = "none";

            });

        }


        // ==========================================
        // CLOSE WHEN CLICKING OUTSIDE MODAL
        // ==========================================

        if (helpModal) {

            helpModal.addEventListener("click", function (event) {

                if (event.target === helpModal) {

                    helpModal.style.display = "none";

                }

            });

        }

    })


    // ==========================================
    // ERROR
    // ==========================================

    .catch(error => {

        console.error("Header load nahi hua:", error);

    });