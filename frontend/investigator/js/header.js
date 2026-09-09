document.addEventListener("DOMContentLoaded", async () => {

    const headerContainer = document.getElementById("investigator-header");

    if (!headerContainer) {
        console.error("investigator-header not found");
        return;
    }

    try {
        const response = await fetch("./header.html");

        if (!response.ok) {
            throw new Error("header.html not found");
        }

        const html = await response.text();

        headerContainer.innerHTML = html;

        // Lucide icons load
        if (window.lucide) {
            lucide.createIcons();
        }

        // ==============================
        // LOAD LOGGED-IN INVESTIGATOR
        // ==============================

        const token = localStorage.getItem("token");

        if (token) {
            try {

                const payload = JSON.parse(
                    atob(token.split(".")[1])
                );

                const name =
                    payload.name ||
                    payload.email?.split("@")[0] ||
                    "Investigator";

                const nameElement =
                    document.getElementById("investigatorName");

                const avatarElement =
                    document.getElementById("investigatorAvatar");

                // Show name
                if (nameElement) {
                    nameElement.textContent = name;
                }

                // Generate initials
                if (avatarElement) {

                    const initials = name
                        .trim()
                        .split(/\s+/)
                        .map(word => word[0])
                        .join("")
                        .substring(0, 2)
                        .toUpperCase();

                    avatarElement.textContent = initials;
                }

            } catch (profileError) {

                console.error(
                    "Failed to load investigator profile:",
                    profileError
                );

            }
        }

        // ==============================
        // ACTIVE PAGE
        // ==============================

        const currentPage =
            window.location.pathname.split("/").pop();

        document
            .querySelectorAll(".top-header nav a")
            .forEach(link => {

                const linkPage =
                    link.getAttribute("href");

                if (linkPage === currentPage) {
                    link.classList.add("active");
                }

            });

    } catch (error) {

        console.error(
            "Header loading failed:",
            error
        );

    }

});