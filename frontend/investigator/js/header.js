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

        // Active page
        const currentPage = window.location.pathname.split("/").pop();

        document.querySelectorAll(".top-header nav a").forEach(link => {
            const linkPage = link.getAttribute("href");

            if (linkPage === currentPage) {
                link.classList.add("active");
            }
        });

    } catch (error) {
        console.error("Header loading failed:", error);
    }
});