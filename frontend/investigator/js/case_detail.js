document.addEventListener("DOMContentLoaded", () => {

    lucide.createIcons();

    const tabs = document.querySelectorAll(".tab");

    // Saare tab sections
    const panels = [
        document.getElementById("overview"),
        document.getElementById("email-evidence"),
        document.getElementById("header-analysis"),
        document.getElementById("email-journey"),
        document.getElementById("ip-intelligence"),
        document.getElementById("domain-intelligence"),
        document.getElementById("campaign"),
        document.getElementById("timeline"),
        document.getElementById("report")
    ];

    // Initially sirf overview
    panels.forEach(panel => {
        if (panel) {
            panel.style.display = "none";
        }
    });

    document.getElementById("overview").style.display = "block";

    tabs.forEach(tab => {

        tab.addEventListener("click", () => {

            const targetId = tab.getAttribute("data-tab");

            console.log("Clicked:", targetId);

            // Sab hide
            panels.forEach(panel => {
                if (panel) {
                    panel.style.display = "none";
                }
            });

            // Sab tabs inactive
            tabs.forEach(t => {
                t.classList.remove("active");
            });

            // Current tab active
            tab.classList.add("active");

            // Target show
            const targetPanel = document.getElementById(targetId);

            if (targetPanel) {
                targetPanel.style.display = "block";
                console.log("Showing:", targetId);
            } else {
                console.error("Panel not found:", targetId);
            }

            lucide.createIcons();
        });

    });

});