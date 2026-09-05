document.addEventListener("DOMContentLoaded", () => {

    /* ================= LUCIDE ================= */

    if (window.lucide) {
        lucide.createIcons();
    }


    /* ================= DRAWER ================= */

    const drawer = document.getElementById("evidenceDrawer");
    const closeDrawer = document.getElementById("closeDrawer");
    const drawerCase = document.getElementById("drawerCase");

    const caseNodes = document.querySelectorAll(".case-node");


    caseNodes.forEach(node => {

        node.addEventListener("click", () => {

            const caseId = node.dataset.case;

            if (drawerCase) {
                drawerCase.textContent = caseId;
            }

            drawer.classList.remove("hidden");

        });

    });


    closeDrawer.addEventListener("click", () => {

        drawer.style.display = "none";

    });


    /* ================= FILTERS ================= */

    const filters = document.querySelectorAll(".filter");

    const lines = document.querySelectorAll(".connections line");

    filters.forEach(button => {

        button.addEventListener("click", () => {

            filters.forEach(btn => {
                btn.classList.remove("active");
            });

            button.classList.add("active");

            const filter = button.dataset.filter;


            lines.forEach(line => {

                if (filter === "all") {

                    line.style.opacity = "0.8";

                } else {

                    if (line.dataset.type === filter) {
                        line.style.opacity = "1";
                        line.style.strokeWidth = "2";
                    } else {
                        line.style.opacity = "0.08";
                        line.style.strokeWidth = "1";
                    }

                }

            });

        });

    });


    /* ================= VIEW TABS ================= */

    const viewTabs = document.querySelectorAll(".view-tab");

    viewTabs.forEach(tab => {

        tab.addEventListener("click", () => {

            viewTabs.forEach(item => {
                item.classList.remove("active");
            });

            tab.classList.add("active");

        });

    });


    /* ================= CHECKBOXES ================= */

    const checkboxes = document.querySelectorAll(
        ".network-footer input[type='checkbox']"
    );

    checkboxes.forEach((checkbox, index) => {

        checkbox.addEventListener("change", () => {

            const selector =
                index === 0
                    ? ".case-node"
                    : ".indicator";

            document.querySelectorAll(selector).forEach(element => {

                element.style.display =
                    checkbox.checked ? "" : "none";

            });

        });

    });


    /* ================= PIN EVIDENCE ================= */

    const pinButton = document.querySelector(".pin-button");

    if (pinButton) {

        pinButton.addEventListener("click", () => {

            pinButton.innerHTML =
                "✓ Evidence pinned to investigation";

            pinButton.style.color = "#29d1b2";
            pinButton.style.borderColor = "#187d6d";

        });

    }


    /* ================= NODE HOVER ================= */

    caseNodes.forEach(node => {

        node.addEventListener("mouseenter", () => {
            node.style.borderColor = "#2bbab5";
            node.style.transform = "translateY(-2px)";
        });

        node.addEventListener("mouseleave", () => {
            node.style.borderColor = "#254057";
            node.style.transform = "";
        });

    });


    /* ================= SYNC TIME ================= */

    const footer = document.querySelector("footer span:first-child");

    if (footer) {

        footer.addEventListener("click", () => {

            footer.textContent = "◷ Last synced just now";

        });

    }

});