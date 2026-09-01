lucide.createIcons();

// =========================
// DARK / LIGHT MODE
// =========================

const themeToggle = document.getElementById("themeToggle");
const themeText = document.getElementById("themeText");


// Load saved theme
const savedTheme = localStorage.getItem("theme");

if (savedTheme === "dark") {
    document.body.classList.add("dark-mode");
    themeText.textContent = "Light";
}


// Toggle theme
themeToggle.addEventListener("click", function () {

    document.body.classList.toggle("dark-mode");

    if (document.body.classList.contains("dark-mode")) {

        themeText.textContent = "Light";

        localStorage.setItem("theme", "dark");

    } else {

        themeText.textContent = "Dark";

        localStorage.setItem("theme", "light");

    }

});

    /* =========================
       SEARCH
    ========================= */

    const searchInput =
        document.getElementById("searchInput");

    const cards =
        document.querySelectorAll(".history-card");


    searchInput.addEventListener("input", function () {

        const value =
            this.value.toLowerCase().trim();


        cards.forEach(card => {

            const text =
                card.innerText.toLowerCase();

            card.style.display =
                text.includes(value)
                ? "grid"
                : "none";

        });

    });


    /* =========================
       FILTER
    ========================= */

    const filters =
        document.querySelectorAll(".filter");


    filters.forEach(filter => {

        filter.addEventListener("click", function () {

            filters.forEach(btn =>
                btn.classList.remove("active")
            );

            this.classList.add("active");


            const selected =
                this.dataset.filter;


            cards.forEach(card => {

                if (selected === "all") {

                    card.style.display = "grid";

                } else {

                    card.style.display =
                        card.dataset.risk === selected
                        ? "grid"
                        : "none";

                }

            });

        });

    });