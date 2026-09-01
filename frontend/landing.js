const themeToggle = document.getElementById("themeToggle");

const savedTheme = localStorage.getItem("theme");

if (savedTheme === "light") {
    document.body.classList.add("light-mode");
}


function updateThemeIcon() {

    themeToggle.innerHTML = document.body.classList.contains("light-mode")
        ? '<i data-lucide="moon"></i>'
        : '<i data-lucide="sun"></i>';

    lucide.createIcons();
}


themeToggle.addEventListener("click", function () {

    document.body.classList.toggle("light-mode");

    const isLight = document.body.classList.contains("light-mode");

    localStorage.setItem(
        "theme",
        isLight ? "light" : "dark"
    );

    updateThemeIcon();
});


updateThemeIcon();