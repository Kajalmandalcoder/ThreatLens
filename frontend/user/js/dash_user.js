lucide.createIcons();

// =========================
// FILE UPLOAD
// =========================

const fileInput = document.getElementById("fileInput");

fileInput.addEventListener("change", function () {

    if (this.files.length > 0) {
        const file = this.files[0];

        if (!file.name.toLowerCase().endsWith(".eml")) {
            alert("Please select an .eml file.");
            this.value = "";
            return;
        }

        console.log("Selected file:", file.name);
    }

});


// =========================
// HELP MODAL
// =========================

const helpBtn = document.getElementById("helpBtn");
const helpModal = document.getElementById("helpModal");
const closeModal = document.getElementById("closeModal");
const gotIt = document.getElementById("gotIt");


// Open modal
helpBtn.addEventListener("click", function () {
    helpModal.classList.add("active");
});


// Close using X
closeModal.addEventListener("click", function () {
    helpModal.classList.remove("active");
});


// Close using Got it
gotIt.addEventListener("click", function () {
    helpModal.classList.remove("active");
});


// Close by clicking outside modal
helpModal.addEventListener("click", function (e) {

    if (e.target === helpModal) {
        helpModal.classList.remove("active");
    }

});

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