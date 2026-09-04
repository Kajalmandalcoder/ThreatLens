document.addEventListener("DOMContentLoaded", () => {

    // Lucide Icons Render
    if (typeof lucide !== "undefined") {
        lucide.createIcons();
    }

    // =========================
    // DOM ELEMENTS
    // =========================
    const fileInput = document.getElementById("fileInput");
    const chooseFileBtn = document.getElementById("chooseFileBtn");
    const dropZone = document.getElementById("dropZone") || document.querySelector(".drop-zone");

    const uploadTitle = document.getElementById("uploadTitle");
    const dragText = document.getElementById("dragText");
    const selectedFile = document.getElementById("selectedFile");

    const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20MB


    // =========================
    // FILE VALIDATION
    // =========================
    function validateEmailFile(file) {
        if (!file) return false;

        if (!file.name.toLowerCase().endsWith(".eml")) {
            alert("Please select a valid .eml file.");
            return false;
        }

        if (file.size > MAX_FILE_SIZE) {
            alert("Maximum file size limit is 20 MB.");
            return false;
        }

        return true;
    }


    // =========================
    // DISPLAY FILE NAME IN UI
    // =========================
    function showSelectedFile(file) {
        if (!file) return;

        if (uploadTitle) uploadTitle.textContent = "Email selected";
        if (dragText) dragText.textContent = "Ready to analyze";

        if (selectedFile) {
            selectedFile.textContent = "📄 " + file.name;
            selectedFile.style.display = "block";
        }

        console.log("✅ File Selected Successfully:", file.name);
    }


    // =========================
    // BUTTON CLICK HANDLER
    // =========================
    if (chooseFileBtn && fileInput) {
        chooseFileBtn.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            fileInput.click();
        });
    }


    // =========================
    // FILE INPUT CHANGE HANDLER
    // =========================
    if (fileInput) {
        fileInput.addEventListener("change", (e) => {
            e.stopPropagation();

            const file = e.target.files[0];
            if (!file) return;

            if (!validateEmailFile(file)) {
                fileInput.value = ""; // Reset invalid file
                return;
            }

            // Show selected file immediately in UI
            showSelectedFile(file);

            // Upload to API
            uploadEmail(file);
        });
    }


    // =========================
    // DRAG & DROP HANDLERS
    // =========================
    if (dropZone) {
        ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        dropZone.addEventListener("dragover", () => {
            dropZone.classList.add("drag-over");
        });

        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("drag-over");
        });

        dropZone.addEventListener("drop", (e) => {
            dropZone.classList.remove("drag-over");

            const files = e.dataTransfer.files;
            if (!files || files.length === 0) return;

            const file = files[0];
            if (!validateEmailFile(file)) return;

            // Assign file to input element safely using DataTransfer
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(file);
            fileInput.files = dataTransfer.files;

            showSelectedFile(file);
            uploadEmail(file);
        });
    }


    // =========================
    // UPLOAD TO BACKEND SERVER
    // =========================
    async function uploadEmail(file) {
        const formData = new FormData();
        formData.append("email", file);

        console.log("📤 Sending EML file to server:", file.name);

        try {
            console.log("🌐 Fetch starting...");
            const response = await fetch("http://localhost:5001/api/emails/analyze", {
                method: "POST",
                body: formData
            });

            console.log("🌐 Fetch response received:", response.status);

            const result = await response.json();

            console.log("📥 Backend result:", result);

            if (!response.ok) {
                throw new Error(result.message || "File analysis failed");
            }

            console.log("📥 Backend Analysis Result:", result);

            // Maintain file selection UI state
            showSelectedFile(file);

        } catch (error) {
            console.error("❌ Upload error:", error);
            // File interface screen par retained rahegi
            showSelectedFile(file);
        }
    }


    // =========================
    // HELP MODAL HANDLERS
    // =========================
    const helpBtn = document.getElementById("helpBtn");
    const helpModal = document.getElementById("helpModal");
    const closeModal = document.getElementById("closeModal");
    const gotIt = document.getElementById("gotIt");

    if (helpBtn && helpModal) {
        helpBtn.addEventListener("click", () => helpModal.classList.add("active"));
    }
    if (closeModal && helpModal) {
        closeModal.addEventListener("click", () => helpModal.classList.remove("active"));
    }
    if (gotIt && helpModal) {
        gotIt.addEventListener("click", () => helpModal.classList.remove("active"));
    }
    if (helpModal) {
        helpModal.addEventListener("click", (e) => {
            if (e.target === helpModal) helpModal.classList.remove("active");
        });
    }

});

