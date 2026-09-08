// =========================
// ANALYSIS HISTORY
// =========================


// =========================
// DOM
// =========================

let themeToggle;
let themeText;
let searchInput;
let historyList;
let filters;


// =========================
// INITIALIZATION
// =========================

document.addEventListener("DOMContentLoaded", () => {

    console.log("🚀 Analysis History started");


    // DOM references
    themeToggle =
        document.getElementById("themeToggle");

    themeText =
        document.getElementById("themeText");

    searchInput =
        document.getElementById("searchInput");

    historyList =
        document.getElementById("historyList");

    filters =
        document.querySelectorAll(".filter");


    // Initialize icons
    if (typeof lucide !== "undefined") {
        lucide.createIcons();
    }


    // Initialize theme
    initializeTheme();


    // Search
    if (searchInput) {

        searchInput.addEventListener(
            "input",
            applyFilters
        );

    }


    // Filters
    filters.forEach(filter => {

        filter.addEventListener(
            "click",
            function () {

                filters.forEach(btn => {
                    btn.classList.remove("active");
                });


                this.classList.add("active");


                applyFilters();

            }
        );

    });


    // Load cases
    loadCases();

});


// =========================
// THEME
// =========================

function initializeTheme() {

    const savedTheme =
        localStorage.getItem("theme");


    if (savedTheme === "dark") {

        document.body.classList.add(
            "dark-mode"
        );

        if (themeText) {
            themeText.textContent = "Light";
        }

    } else {

        document.body.classList.remove(
            "dark-mode"
        );

        if (themeText) {
            themeText.textContent = "Dark";
        }

    }


    if (themeToggle) {

        themeToggle.addEventListener(
            "click",
            toggleTheme
        );

    }

}


// =========================
// TOGGLE THEME
// =========================

function toggleTheme() {

    document.body.classList.toggle(
        "dark-mode"
    );


    const isDark =
        document.body.classList.contains(
            "dark-mode"
        );


    if (themeText) {

        themeText.textContent =
            isDark
                ? "Light"
                : "Dark";

    }


    localStorage.setItem(
        "theme",
        isDark
            ? "dark"
            : "light"
    );


    if (typeof lucide !== "undefined") {
        lucide.createIcons();
    }

}


// =========================
// LOAD USER'S CASES
// =========================

async function loadCases() {

    try {

        const token =
            localStorage.getItem("token");


        // -------------------------
        // TOKEN CHECK
        // -------------------------

        if (!token) {

            showError(
                "Please login again."
            );

            return;

        }


        console.log(
            "📡 Fetching user's analysis history..."
        );


        // -------------------------
        // API
        // -------------------------

        const response =
            await fetch(
                "http://localhost:5001/api/emails",
                {
                    method: "GET",

                    headers: {
                        "Authorization":
                            `Bearer ${token}`
                    }
                }
            );


        const result =
            await response.json();


        console.log(
            "📦 History API response:",
            result
        );


        // -------------------------
        // API ERROR
        // -------------------------

        if (!response.ok) {

            throw new Error(
                result.message ||
                "Failed to fetch analysis history."
            );

        }


        if (!result.success) {

            throw new Error(
                result.message ||
                "Failed to fetch analysis history."
            );

        }


        // -------------------------
        // CASES
        // -------------------------

        /*
         * IMPORTANT:
         *
         * Backend already applies ownership:
         *
         * USER:
         * { userId: req.user.userId }
         *
         * INVESTIGATOR:
         * {}
         *
         * So DON'T filter userId here.
         */

        const cases =
            Array.isArray(result.cases)
                ? result.cases
                : [];


        console.log(
            "📥 My cases:",
            cases.length
        );


        // -------------------------
        // RENDER
        // -------------------------

        renderCases(cases);


    } catch (error) {

        console.error(
            "❌ History loading error:",
            error
        );


        showError(
            error.message ||
            "Unable to load analysis history."
        );

    }

}


// =========================
// RENDER CASES
// =========================

function renderCases(cases) {

    if (!historyList) {

        console.error(
            "❌ #historyList not found."
        );

        return;

    }


    historyList.innerHTML = "";


    // -------------------------
    // EMPTY
    // -------------------------

    if (!cases.length) {

        historyList.innerHTML = `

            <div class="empty-state">

                <i data-lucide="inbox"></i>

                <h3>
                    No analysis history
                </h3>

                <p>
                    You haven't analyzed any emails yet.
                </p>

            </div>

        `;


        refreshIcons();

        return;

    }


    // -------------------------
    // CREATE CARDS
    // -------------------------

    cases.forEach(email => {

        const card =
            document.createElement("div");


        card.className =
            "history-card";


        // =========================
        // DATA
        // =========================

        const subject =
            email.headers?.subject ||
            "No Subject";


        const fileName =
            email.fileName ||
            email.filename ||
            "Analyzed email";


        const date =
            formatDate(
                email.headers?.date ||
                email.createdAt
            );


        const risk =
            getRiskInfo(email);


        // Used by filters
        card.dataset.risk =
            risk.label;


        // Used by search
        card.dataset.search =
            [
                subject,
                fileName,
                date,
                risk.label
            ]
                .join(" ")
                .toLowerCase();


        // =========================
        // CARD HTML
        // =========================

        card.innerHTML = `

            <div class="mail-icon">

                <i data-lucide="mail"></i>

            </div>


            <div class="email-details">

                <h3>
                    ${escapeHtml(subject)}
                </h3>


                <div class="email-meta">

                    <span>
                        ${escapeHtml(fileName)}
                    </span>

                    <b>•</b>

                    <span>
                        ${escapeHtml(date)}
                    </span>

                </div>

            </div>


            <div class="risk ${risk.cssClass}">

                <span></span>

                ${escapeHtml(risk.label)}

            </div>


            <div class="score">

                <strong>
                    ${risk.score}
                </strong>

                <span>
                    /100
                </span>

            </div>


            <button
                class="view-btn"
                type="button"
            >

                View

                <i data-lucide="arrow-right"></i>

            </button>

        `;


        // =========================
        // VIEW BUTTON
        // =========================

        const viewBtn =
            card.querySelector(
                ".view-btn"
            );


        if (viewBtn) {

            viewBtn.addEventListener(
                "click",
                event => {

                    event.stopPropagation();


                    // MongoDB _id required
                    if (!email._id) {

                        console.error(
                            "❌ MongoDB _id missing:",
                            email
                        );

                        return;

                    }


                    /*
                     * USER FLOW:
                     *
                     * History
                     *      ↓
                     * View
                     *      ↓
                     * analysis_result.html
                     *
                     * NOT case_detail.html
                     */

                    window.location.href =
                        `analysis_result.html?id=${encodeURIComponent(
                            email._id
                        )}`;

                }
            );

        }


        historyList.appendChild(card);

    });


    refreshIcons();


    // Apply current search/filter
    applyFilters();

}


// =========================
// RISK INFORMATION
// =========================

function getRiskInfo(email) {

    const ml =
        email.mlAnalysis || {};


    let score = 0;


    // -------------------------
    // RISK ANALYSIS
    // -------------------------

    if (
        email.riskAnalysis?.final_score !==
        undefined &&
        email.riskAnalysis?.final_score !==
        null
    ) {

        score =
            Number(
                email.riskAnalysis.final_score
            );

    }


    // -------------------------
    // RISK ENGINE
    // -------------------------

    else if (
        email.riskEngine?.final_score !==
        undefined &&
        email.riskEngine?.final_score !==
        null
    ) {

        score =
            Number(
                email.riskEngine.final_score
            );

    }


    // -------------------------
    // ML THREAT SCORE
    // -------------------------

    else if (
        ml.threatScore !==
        undefined &&
        ml.threatScore !==
        null
    ) {

        score =
            Number(
                ml.threatScore
            );

    }


    // -------------------------
    // FALLBACK
    // -------------------------

    if (!Number.isFinite(score)) {

        score = 0;

    }


    score =
        Math.max(
            0,
            Math.min(
                100,
                Math.round(score)
            )
        );


    const prediction =
        String(
            ml.prediction || ""
        )
            .trim()
            .toUpperCase();


    const riskLevel =
        String(
            ml.riskLevel || ""
        )
            .trim()
            .toUpperCase();


    // =========================
    // PHISHING
    // =========================

    if (
        prediction === "PHISHING"
    ) {

        return {
            label: "Critical",
            cssClass: "critical",
            score
        };

    }


    // =========================
    // SUSPICIOUS
    // =========================

    if (
        prediction === "SUSPICIOUS"
    ) {

        return {
            label: "Suspicious",
            cssClass: "suspicious",
            score
        };

    }


    // =========================
    // HIGH RISK
    // =========================

    if (
        riskLevel === "HIGH" ||
        score >= 60
    ) {

        return {
            label: "High Risk",
            cssClass: "high",
            score
        };

    }


    // =========================
    // MEDIUM
    // =========================

    if (
        riskLevel === "MEDIUM" ||
        score >= 30
    ) {

        return {
            label: "Suspicious",
            cssClass: "suspicious",
            score
        };

    }


    // =========================
    // SAFE
    // =========================

    return {
        label: "Safe",
        cssClass: "safe",
        score
    };

}


// =========================
// SEARCH + FILTER
// =========================

function applyFilters() {

    const cards =
        document.querySelectorAll(
            ".history-card"
        );


    const searchValue =
        searchInput
            ? searchInput.value
                .toLowerCase()
                .trim()
            : "";


    const activeFilter =
        document.querySelector(
            ".filter.active"
        );


    const selectedFilter =
        activeFilter?.dataset.filter ||
        "all";


    cards.forEach(card => {

        const searchableText =
            card.dataset.search ||
            card.innerText.toLowerCase();


        const searchMatch =
            searchableText.includes(
                searchValue
            );


        const filterMatch =
            selectedFilter === "all" ||
            card.dataset.risk ===
                selectedFilter;


        if (
            searchMatch &&
            filterMatch
        ) {

            card.style.display =
                "grid";

        } else {

            card.style.display =
                "none";

        }

    });

}


// =========================
// DATE
// =========================

function formatDate(value) {

    if (!value) {

        return "—";

    }


    const date =
        new Date(value);


    if (
        isNaN(
            date.getTime()
        )
    ) {

        return String(value);

    }


    return date.toLocaleString(
        "en-IN",
        {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );

}


// =========================
// ESCAPE HTML
// =========================

function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {

        return "";

    }


    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );

}


// =========================
// ERROR
// =========================

function showError(message) {

    if (!historyList) {

        return;

    }


    historyList.innerHTML = `

        <div class="empty-state">

            <i data-lucide="alert-circle"></i>

            <h3>
                Failed to load history
            </h3>

            <p>
                ${escapeHtml(
                    message ||
                    "Something went wrong."
                )}
            </p>

        </div>

    `;


    refreshIcons();

}


// =========================
// LUCIDE REFRESH
// =========================

function refreshIcons() {

    if (
        typeof lucide !== "undefined"
    ) {

        lucide.createIcons();

    }

}