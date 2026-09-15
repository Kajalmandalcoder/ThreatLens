// ============================================================
// THREATLENS - DYNAMIC FORENSIC INVESTIGATION REPORT
// ============================================================

const API_BASE_URL = "http://localhost:5001/api";


// ============================================================
// 1. GET CASE ID + TOKEN
// ============================================================

const params = new URLSearchParams(window.location.search);

const caseId =
    params.get("id") ||
    params.get("caseId");

const token = localStorage.getItem("token");


// ============================================================
// 2. BASIC VALIDATION
// ============================================================

if (!token) {
    alert("Please login first.");
    window.location.href = "login.html";
}

if (!caseId) {
    console.error("ThreatLens: Case ID missing from URL.");
}


// ============================================================
// 3. MODULE CONFIGURATION
// ============================================================

const MODULES = [
    {
        key: "ml",
        name: "ML Analysis",
        short: "ML",
        icon: "ml"
    },
    {
        key: "header",
        name: "Header Forensics",
        short: "HF",
        icon: "header"
    },
    {
        key: "ip",
        name: "IP Intelligence",
        short: "IP",
        icon: "ip"
    },
    {
        key: "domain",
        name: "Domain Intelligence",
        short: "DI",
        icon: "domain"
    },
    {
        key: "url",
        name: "URL Intelligence",
        short: "UI",
        icon: "url"
    },
    {
        key: "attachment",
        name: "Attachment Intelligence",
        short: "AI",
        icon: "attachment"
    },
    {
        key: "image",
        name: "Image Intelligence",
        short: "IM",
        icon: "image"
    }
];


// ============================================================
// 4. FETCH REPORT DATA
// ============================================================

async function fetchCaseReport() {

    if (!caseId) {
        return;
    }

    try {

        console.log(
            "ThreatLens: Fetching case:",
            caseId
        );

        const response = await fetch(
            `${API_BASE_URL}/emails/${encodeURIComponent(caseId)}`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${token}`,
                    Accept: "application/json"
                }
            }
        );

        const result = await response.json();

        if (!response.ok || !result.success) {

            throw new Error(
                result.message ||
                "Failed to fetch case report"
            );
        }

        console.log(
            "ThreatLens: Case data received:",
            result.data
        );

        renderReport(result.data);

    } catch (error) {

        console.error(
            "ThreatLens report error:",
            error
        );

        showReportError(
            error.message
        );
    }
}


// ============================================================
// 5. MAIN REPORT RENDERER
// ============================================================

function renderReport(email) {

    const riskAssessment =
        email?.riskAssessment || {};

    const scores =
        riskAssessment.scoreComposition || {};

    const moduleAnalysis =
        riskAssessment.moduleAnalysis || {};


    // ----------------------------------------
    // FINAL RISK
    // ----------------------------------------

    const finalScore =
        Number(
            riskAssessment.finalRiskScore || 0
        );

    const classification =
        riskAssessment.classification ||
        "LEGITIMATE";

    const riskLevel =
        riskAssessment.riskLevel ||
        getScoreLevel(finalScore);


    // ----------------------------------------
    // HEADER INFORMATION
    // ----------------------------------------

    updateHeaderInformation(
        email,
        classification
    );


    // ----------------------------------------
    // EXECUTIVE SUMMARY
    // ----------------------------------------

    updateFinalScore(
        finalScore
    );

    updateClassification(
        classification,
        riskLevel
    );

    updateRiskRing(
        finalScore
    );


    // ----------------------------------------
    // SCORE COMPOSITION
    // ----------------------------------------

    updateComposition(
        scores
    );


    // ----------------------------------------
    // WEIGHTED OUTPUT CARDS
    // ----------------------------------------

    updateScoreCards(
        scores
    );


    // ----------------------------------------
    // MODULE ANALYSIS
    // ----------------------------------------

    updateAnalysisCards(
        scores,
        moduleAnalysis
    );


    // ----------------------------------------
    // FINAL ASSESSMENT
    // ----------------------------------------

    updateFinalAssessment(
        finalScore,
        classification,
        riskLevel,
        moduleAnalysis
    );


    // ----------------------------------------
    // RECOMMENDED ACTION
    // ----------------------------------------

    updateRecommendedActions(
        classification,
        riskLevel
    );


    console.log(
        "ThreatLens: Report rendered successfully."
    );
}


// ============================================================
// 6. HEADER INFORMATION
// ============================================================

function updateHeaderInformation(
    email,
    classification
) {

    const caseReference =
        email?.caseId ||
        email?._id ||
        caseId ||
        "N/A";


    // CASE REFERENCE
    const metaItems =
        document.querySelectorAll(
            ".header-meta .meta-item strong"
        );

    if (metaItems.length >= 1) {

        metaItems[0].textContent =
            caseReference;
    }


    // REPORT GENERATED
    if (metaItems.length >= 2) {

        const createdAt =
            email?.createdAt;

        metaItems[1].textContent =
            formatDateTime(
                createdAt
            );
    }


    // TOP BADGE
    const badge =
        document.querySelector(
            ".header-badge"
        );

    if (badge) {

        badge.textContent =
            classification;

        applyRiskClass(
            badge,
            classification
        );
    }
}


// ============================================================
// 7. FINAL SCORE
// ============================================================

function updateFinalScore(score) {

    // Big score
    const bigScore =
        document.querySelector(
            ".big-score"
        );

    if (bigScore) {

        bigScore.innerHTML = `
            ${score}
            <span>/ 100</span>
        `;
    }


    // Ring score
    const ringInner =
        document.querySelector(
            ".ring-inner"
        );

    if (ringInner) {

        ringInner.innerHTML = `
            <strong>${score}</strong>
            <span>/ 100</span>
        `;
    }


    // Final score
    const finalNumber =
        document.querySelector(
            ".final-number"
        );

    if (finalNumber) {

        finalNumber.innerHTML = `
            ${score}
            <small>/100</small>
        `;
    }
}


// ============================================================
// 8. CLASSIFICATION
// ============================================================

function updateClassification(
    classification,
    riskLevel
) {

    // Main classification block
    const classificationValue =
        document.querySelector(
            ".classification-value"
        );

    if (classificationValue) {

        classificationValue.innerHTML = `
            <span class="status-dot ${getStatusClass(classification)}"></span>
            ${classification}
            <span class="separator">•</span>
            ${riskLevel}
        `;
    }


    // Risk label
    const riskLabel =
        document.querySelector(
            ".risk-label"
        );

    if (riskLabel) {

        riskLabel.innerHTML = `
            <span class="status-dot ${getStatusClass(classification)}"></span>
            ${riskLevel} RISK CLASSIFICATION
        `;
    }


    // Final assessment classification
    const finalClassification =
        document.querySelector(
            ".final-score-row div:first-child strong"
        );

    if (finalClassification) {

        finalClassification.textContent =
            classification;

        applyRiskClass(
            finalClassification,
            classification
        );
    }


    // All classification elements
    document
        .querySelectorAll(
            ".classification"
        )
        .forEach(element => {

            element.textContent =
                classification;

            applyRiskClass(
                element,
                classification
            );
        });
}


// ============================================================
// 9. RISK RING
// ============================================================

function updateRiskRing(score) {

    const ring =
        document.querySelector(
            ".ring"
        );

    if (!ring) {
        return;
    }


    // Existing CSS may use conic-gradient.
    // This keeps the ring compatible with
    // most ThreatLens report styles.

    ring.style.background =
        `conic-gradient(
            currentColor ${score}%,
            rgba(255,255,255,0.08) ${score}%
        )`;
}


// ============================================================
// 10. SCORE COMPOSITION
// ============================================================

function updateComposition(scores) {

    const rows =
        document.querySelectorAll(
            ".composition-row"
        );


    rows.forEach(row => {

        const label =
            row.querySelector("span");

        const bar =
            row.querySelector(
                ".mini-bar i"
            );

        const value =
            row.querySelector("b");

        if (!label) {
            return;
        }

        const module =
            findModuleByName(
                label.textContent
            );

        if (!module) {
            return;
        }

        const score =
            Number(
                scores[module.key] || 0
            );


        if (value) {
            value.textContent =
                score;
        }


        if (bar) {

            bar.style.width =
                `${Math.max(score, score === 0 ? 3 : score)}%`;

            setLevelClass(
                bar,
                score
            );
        }

    });


    // Update module count
    const compositionHeader =
        document.querySelector(
            ".composition-header strong"
        );

    if (compositionHeader) {

        compositionHeader.textContent =
            `${MODULES.length} MODULES`;
    }
}


// ============================================================
// 11. WEIGHTED SCORE CARDS
// ============================================================

function updateScoreCards(scores) {

    const cards =
        document.querySelectorAll(
            ".score-card"
        );


    cards.forEach(card => {

        const title =
            card.querySelector("h3");

        if (!title) {
            return;
        }

        const module =
            findModuleByName(
                title.textContent
            );

        if (!module) {
            return;
        }

        const score =
            Number(
                scores[module.key] || 0
            );


        // Score
        const scoreNumber =
            card.querySelector(
                ".score-number"
            );

        if (scoreNumber) {

            scoreNumber.innerHTML = `
                ${score}
                <span>/100</span>
            `;
        }


        // Bar
        const bar =
            card.querySelector(
                ".score-bar i"
            );

        if (bar) {

            bar.style.width =
                `${Math.max(score, score === 0 ? 3 : score)}%`;

            setLevelClass(
                bar,
                score
            );
        }


        // Level badge
        const level =
            card.querySelector(
                ".level"
            );

        if (level) {

            level.textContent =
                getScoreLevel(score);

            setLevelClass(
                level,
                score
            );
        }


        // Card level class
        setCardLevel(
            card,
            score
        );

    });


    // Header card is not present in original HTML.
    // Add it dynamically.
    addMissingHeaderScoreCard(
        scores
    );
}


// ============================================================
// 12. ADD HEADER SCORE CARD
// ============================================================

function addMissingHeaderScoreCard(scores) {

    const existing =
        findElementByHeading(
            ".score-card",
            "Header Forensics"
        );

    if (existing) {
        return;
    }


    const grid =
        document.querySelector(
            ".score-grid"
        );

    if (!grid) {
        return;
    }


    const score =
        Number(
            scores.header || 0
        );


    const card =
        document.createElement(
            "div"
        );

    card.className =
        "score-card low-card dynamic-header-card";


    card.innerHTML = `
        <div class="score-card-top">
            <h3>Header Forensics</h3>
            <span class="level low">
                LOW
            </span>
        </div>

        <div class="score-number">
            ${score}
            <span>/100</span>
        </div>

        <div class="score-bar">
            <i style="width:${Math.max(score, score === 0 ? 3 : score)}%"></i>
        </div>

        <span class="score-caption">
            RISK SCORE
        </span>
    `;


    // Put Header after ML
    const mlCard =
        findElementByHeading(
            ".score-card",
            "ML Analysis"
        );

    if (mlCard) {

        mlCard.insertAdjacentElement(
            "afterend",
            card
        );

    } else {

        grid.prepend(card);
    }


    setCardLevel(
        card,
        score
    );
}


// ============================================================
// 13. MODULE ANALYSIS CARDS
// ============================================================

function updateAnalysisCards(
    scores,
    moduleAnalysis
) {

    const cards =
        document.querySelectorAll(
            ".analysis-card"
        );


    cards.forEach(card => {

        const title =
            card.querySelector(
                ".analysis-header h3"
            );

        if (!title) {
            return;
        }


        const module =
            findModuleByName(
                title.textContent
            );

        if (!module) {
            return;
        }


        const score =
            Number(
                scores[module.key] || 0
            );


        const analysis =
            moduleAnalysis[module.key] ||
            {};


        const reasoning =
            analysis.technicalReasoning ||
            "No technical reasoning available.";


        // ------------------------------------
        // SCORE
        // ------------------------------------

        const scoreStrong =
            card.querySelector(
                ".analysis-score strong"
            );

        if (scoreStrong) {

            scoreStrong.innerHTML = `
                ${score}
                <small>/100</small>
            `;
        }


        // ------------------------------------
        // RISK LEVEL
        // ------------------------------------

        const levelElement =
            card.querySelector(
                ".analysis-score b"
            );

        if (levelElement) {

            levelElement.textContent =
                `● ${getScoreLevel(score)}`;

            setTextLevelClass(
                levelElement,
                score
            );
        }


        // ------------------------------------
        // TECHNICAL REASONING
        // ------------------------------------

        const reason =
            card.querySelector(
                ".reason p"
            );

        if (reason) {

            reason.textContent =
                reasoning;
        }

    });


    // Add Header analysis card
    addMissingHeaderAnalysisCard(
        scores,
        moduleAnalysis
    );
}


// ============================================================
// 14. ADD HEADER ANALYSIS CARD
// ============================================================

function addMissingHeaderAnalysisCard(
    scores,
    moduleAnalysis
) {

    const existing =
        findElementByHeading(
            ".analysis-card",
            "Header Forensics"
        );

    if (existing) {
        return;
    }


    const grid =
        document.querySelector(
            ".analysis-grid"
        );

    if (!grid) {
        return;
    }


    const score =
        Number(
            scores.header || 0
        );


    const reasoning =
        moduleAnalysis?.header
            ?.technicalReasoning ||
        "No significant header anomalies detected.";


    const card =
        document.createElement(
            "article"
        );

    card.className =
        "analysis-card dynamic-header-analysis";


    card.innerHTML = `
        <div class="analysis-header">

            <div class="module-icon header">
                HF
            </div>

            <div>
                <h3>Header Forensics</h3>
                <span>ANALYSIS MODULE 02</span>
            </div>

            <div class="arrow">
                ↗
            </div>

        </div>


        <div class="analysis-score">

            <div>
                <span>RISK SCORE</span>

                <strong>
                    ${score}
                    <small>/100</small>
                </strong>
            </div>


            <div>
                <span>RISK LEVEL</span>

                <b>
                    ● ${getScoreLevel(score)}
                </b>
            </div>

        </div>


        <div class="reason">

            <span>
                ⓘ &nbsp; TECHNICAL REASONING
            </span>

            <p>
                ${escapeHtml(reasoning)}
            </p>

        </div>
    `;


    const mlCard =
        findElementByHeading(
            ".analysis-card",
            "ML Analysis"
        );


    if (mlCard) {

        mlCard.insertAdjacentElement(
            "afterend",
            card
        );

    } else {

        grid.prepend(card);
    }


    const levelElement =
        card.querySelector(
            ".analysis-score b"
        );

    if (levelElement) {

        setTextLevelClass(
            levelElement,
            score
        );
    }
}


// ============================================================
// 15. FINAL ASSESSMENT
// ============================================================

function updateFinalAssessment(
    score,
    classification,
    riskLevel,
    moduleAnalysis
) {

    // Final score
    const finalNumber =
        document.querySelector(
            ".final-number"
        );

    if (finalNumber) {

        finalNumber.innerHTML = `
            ${score}
            <small>/100</small>
        `;
    }


    // Classification
    const finalClassification =
        document.querySelector(
            ".final-score-row div:first-child strong"
        );

    if (finalClassification) {

        finalClassification.textContent =
            classification;
    }


    // Dynamic conclusion
    const finalReason =
        document.querySelector(
            ".final-reason p"
        );

    if (finalReason) {

        finalReason.textContent =
            buildFinalReason(
                score,
                classification,
                riskLevel,
                moduleAnalysis
            );
    }
}


// ============================================================
// 16. FINAL REASONING
// ============================================================

function buildFinalReason(
    score,
    classification,
    riskLevel,
    moduleAnalysis
) {

    const activeModules = [];


    MODULES.forEach(module => {

        const moduleData =
            moduleAnalysis?.[module.key];

        const scoreValue =
            Number(
                moduleData?.riskScore || 0
            );

        if (scoreValue > 0) {

            activeModules.push(
                module.name
            );
        }

    });


    let reason =
        `ThreatLens classified this email as ${classification} ` +
        `with a final risk score of ${score}/100 ` +
        `(${riskLevel}). `;


    if (activeModules.length > 0) {

        reason +=
            `The assessment reflects risk contributions from ` +
            `${activeModules.join(", ")}. `;

    }


    reason +=
        `The final score is based on the weighted combination ` +
        `of independent ThreatLens analysis modules.`;


    return reason;
}


// ============================================================
// 17. RECOMMENDED ACTIONS
// ============================================================

function updateRecommendedActions(
    classification,
    riskLevel
) {

    const actions =
        document.querySelectorAll(
            ".action-item p"
        );


    if (!actions.length) {
        return;
    }


    if (classification === "PHISHING") {

        setAction(
            actions[0],
            "Treat the email as potentially malicious and avoid interacting with it."
        );

        setAction(
            actions[1],
            "Do not open suspicious links, QR codes, attachments or credential prompts."
        );

        setAction(
            actions[2],
            "Escalate the case for further investigation and forensic review."
        );

        return;
    }


    if (classification === "SUSPICIOUS") {

        setAction(
            actions[0],
            "Treat the email with caution until the suspicious indicators are reviewed."
        );

        setAction(
            actions[1],
            "Avoid interacting with embedded links, QR codes or unexpected attachments."
        );

        setAction(
            actions[2],
            "Escalate the case for further investigation if required."
        );

        return;
    }


    // LEGITIMATE

    setAction(
        actions[0],
        "No immediate malicious activity was identified by the ThreatLens risk engine."
    );

    setAction(
        actions[1],
        "Continue normal email handling while following standard security practices."
    );

    setAction(
        actions[2],
        "No escalation is required unless additional evidence becomes available."
    );
}


function setAction(
    element,
    text
) {

    if (element) {
        element.textContent =
            text;
    }
}


// ============================================================
// 18. SCORE LEVEL
// ============================================================

function getScoreLevel(score) {

    score =
        Number(score || 0);


    if (score >= 75) {
        return "CRITICAL";
    }

    if (score >= 60) {
        return "HIGH";
    }

    if (score >= 30) {
        return "MEDIUM";
    }

    return "LOW";
}


// ============================================================
// 19. CSS CLASS HELPERS
// ============================================================

function setLevelClass(
    element,
    score
) {

    if (!element) {
        return;
    }


    element.classList.remove(
        "low",
        "medium",
        "high",
        "critical"
    );


    const level =
        getScoreLevel(score);


    element.classList.add(
        level.toLowerCase()
    );
}


function setCardLevel(
    card,
    score
) {

    if (!card) {
        return;
    }


    card.classList.remove(
        "low-card",
        "medium-card",
        "high-card",
        "critical-card"
    );


    const level =
        getScoreLevel(score);


    card.classList.add(
        `${level.toLowerCase()}-card`
    );
}


function setTextLevelClass(
    element,
    score
) {

    if (!element) {
        return;
    }


    element.classList.remove(
        "low-text",
        "medium-text",
        "high-text",
        "critical-text"
    );


    const level =
        getScoreLevel(score);


    element.classList.add(
        `${level.toLowerCase()}-text`
    );
}


function applyRiskClass(
    element,
    value
) {

    if (!element) {
        return;
    }


    element.classList.remove(
        "legitimate",
        "suspicious",
        "phishing",
        "low",
        "medium",
        "high",
        "critical"
    );


    const normalized =
        String(value)
            .toUpperCase();


    if (normalized === "PHISHING") {

        element.classList.add(
            "phishing"
        );

    } else if (
        normalized === "SUSPICIOUS"
    ) {

        element.classList.add(
            "suspicious"
        );

    } else {

        element.classList.add(
            "legitimate"
        );
    }
}


function getStatusClass(
    classification
) {

    if (
        classification ===
        "PHISHING"
    ) {
        return "danger";
    }

    if (
        classification ===
        "SUSPICIOUS"
    ) {
        return "warning";
    }

    return "safe";
}


// ============================================================
// 20. MODULE NAME MATCHING
// ============================================================

function findModuleByName(
    name
) {

    const normalized =
        String(name)
            .toLowerCase()
            .trim();


    return MODULES.find(
        module => {

            const moduleName =
                module.name
                    .toLowerCase();


            return (
                normalized.includes(
                    moduleName
                ) ||
                moduleName.includes(
                    normalized
                )
            );
        }
    );
}


// ============================================================
// 21. FIND ELEMENT BY HEADING
// ============================================================

function findElementByHeading(
    selector,
    heading
) {

    const elements =
        document.querySelectorAll(
            selector
        );


    const target =
        heading
            .toLowerCase()
            .trim();


    for (
        const element of elements
    ) {

        const h3 =
            element.querySelector(
                "h3"
            );

        if (!h3) {
            continue;
        }


        const text =
            h3.textContent
                .toLowerCase()
                .trim();


        if (text === target) {

            return element;
        }
    }


    return null;
}


// ============================================================
// 22. DATE FORMAT
// ============================================================

function formatDateTime(
    value
) {

    if (!value) {

        return new Date()
            .toLocaleString(
                "en-GB",
                {
                    day: "2-digit",
                    month: "short",
                    year: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                    timeZone: "UTC"
                }
            )
            .toUpperCase() +
            " UTC";
    }


    const date =
        new Date(value);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return "N/A";
    }


    return (
        date
            .toLocaleString(
                "en-GB",
                {
                    day: "2-digit",
                    month: "short",
                    year: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                    timeZone: "UTC"
                }
            )
            .toUpperCase() +
        " UTC"
    );
}


// ============================================================
// 23. HTML ESCAPE
// ============================================================

function escapeHtml(
    value
) {

    const div =
        document.createElement(
            "div"
        );

    div.textContent =
        value || "";

    return div.innerHTML;
}


// ============================================================
// 24. ERROR DISPLAY
// ============================================================

function showReportError(
    message
) {

    console.error(
        "ThreatLens:",
        message
    );


    const reportPage =
        document.querySelector(
            ".report-page"
        );


    if (!reportPage) {
        return;
    }


    const error =
        document.createElement(
            "div"
        );


    error.style.cssText = `
        margin: 20px;
        padding: 16px 20px;
        border: 1px solid rgba(255,80,80,.4);
        background: rgba(255,60,60,.08);
        color: #ff8080;
        border-radius: 10px;
        font-family: Inter, sans-serif;
    `;


    error.innerHTML = `
        <strong>
            ThreatLens Report Error
        </strong>
        <br>
        <span>
            ${escapeHtml(message)}
        </span>
    `;


    reportPage.prepend(
        error
    );
}


// ============================================================
// 25. START REPORT
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        fetchCaseReport();

    }
);