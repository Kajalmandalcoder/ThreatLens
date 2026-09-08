// ==========================================
// ANALYSIS RESULT
// ==========================================

document.addEventListener("DOMContentLoaded", async () => {

    // ==========================================
    // GET EMAIL ID FROM URL
    // ==========================================

    const params = new URLSearchParams(window.location.search);
    const emailId = params.get("id");

    if (!emailId) {
        console.error("❌ Email ID missing from URL");
        return;
    }


    // ==========================================
    // GET AUTH TOKEN
    // ==========================================

    const token = localStorage.getItem("token");

    if (!token) {
        console.error("❌ Authentication token missing");
        return;
    }


    // ==========================================
    // FETCH EMAIL DATA
    // ==========================================

    try {

        const response = await fetch(
            `http://localhost:5001/api/emails/${encodeURIComponent(emailId)}`,
            {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            }
        );

        if (!response.ok) {
            throw new Error(
                `API request failed: ${response.status}`
            );
        }

        const result = await response.json();

        console.log("📦 Analysis Result:", result);

        if (!result.success || !result.data) {
            console.error(
                "❌ Email data not found",
                result
            );
            return;
        }

        const email = result.data;


        // ==========================================
        // RENDER PAGE
        // ==========================================

        renderResult(email);

        renderFindings(email);

        renderActions(email);

        renderTechnicalSummary(email);


        // ==========================================
        // LUCIDE ICONS
        // ==========================================

        if (window.lucide) {
            lucide.createIcons();
        }

    } catch (error) {

        console.error(
            "❌ Failed to load analysis result:",
            error
        );

    }


    // ==========================================
    // TECHNICAL SUMMARY TOGGLE
    // ==========================================

    setupTechnicalSummaryToggle();

});


// ==================================================
// RENDER MAIN RESULT
// ==================================================

function renderResult(email) {

    const ml = email.mlAnalysis || {};

    console.log("🤖 ML ANALYSIS:", ml);

    // ==========================================
    // GET ML VALUES
    // ==========================================

    const riskScore = Number(
        ml.threatScore ??
        ml.threat_score ??
        ml.score ??
        0
    );

    const confidence = Number(
        ml.confidence ??
        ml.confidenceScore ??
        ml.confidence_score ??
        0
    );

    const riskLevel = String(
        ml.riskLevel ??
        ml.risk_level ??
        getRiskLevel(riskScore) ??
        "UNKNOWN"
    ).toUpperCase();

    const resultHero =
        document.getElementById("resultHero");

    if (resultHero) {

        resultHero.classList.remove(
            "risk-high",
            "risk-medium",
            "risk-low",
            "risk-unknown"
        );

        resultHero.classList.add(
            getRiskClass(riskLevel)
        );
    }

    const prediction =
        ml.prediction ??
        ml.label ??
        "UNKNOWN";


    // ==========================================
    // RISK SCORE
    // ==========================================

    const riskScoreElement =
        document.getElementById("resultRiskScore");

    if (riskScoreElement) {

        riskScoreElement.innerHTML =
            `${Math.round(riskScore)} <small>/ 100</small>`;

    }


    // ==========================================
    // RISK BADGE
    // ==========================================

    const badge =
        document.querySelector(".risk-badge");

    if (badge) {

        badge.className =
            `risk-badge ${getRiskClass(riskLevel)}`;

        badge.innerHTML = `
            <span></span>
            ${formatRiskLevel(riskLevel)}
        `;

    }


    // ==========================================
    // CONFIDENCE
    // ==========================================

    const confidenceElement =
        document.getElementById("resultConfidence");

    if (confidenceElement) {

        confidenceElement.textContent =
            getConfidenceLabel(confidence);

    }


    // ==========================================
    // SUBJECT
    // ==========================================

    const subjectElement =
        document.getElementById("resultSubject");

    if (subjectElement) {

        subjectElement.textContent =
            email.headers?.subject ||
            "No subject";

    }


    // ==========================================
    // THREAT CATEGORY
    // ==========================================

    const categoryElement =
        document.getElementById("resultThreatCategory");

    if (categoryElement) {

        categoryElement.textContent =
            getThreatCategory(prediction);

    }


    // ==========================================
    // MAIN HEADING
    // ==========================================

    const titleElement =
        document.getElementById("resultTitle");

    if (titleElement) {

        titleElement.textContent =
            getResultMessage(prediction);

    }

}


// ==================================================
// DYNAMIC FINDINGS
// ==================================================

function renderFindings(email) {

    const reasons =
        email.mlAnalysis?.technicalReasons || [];

    const findingGrid =
        document.getElementById("findingGrid");

    if (!findingGrid) {

        console.error(
            "❌ findingGrid not found in HTML"
        );

        return;
    }

    findingGrid.innerHTML = "";


    // ==========================================
    // NO FINDINGS
    // ==========================================

    if (!Array.isArray(reasons) || reasons.length === 0) {

        findingGrid.innerHTML = `
            <div class="finding-card">

                <div class="finding-icon">
                    <i data-lucide="check-circle"></i>
                </div>

                <div>
                    <h3>No major threat indicators found</h3>

                    <p>
                        No significant threat indicators were
                        identified during the analysis.
                    </p>
                </div>

            </div>
        `;

        if (window.lucide) {
            lucide.createIcons();
        }

        return;
    }


    // ==========================================
    // CREATE FINDING CARDS
    // ==========================================

    reasons.forEach((reason) => {

        let code = "Threat indicator";

        let description =
            "This indicator contributed to the overall threat assessment.";

        if (typeof reason === "string") {

            const separator =
                reason.indexOf(":");

            if (separator !== -1) {

                code =
                    reason
                        .substring(0, separator)
                        .trim();

                description =
                    reason
                        .substring(separator + 1)
                        .trim();

            } else {

                code =
                    reason.trim();

            }

        }

        const card =
            document.createElement("div");

        card.className =
            "finding-card";

        card.innerHTML = `
            <div class="finding-icon">
                <i data-lucide="triangle-alert"></i>
            </div>

            <div>
                <h3>
                    ${escapeHtml(formatReason(code))}
                </h3>

                <p>
                    ${escapeHtml(description)}
                </p>
            </div>
        `;

        findingGrid.appendChild(card);

    });

    if (window.lucide) {
        lucide.createIcons();
    }

}


function renderActions(email) {

    const actions =
        email.mlAnalysis?.recommendedActions || [];

    const actionGrid =
        document.querySelector(".action-grid");

    if (!actionGrid) {
        console.error("❌ .action-grid not found in HTML");
        return;
    }

    actionGrid.innerHTML = "";

    if (!Array.isArray(actions) || actions.length === 0) {

        actionGrid.innerHTML = `
            <div class="action-item safe">
                <span class="action-mark">✓</span>

                <span class="action-text">
                    No specific action is required based on
                    the available analysis.
                </span>
            </div>
        `;

        return;
    }

    actions.forEach((action, index) => {

        let text = "";

        if (typeof action === "string") {
            text = action;
        } else {
            text =
                action.action ||
                action.description ||
                action.message ||
                "Review this recommendation.";
        }

        const actionItem =
            document.createElement("div");

        // Last action = positive green action
        const isPositive =
            index === actions.length - 1;

        actionItem.className =
            isPositive
                ? "action-item safe"
                : "action-item danger";

        actionItem.innerHTML = `
            <span class="action-mark">
                ${isPositive ? "✓" : "×"}
            </span>

            <span class="action-text">
                ${escapeHtml(text)}
            </span>
        `;

        actionGrid.appendChild(actionItem);
    });
}

function renderTechnicalSummary(email) {

    const container =
        document.getElementById("technicalSummaryContent");

    if (!container) {
        console.error("❌ technicalSummaryContent not found");
        return;
    }

    const headers = email.headers || {};
    const hf = email.headerForensics || {};
    const auth = hf.authentication_matrix || {};

    const domain = email.domainIntelligence || {};
    const ip = email.ipIntelligence || {};
    const url = email.urlIntelligence || {};
    const attachment = email.attachmentIntelligence || {};
    const journey = email.emailJourney || {};
    const ml = email.mlAnalysis || {};

    // ==============================
    // AUTHENTICATION
    // ==============================

    const spf =
        auth.spf_status ||
        auth.spf ||
        hf.spf ||
        "Unavailable";

    const dkim =
        auth.dkim_status ||
        auth.dkim ||
        hf.dkim ||
        "Unavailable";

    const dmarc =
        auth.dmarc_status ||
        auth.dmarc ||
        hf.dmarc ||
        "Unavailable";


    // ==============================
    // URL COUNT
    // ==============================

    const urlCount =
        url.summary?.total ??
        url.summary?.total_urls ??
        url.total_urls ??
        url.urls?.length ??
        email.links?.length ??
        0;


    // ==============================
    // ATTACHMENT COUNT
    // ==============================

    const attachmentCount =
        attachment.summary?.total ??
        attachment.total_attachments ??
        attachment.attachments?.length ??
        email.attachments?.length ??
        0;


    // ==============================
    // JOURNEY
    // ==============================

    const hopCount =
        journey.hops?.length ??
        journey.total_hops ??
        hf.network_hops?.total ??
        0;


    // ==============================
    // SCORES
    // ==============================

    const domainScore =
        Number(domain.risk_score ?? 0);

    const ipScore =
        Number(ip.risk_score ?? 0);

    const mlScore =
        Number(ml.threatScore ?? 0);


    // ==============================
    // SENDER VERIFICATION
    // ==============================

    let senderVerification = "Passed";

    if (
        hf.identity?.is_spoofed === true ||
        hf.identity?.isSpoofed === true
    ) {
        senderVerification = "Failed";
    }

    if (
        domain.signals?.return_path_mismatch === true ||
        hf.anomaly?.return_path_mismatch === true
    ) {
        senderVerification = "Review required";
    }


    // ==============================
    // RENDER CONTENT
    // ==============================

    container.innerHTML = `

        <div class="technical-item">
            <span>Sender verification</span>
            <strong>
                ${escapeHtml(senderVerification)}
            </strong>
        </div>


        <div class="technical-item">
            <span>ML threat score</span>
            <strong>
                ${Math.round(mlScore)}/100
            </strong>
        </div>


        <div class="technical-item">
            <span>Domain risk</span>
            <strong>
                ${Math.round(domainScore)}/100
            </strong>
        </div>


        <div class="technical-item">
            <span>IP risk</span>
            <strong>
                ${Math.round(ipScore)}/100
            </strong>
        </div>


        <div class="technical-item">
            <span>Suspicious links</span>
            <strong>
                ${urlCount} detected
            </strong>
        </div>


        <div class="technical-item">
            <span>Attachments</span>
            <strong>
                ${attachmentCount} detected
            </strong>
        </div>


        <div class="technical-item">
            <span>Authentication</span>
            <strong>
                SPF: ${escapeHtml(String(spf))}
                /
                DKIM: ${escapeHtml(String(dkim))}
                /
                DMARC: ${escapeHtml(String(dmarc))}
            </strong>
        </div>


        <div class="technical-item">
            <span>Email journey</span>
            <strong>
                ${
                    hopCount > 0
                        ? `${hopCount} hops`
                        : "Unavailable"
                }
            </strong>
        </div>


        <div class="technical-item">
            <span>Threat classification</span>
            <strong>
                ${escapeHtml(
                    getThreatCategory(ml.prediction)
                )}
            </strong>
        </div>

    `;

}

function getRiskClass(riskLevel) {

    const level =
        String(riskLevel || "").toUpperCase();

    if (
        level === "CRITICAL" ||
        level === "HIGH"
    ) {
        return "risk-high";
    }

    if (level === "MEDIUM") {
        return "risk-medium";
    }

    if (level === "LOW") {
        return "risk-low";
    }

    return "risk-unknown";
}

// ==================================================
// TECHNICAL SUMMARY TOGGLE
// ==================================================

function setupTechnicalSummaryToggle() {

    const toggle =
        document.getElementById(
            "technicalSummaryToggle"
        );

    const content =
        document.getElementById(
            "technicalSummaryContent"
        );

    const icon =
        document.getElementById(
            "technicalSummaryIcon"
        );

    const text =
        document.getElementById(
            "technicalSummaryText"
        );


    if (!toggle || !content) {

        console.error(
            "❌ Technical Summary elements not found"
        );

        return;
    }


    // ==========================================
    // INITIAL STATE = CLOSED
    // ==========================================

    content.hidden = true;


    // ==========================================
    // CLICK
    // ==========================================

    toggle.addEventListener("click", () => {

        const willOpen =
            content.hidden;

        content.hidden =
            !willOpen;


        toggle.classList.toggle(
            "active",
            willOpen
        );


        // ==========================================
        // ICON ROTATION
        // ==========================================

        if (icon) {

            icon.style.transform =
                willOpen
                    ? "rotate(180deg)"
                    : "rotate(0deg)";

        }


        // ==========================================
        // TEXT
        // ==========================================

        if (text) {

            text.textContent =
                willOpen
                    ? "Hide technical summary"
                    : "View technical summary";

        }


        console.log(
            willOpen
                ? "📂 Technical Summary opened"
                : "📁 Technical Summary closed"
        );

    });

}


// ==================================================
// SENDER VERIFICATION
// ==================================================

function getSenderVerification(email) {

    const identity =
        email.headerForensics?.identity || {};

    const anomalies =
        email.headerForensics?.anomalies || [];

    if (
        identity.is_spoofed === true ||
        identity.isSpoofed === true
    ) {
        return "Failed";
    }

    if (
        Array.isArray(anomalies) &&
        anomalies.length > 0
    ) {
        return "Review required";
    }

    return "Passed";

}


// ==================================================
// CONFIDENCE
// ==================================================

function getConfidenceLabel(score) {

    if (score >= 75) {
        return "High";
    }

    if (score >= 50) {
        return "Medium";
    }

    return "Low";

}


// ==================================================
// RISK LEVEL
// ==================================================

function getRiskLevel(score) {

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


// ==================================================
// FORMAT RISK LEVEL
// ==================================================

function formatRiskLevel(level) {

    if (!level) {
        return "Unknown";
    }

    return String(level)
        .replace(/_/g, " ")
        .replace(
            /\b\w/g,
            char => char.toUpperCase()
        );

}


// ==================================================
// THREAT CATEGORY
// ==================================================

function getThreatCategory(prediction) {

    const value =
        String(prediction || "")
            .toUpperCase();

    if (value === "PHISHING") {
        return "Possible Phishing";
    }

    if (value === "SUSPICIOUS") {
        return "Suspicious Activity";
    }

    if (value === "THREAT") {
        return "Potential Threat";
    }

    if (value === "LEGITIMATE") {
        return "Legitimate Email";
    }

    if (value === "SAFE") {
        return "Safe Email";
    }

    return "Threat Detected";

}


// ==================================================
// RESULT MESSAGE
// ==================================================

function getResultMessage(prediction) {

    const value =
        String(prediction || "")
            .toUpperCase();

    if (
        value === "PHISHING" ||
        value === "THREAT" ||
        value === "SUSPICIOUS"
    ) {
        return "This email appears suspicious.";
    }

    if (
        value === "LEGITIMATE" ||
        value === "SAFE"
    ) {
        return "This email appears safe.";
    }

    return "Analysis completed.";

}


// ==================================================
// FORMAT TECHNICAL REASON
// ==================================================

function formatReason(code) {

    const map = {

        RETURN_PATH_MISMATCH:
            "Return-Path mismatch",

        DMARC_FAILURE:
            "DMARC authentication failed",

        SUSPICIOUS_URL:
            "Suspicious URL detected",

        VPN_PROXY_ORIGIN:
            "VPN / proxy origin detected",

        HOSTING_ORIGIN:
            "Hosting infrastructure detected",

        SPF_FAILURE:
            "SPF authentication failed",

        DKIM_FAILURE:
            "DKIM authentication failed",

        DOMAIN_MISMATCH:
            "Domain mismatch detected",

        REPLY_TO_MISMATCH:
            "Reply-To mismatch",

        ATTACHMENT_RISK:
            "Risky attachment detected"

    };

    return map[code] ||

        String(code)
            .replace(/_/g, " ")
            .toLowerCase()
            .replace(
                /\b\w/g,
                char => char.toUpperCase()
            );

}


// ==================================================
// HTML ESCAPE
// ==================================================

function escapeHtml(value) {

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