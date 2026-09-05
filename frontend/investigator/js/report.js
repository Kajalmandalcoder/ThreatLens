document.addEventListener("DOMContentLoaded", async () => {

    lucide.createIcons();

    const params = new URLSearchParams(window.location.search);
    const emailId = params.get("id");

    console.log("📄 Report Email ID:", emailId);

    if (!emailId) {
        showError("No case ID provided.");
        return;
    }

    setupButtons(emailId);
    startReportClock();

    try {

        const response = await fetch(
            `http://localhost:5001/api/emails/${encodeURIComponent(emailId)}`
        );

        console.log("📡 Report API status:", response.status);

        const result = await response.json();

        console.log("📦 Report API response:", result);

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Failed to fetch case data"
            );
        }

        const email = result.data;

        console.log("✅ Case data loaded:", email);

        renderReport(email);

    } catch (error) {

        console.error("❌ Report loading error:", error);

        showError(error.message);
    }
});


// =====================================================
// MAIN RENDER
// =====================================================

function renderReport(email) {

    const headers = email.headers || {};
    const ml = email.mlAnalysis || {};
    const header = email.headerForensics || {};
    const url = email.urlIntelligence || {};
    const domain = email.domainIntelligence || {};
    const ip = email.ipIntelligence || {};
    const attachment = email.attachmentIntelligence || {};

    const auth = header.authentication_matrix || {};
    const identity = header.identity_analysis || {};

    const urlSummary = url.summary || {};
    const attachmentSummary = attachment.summary || {};
    const routing = ip.routing_summary || {};
    const originIP = ip.origin_ip_data || {};
    const domainData = domain.domains || {};
    const alignment = domain.identity_alignment || {};
    const signals = domain.signals || {};
    const lookalike = domain.lookalike_analysis || {};

    // -------------------------------------------------
    // SCORES
    // -------------------------------------------------

    const headerScore = Number(header.header_risk_score || 0);

    const urlMaxScore = Number(
        urlSummary.max_risk_score || 0
    );

    const attachmentMaxScore = Number(
        attachmentSummary.max_attachment_risk_score || 0
    );

    const mlConfidence = normalizeConfidence(
        ml.confidence
    );

    const mlScore = mlConfidence;

    const ipScore = calculateIPScore(ip);
    const domainScore = calculateDomainScore(domain);

    const compositeScore = Math.round(
        Math.max(
            mlScore,
            headerScore,
            urlMaxScore,
            attachmentMaxScore,
            ipScore,
            domainScore
        )
    );

    const risk = getRiskLevel(compositeScore);

    // -------------------------------------------------
    // CASE INFORMATION
    // -------------------------------------------------

    setText(
        "case-id",
        email.caseId || `CASE-${email._id || "UNKNOWN"}`
    );

    setText(
        "footer-case-id",
        email.caseId || "--------"
    );

    setText(
        "analysis-date",
        formatDate(email.createdAt || headers.date)
    );

    setText(
        "report-from-domain",
        domainData.from_domain || extractDomain(headers.from)
    );

    setText(
        "report-subject",
        headers.subject || "—"
    );

    setText(
        "report-reply",
        identity.reply_to_domain ||
        domainData.reply_to_domain ||
        extractDomain(headers.replyTo) ||
        "—"
    );

    setText(
        "report-date",
        formatDate(headers.date)
    );

    setText(
        "report-return",
        domainData.return_path_domain ||
        identity.return_path_domain ||
        "—"
    );

    setText(
        "report-total-urls",
        getTotalUrls(url)
    );

    setText(
        "report-total-attachments",
        attachmentSummary.total_attachments || 0
    );


    // -------------------------------------------------
    // EXECUTIVE SUMMARY
    // -------------------------------------------------

    setText(
        "composite-score",
        compositeScore
    );

    setText(
        "final-score",
        compositeScore
    );

    setText(
        "threat-level",
        risk
    );

    setText(
        "final-risk",
        risk
    );

    setText(
        "executive-verdict",
        risk === "HIGH" || risk === "CRITICAL"
            ? "THREAT DETECTED"
            : risk === "MEDIUM"
                ? "SUSPICIOUS"
                : "LOW RISK"
    );

    setText(
        "top-verdict",
        risk
    );

    setText(
        "recommended-action",
        getPrimaryAction(risk)
    );

    setText(
        "primary-action",
        getPrimaryAction(risk)
    );

    setText(
        "executive-description",
        getExecutiveDescription(
            risk,
            ml.prediction,
            compositeScore
        )
    );

    const scoreFill =
        document.getElementById("composite-score-fill");

    if (scoreFill) {
        scoreFill.style.width =
            `${Math.min(compositeScore, 100)}%`;
    }


    // -------------------------------------------------
    // ML
    // -------------------------------------------------

    setText(
        "ml-confidence",
        ml.confidence != null
            ? `${Math.round(mlConfidence)}%`
            : "NOT AVAILABLE"
    );

    setText(
        "overview-ml",
        ml.prediction || "N/A"
    );

    setText(
        "overview-ml-status",
        ml.confidence != null
            ? `${Math.round(mlConfidence)}% CONFIDENCE`
            : "NOT AVAILABLE"
    );


    // -------------------------------------------------
    // HEADER
    // -------------------------------------------------

    setText(
        "overview-header-score",
        headerScore
    );

    setText(
        "overview-header-status",
        getScoreRisk(headerScore)
    );

    setAuth(
        "report-spf",
        "spf-icon",
        "spf-line",
        auth.spf
    );

    setAuth(
        "report-dkim",
        "dkim-icon",
        "dkim-line",
        auth.dkim
    );

    setAuth(
        "report-dmarc",
        "dmarc-icon",
        "dmarc-line",
        auth.dmarc
    );


    // -------------------------------------------------
    // IP INTELLIGENCE
    // -------------------------------------------------

    const publicOrigin =
        routing.has_public_origin === true;

    const hosting =
        originIP.is_hosting === true;

    const proxy =
        originIP.is_proxy === true;

    setText(
        "overview-ip-score",
        ipScore
    );

    setText(
        "overview-ip-status",
        getScoreRisk(ipScore)
    );

    setText(
        "ip-origin-report",
        originIP.ip || "—"
    );

    setText(
        "ip-country-report",
        originIP.country || "—"
    );

    setText(
        "ip-city-report",
        originIP.city || "—"
    );

    setText(
        "ip-asn-report",
        originIP.asn || "—"
    );

    setText(
        "ip-provider-report",
        originIP.isp || "—"
    );

    setText(
        "ip-hosting-report",
        hosting ? "YES" : "NO"
    );

    setText(
        "ip-proxy-report",
        proxy ? "YES" : "NO"
    );

    setText(
        "ip-public-origin-report",
        publicOrigin ? "YES" : "NO"
    );

    setText(
        "ip-total-report",
        routing.total_extracted_ips || 0
    );

    setText(
        "ip-risk-report",
        getScoreRisk(ipScore)
    );


    // -------------------------------------------------
    // DOMAIN INTELLIGENCE
    // -------------------------------------------------

    setText(
        "domain-from-report",
        domainData.from_domain || "—"
    );

    setText(
        "domain-reply-report",
        domainData.reply_to_domain || "—"
    );

    setText(
        "domain-return-report",
        domainData.return_path_domain || "—"
    );

    setText(
        "domain-body-report",
        Array.isArray(domain.body_domains)
            ? domain.body_domains.join(", ")
            : "—"
    );

    setText(
        "domain-reply-match-report",
        alignment.from_matches_reply_to
            ? "MATCH"
            : "MISMATCH"
    );

    setText(
        "domain-return-match-report",
        alignment.from_matches_return_path
            ? "MATCH"
            : "MISMATCH"
    );

    setText(
        "domain-body-match-report",
        alignment.from_matches_body_links
            ? "MATCH"
            : "MISMATCH"
    );

    setText(
        "domain-lookalike-report",
        lookalike.is_lookalike
            ? `YES${lookalike.matched_brand
                ? ` (${lookalike.matched_brand})`
                : ""}`
            : "NO"
    );

    setText(
        "domain-mx-report",
        domain.dns_health?.from_has_mx
            ? "PRESENT"
            : "MISSING"
    );

    setText(
        "domain-risk-report",
        getScoreRisk(domainScore)
    );


    // -------------------------------------------------
    // URL INTELLIGENCE
    // -------------------------------------------------

    const totalUrls = getTotalUrls(url);

    setText(
        "overview-url-score",
        urlMaxScore
    );

    setText(
        "overview-url-status",
        urlSummary.overall_status || "LOW"
    );

    setText(
        "report-url-total",
        totalUrls
    );

    setText(
        "report-url-critical",
        urlSummary.critical_count || 0
    );

    setText(
        "report-url-high",
        urlSummary.high_count || 0
    );

    setText(
        "report-url-medium",
        urlSummary.medium_count || 0
    );

    setText(
        "report-url-low",
        urlSummary.low_count || 0
    );

    setText(
        "report-url-max",
        urlMaxScore
    );

    renderURLList(url);


    // -------------------------------------------------
    // ATTACHMENTS
    // -------------------------------------------------

    setText(
        "overview-attachment-score",
        attachmentMaxScore
    );

    setText(
        "overview-attachment-status",
        attachmentSummary.overall_status || "LOW"
    );

    setText(
        "report-attachment-total",
        attachmentSummary.total_attachments || 0
    );

    setText(
        "report-attachment-high",
        attachmentSummary.high_risk_count > 0
            ? "YES"
            : "NO"
    );

    setText(
        "report-attachment-executable",
        attachmentSummary.has_executable
            ? "YES"
            : "NO"
    );

    setText(
        "report-attachment-scripts",
        attachmentSummary.has_scripts_or_macros
            ? "YES"
            : "NO"
    );

    setText(
        "report-attachment-score",
        attachmentMaxScore
    );

    setText(
        "report-attachment-status",
        attachmentSummary.overall_status || "LOW"
    );

    renderAttachmentList(attachment);


    // -------------------------------------------------
    // FINAL MODULES
    // -------------------------------------------------

    setText(
        "final-ml",
        ml.prediction || "N/A"
    );

    setText(
        "final-header",
        getScoreRisk(headerScore)
    );

    setText(
        "final-ip",
        getScoreRisk(ipScore)
    );

    setText(
        "final-domain",
        getScoreRisk(domainScore)
    );

    setText(
        "final-url",
        urlSummary.overall_status || "LOW"
    );

    setText(
        "final-attachments",
        attachmentSummary.overall_status || "LOW"
    );

    setText(
        "final-conclusion",
        getFinalConclusion(
            risk,
            compositeScore
        )
    );


    // -------------------------------------------------
    // KEY FINDINGS
    // -------------------------------------------------

    renderKeyFindings(email);


    // -------------------------------------------------
    // SCORE CIRCLE
    // -------------------------------------------------

    const circle =
        document.getElementById("final-score-circle");

    if (circle) {
        circle.style.setProperty(
            "--score",
            `${compositeScore * 3.6}deg`
        );
    }


    lucide.createIcons();

    console.log("✅ Complete report rendered");
}


// =====================================================
// AUTHENTICATION
// =====================================================

function setAuth(valueId, iconId, lineId, value) {

    const status =
        String(value || "MISSING").toUpperCase();

    setText(valueId, status);

    const icon =
        document.getElementById(iconId);

    const line =
        document.getElementById(lineId);

    const passed =
        status === "PASS" ||
        status === "PASSED";

    if (icon) {
        icon.setAttribute(
            "data-lucide",
            passed ? "check" : "x"
        );
    }

    if (line) {
        line.classList.remove(
            "success-line",
            "warning-line",
            "fail-line"
        );

        line.classList.add(
            passed
                ? "success-line"
                : "warning-line"
        );
    }
}


// =====================================================
// KEY FINDINGS
// =====================================================

function renderKeyFindings(email) {

    const container =
        document.getElementById("key-findings");

    if (!container) return;

    const findings = [];

    const header =
        email.headerForensics || {};

    const domain =
        email.domainIntelligence || {};

    const ip =
        email.ipIntelligence || {};

    const url =
        email.urlIntelligence || {};

    const attachment =
        email.attachmentIntelligence || {};

    const ml =
        email.mlAnalysis || {};

    if (
        ml.prediction &&
        String(ml.prediction).toLowerCase() !== "benign"
    ) {
        findings.push(
            `ML model classified the email as ${ml.prediction}.`
        );
    }

    if (header.header_risk_score > 0) {
        findings.push(
            `Header forensics produced a risk score of ${header.header_risk_score}/100.`
        );
    }

    if (header.identity_analysis?.is_spoofed) {
        findings.push(
            "Sender identity shows signs of spoofing."
        );
    }

    if (domain.signals?.body_domain_mismatch) {
        findings.push(
            "Body/link domain differs from the sender domain."
        );
    }

    if (domain.lookalike_analysis?.is_lookalike) {
        findings.push(
            "A potential lookalike / brand impersonation domain was detected."
        );
    }

    if (url.summary?.max_risk_score > 0) {
        findings.push(
            `URL intelligence detected suspicious URL activity with a maximum score of ${url.summary.max_risk_score}.`
        );
    }

    if (ip.routing_summary?.has_public_origin) {
        if (ip.origin_ip_data?.is_hosting) {
            findings.push(
                "The originating IP belongs to a hosting/cloud provider."
            );
        }
    }

    if (
        attachment.summary?.overall_status &&
        attachment.summary.overall_status !== "LOW"
    ) {
        findings.push(
            `Attachment intelligence reports ${attachment.summary.overall_status} risk.`
        );
    }

    if (findings.length === 0) {
        findings.push(
            "No significant malicious indicators were identified by the available analysis modules."
        );
    }

    container.innerHTML = findings.map(
        (finding, index) => `
            <div class="finding-row">
                <div class="finding-icon info">
                    <i data-lucide="alert-circle"></i>
                </div>
                <span>${escapeHTML(finding)}</span>
            </div>
        `
    ).join("");

    lucide.createIcons();
}


// =====================================================
// URL LIST
// =====================================================

function renderURLList(urlData) {

    const container =
        document.getElementById("report-url-list");

    if (!container) return;

    const urls =
        urlData.urls ||
        urlData.results ||
        urlData.details ||
        [];

    if (!Array.isArray(urls) || urls.length === 0) {

        container.innerHTML = `
            <div class="finding-row">
                <div class="finding-icon info">
                    <i data-lucide="info"></i>
                </div>
                <span>No URLs available for detailed inspection.</span>
            </div>
        `;

        lucide.createIcons();

        return;
    }

    container.innerHTML = urls.map(
        item => {

            const url =
                typeof item === "string"
                    ? item
                    : item.url || item.original_url || "—";

            const score =
                item.risk_score ??
                item.score ??
                0;

            const status =
                item.risk_status ||
                item.status ||
                getScoreRisk(Number(score));

            return `
                <div class="report-url-row">
                    <strong>${escapeHTML(url)}</strong>
                    <span>${escapeHTML(String(status))}</span>
                    <small>Score: ${score}</small>
                </div>
            `;
        }
    ).join("");

    lucide.createIcons();
}


// =====================================================
// ATTACHMENT LIST
// =====================================================

function renderAttachmentList(data) {

    const container =
        document.getElementById(
            "report-attachment-list"
        );

    if (!container) return;

    const attachments =
        data.attachments || [];

    if (
        !Array.isArray(attachments) ||
        attachments.length === 0
    ) {

        container.innerHTML = `
            <div class="finding-row">
                <div class="finding-icon info">
                    <i data-lucide="info"></i>
                </div>
                <span>No attachments detected.</span>
            </div>
        `;

        lucide.createIcons();

        return;
    }

    container.innerHTML = attachments.map(
        item => {

            const name =
                item.filename ||
                item.name ||
                "Unknown attachment";

            const score =
                item.risk_score ??
                item.score ??
                0;

            const status =
                item.risk_status ||
                item.status ||
                getScoreRisk(Number(score));

            return `
                <div class="report-attachment-row">

                    <strong>
                        ${escapeHTML(name)}
                    </strong>

                    <span>
                        ${escapeHTML(String(status))}
                    </span>

                    <small>
                        Score: ${score}
                    </small>

                </div>
            `;
        }
    ).join("");

    lucide.createIcons();
}


// =====================================================
// BUTTONS
// =====================================================

function setupButtons(emailId) {

    const back =
        document.getElementById("backCaseBtn");

    if (back) {
        back.addEventListener("click", () => {
            window.location.href =
                `case_detail.html?id=${encodeURIComponent(emailId)}`;
        });
    }

    const print =
        document.getElementById("printReportBtn");

    if (print) {
        print.addEventListener(
            "click",
            () => window.print()
        );
    }

    const exportBtn =
        document.getElementById("exportReportBtn");

    if (exportBtn) {
        exportBtn.addEventListener(
            "click",
            () => {

                window.print();

            }
        );
    }
}


// =====================================================
// CLOCK
// =====================================================

function startReportClock() {

    const element =
        document.getElementById("report-time");

    if (!element) return;

    function update() {

        const now = new Date();

        element.textContent =
            "UTC " +
            now.toISOString()
                .split("T")[1]
                .split(".")[0];
    }

    update();

    setInterval(update, 1000);
}


// =====================================================
// HELPERS
// =====================================================

function setText(id, value) {

    const element =
        document.getElementById(id);

    if (element) {
        element.textContent =
            value === null ||
            value === undefined ||
            value === ""
                ? "—"
                : value;
    }
}


function extractDomain(value) {

    if (!value) return null;

    const match =
        String(value).match(
            /@([^>\s]+)/
        );

    return match
        ? match[1].trim()
        : null;
}


function formatDate(value) {

    if (!value) return "—";

    const date = new Date(value);

    if (isNaN(date.getTime())) {
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


function normalizeConfidence(value) {

    if (value === null || value === undefined) {
        return 0;
    }

    let number = Number(value);

    if (number <= 1) {
        number *= 100;
    }

    return Math.min(
        Math.max(number, 0),
        100
    );
}


function calculateIPScore(ip) {

    if (!ip || !ip.origin_ip_data) {
        return 0;
    }

    if (ip.origin_ip_data.is_proxy) {
        return 90;
    }

    if (ip.origin_ip_data.is_hosting) {
        return 60;
    }

    if (ip.routing_summary?.has_public_origin) {
        return 20;
    }

    return 0;
}


function calculateDomainScore(domain) {

    const signals =
        domain.signals || {};

    const lookalike =
        domain.lookalike_analysis || {};

    if (
        lookalike.is_lookalike ||
        signals.reply_to_mismatch ||
        signals.return_path_mismatch
    ) {
        return 90;
    }

    if (
        signals.body_domain_mismatch ||
        signals.from_missing_mx
    ) {
        return 50;
    }

    return 0;
}


function getTotalUrls(url) {

    return (
        url.summary?.total_urls ??
        url.total_urls ??
        url.urls?.length ??
        url.results?.length ??
        0
    );
}


function getScoreRisk(score) {

    score = Number(score || 0);

    if (score >= 80) return "CRITICAL";
    if (score >= 60) return "HIGH";
    if (score >= 40) return "MEDIUM";

    return "LOW";
}


function getRiskLevel(score) {

    score = Number(score || 0);

    if (score >= 80) return "CRITICAL";
    if (score >= 60) return "HIGH";
    if (score >= 40) return "MEDIUM";

    return "LOW";
}


function getPrimaryAction(risk) {

    if (risk === "CRITICAL") {
        return "QUARANTINE / BLOCK";
    }

    if (risk === "HIGH") {
        return "QUARANTINE EMAIL";
    }

    if (risk === "MEDIUM") {
        return "INVESTIGATE EMAIL";
    }

    return "REVIEW EMAIL";
}


function getExecutiveDescription(
    risk,
    prediction,
    score
) {

    if (risk === "CRITICAL") {
        return `The email demonstrates multiple high-confidence threat indicators. Composite analysis produced a score of ${score}/100. Immediate containment and investigation are recommended.`;
    }

    if (risk === "HIGH") {
        return `The email contains significant suspicious indicators. Composite analysis produced a score of ${score}/100 and requires investigation.`;
    }

    if (risk === "MEDIUM") {
        return `The email contains one or more suspicious signals. Further investigation is recommended before treating the message as benign.`;
    }

    return `Available forensic modules did not identify significant malicious indicators. Composite score: ${score}/100.`;
}


function getFinalConclusion(risk, score) {

    if (risk === "CRITICAL") {
        return `Final assessment: CRITICAL risk with a composite score of ${score}/100. Immediate containment is recommended.`;
    }

    if (risk === "HIGH") {
        return `Final assessment: HIGH risk with a composite score of ${score}/100. The email should be investigated and potentially quarantined.`;
    }

    if (risk === "MEDIUM") {
        return `Final assessment: MEDIUM risk with a composite score of ${score}/100. Additional investigation is recommended.`;
    }

    return `Final assessment: LOW risk with a composite score of ${score}/100. No immediate containment action is indicated.`;
}


function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function showError(message) {

    console.error("❌", message);

    const title =
        document.querySelector(".report-title-section h1");

    if (title) {
        title.textContent = "Unable to Load Report";
    }

    const description =
        document.getElementById("executive-description");

    if (description) {
        description.textContent = message;
    }

    setText(
        "executive-verdict",
        "ERROR"
    );

    setText(
        "top-verdict",
        "ERROR"
    );

    setText(
        "threat-level",
        "UNAVAILABLE"
    );
}