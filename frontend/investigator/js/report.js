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
// MAIN REPORT RENDER
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

    // =================================================
    // SCORE CALCULATION
    // =================================================

    const headerScore =
        Number(header.header_risk_score ?? 0);

    const urlMaxScore =
        Number(urlSummary.max_risk_score ?? 0);

    const attachmentMaxScore =
        Number(
            attachmentSummary.max_attachment_risk_score ?? 0
        );

    const mlConfidence =
        normalizeConfidence(ml.confidence);

    const mlScore =
        ml.confidence != null
            ? mlConfidence
            : 0;

    const ipScore =
        calculateIPScore(ip);

    const domainScore =
        calculateDomainScore(domain);

    const compositeScore =
        Math.round(
            Math.max(
                mlScore,
                headerScore,
                urlMaxScore,
                attachmentMaxScore,
                ipScore,
                domainScore
            )
        );

    const risk =
        getRiskLevel(compositeScore);


    console.log("📊 REPORT SCORES");
    console.log("ML:", mlScore);
    console.log("Header:", headerScore);
    console.log("IP:", ipScore);
    console.log("Domain:", domainScore);
    console.log("URL:", urlMaxScore);
    console.log("Attachment:", attachmentMaxScore);
    console.log("Composite:", compositeScore);
    console.log("Risk:", risk);


    // =================================================
    // CASE INFORMATION
    // =================================================

    setText(
        "case-id",
        email.caseId || "CASE-UNKNOWN"
    );

    setText(
        "footer-case-id",
        email.caseId || "--------"
    );

    setText(
        "analysis-date",
        formatDate(email.createdAt)
    );

    setText(
        "report-from-domain",
        domainData.from_domain ||
        extractDomain(headers.from) ||
        "—"
    );

    setText(
        "report-subject",
        headers.subject || "—"
    );

    const replyDomain =
        domainData.reply_to_domain ||
        identity.reply_to_domain ||
        extractDomain(headers.replyTo);

    setText(
        "report-reply",
        replyDomain || "—"
    );

    setText(
        "report-date",
        formatDate(headers.date)
    );

    setText(
        "report-return",
        domainData.return_path_domain ||
        identity.return_path_domain ||
        extractDomain(headers.returnPath) ||
        "—"
    );

    setText(
        "report-total-urls",
        getTotalUrls(url)
    );

    setText(
        "report-total-attachments",
        attachmentSummary.total_attachments ?? 0
    );


    // =================================================
    // EXECUTIVE SUMMARY
    // =================================================

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

    let verdict = "LOW RISK";

    if (risk === "CRITICAL" || risk === "HIGH") {
        verdict = "THREAT DETECTED";
    } else if (risk === "MEDIUM") {
        verdict = "SUSPICIOUS";
    }

    setText(
        "executive-verdict",
        verdict
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


    // =================================================
    // SCORE BAR
    // =================================================

    const scoreFill =
        document.getElementById(
            "composite-score-fill"
        );

    if (scoreFill) {
        scoreFill.style.width =
            `${Math.min(compositeScore, 100)}%`;
    }


    // =================================================
    // ML ANALYSIS
    // =================================================

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


    // =================================================
    // HEADER FORENSICS
    // =================================================

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


    // =================================================
    // IP INTELLIGENCE
    // =================================================

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
        routing.total_extracted_ips ?? 0
    );

    setText(
        "ip-risk-report",
        getScoreRisk(ipScore)
    );


    // =================================================
    // DOMAIN INTELLIGENCE
    // =================================================

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
        Array.isArray(domain.body_domains) &&
        domain.body_domains.length > 0
            ? domain.body_domains.join(", ")
            : "—"
    );


    // -----------------------------------------------
    // FROM ↔ REPLY-TO
    // -----------------------------------------------

    if (domainData.reply_to_domain) {

        setText(
            "domain-reply-match-report",
            alignment.from_matches_reply_to
                ? "MATCH"
                : "MISMATCH"
        );

    } else {

        setText(
            "domain-reply-match-report",
            "NOT AVAILABLE"
        );
    }


    // -----------------------------------------------
    // FROM ↔ RETURN PATH
    // -----------------------------------------------

    if (domainData.return_path_domain) {

        setText(
            "domain-return-match-report",
            alignment.from_matches_return_path
                ? "MATCH"
                : "MISMATCH"
        );

    } else {

        setText(
            "domain-return-match-report",
            "NOT AVAILABLE"
        );
    }


    // -----------------------------------------------
    // BODY DOMAIN MATCH
    // -----------------------------------------------

    setText(
        "domain-body-match-report",
        alignment.from_matches_body_links
            ? "MATCH"
            : "MISMATCH"
    );


    // -----------------------------------------------
    // LOOKALIKE
    // -----------------------------------------------

    setText(
        "domain-lookalike-report",
        lookalike.is_lookalike
            ? `YES${lookalike.matched_brand
                ? ` (${lookalike.matched_brand})`
                : ""}`
            : "NO"
    );


    // -----------------------------------------------
    // MX
    // -----------------------------------------------

    const hasMX =
        domain.dns_health?.from_has_mx;

    setText(
        "domain-mx-report",
        hasMX === true
            ? "PRESENT"
            : hasMX === false
                ? "MISSING"
                : "NOT AVAILABLE"
    );


    setText(
        "domain-risk-report",
        getScoreRisk(domainScore)
    );


    // =================================================
    // URL INTELLIGENCE
    // =================================================

    const totalUrls =
        getTotalUrls(url);

    const criticalUrls =
        Number(
            urlSummary.critical_risk_urls ??
            urlSummary.critical_count ??
            0
        );

    const highUrls =
        Number(
            urlSummary.high_risk_urls ??
            urlSummary.high_count ??
            0
        );

    const mediumUrls =
        Number(
            urlSummary.medium_risk_urls ??
            urlSummary.medium_count ??
            0
        );

    const lowUrls =
        Number(
            urlSummary.low_risk_urls ??
            urlSummary.low_count ??
            0
        );


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
        criticalUrls
    );

    setText(
        "report-url-high",
        highUrls
    );

    setText(
        "report-url-medium",
        mediumUrls
    );

    setText(
        "report-url-low",
        lowUrls
    );

    setText(
        "report-url-max",
        urlMaxScore
    );

    renderURLList(url);


    // =================================================
    // ATTACHMENT INTELLIGENCE
    // =================================================

    const totalAttachments =
        Number(
            attachmentSummary.total_attachments ??
            attachment.attachments?.length ??
            0
        );

    const hasHighRiskFiles =
        attachmentSummary.has_high_risk_files === true;

    const hasExecutableTypes =
        attachmentSummary.has_executable_types === true;

    const hasMacrosScripts =
        attachmentSummary.has_macros_or_scripts === true;


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
        totalAttachments
    );

    setText(
        "report-attachment-high",
        hasHighRiskFiles
            ? "YES"
            : "NO"
    );

    setText(
        "report-attachment-executable",
        hasExecutableTypes
            ? "YES"
            : "NO"
    );

    setText(
        "report-attachment-scripts",
        hasMacrosScripts
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


    // =================================================
    // FINAL RISK ASSESSMENT
    // =================================================

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


    // =================================================
    // KEY FINDINGS
    // =================================================

    renderKeyFindings(email);


    // =================================================
    // SCORE CIRCLE
    // =================================================

    const circle =
        document.getElementById(
            "final-score-circle"
        );

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

function setAuth(
    valueId,
    iconId,
    lineId,
    value
) {

    const status =
        String(
            value || "MISSING"
        ).toUpperCase();

    setText(
        valueId,
        status
    );

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
            passed
                ? "check"
                : "x"
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
        document.getElementById(
            "key-findings"
        );

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


    // ML
    if (
        ml.prediction &&
        String(ml.prediction)
            .toLowerCase() !== "benign"
    ) {

        findings.push(
            `ML model classified the email as ${ml.prediction}.`
        );
    }


    // Header
    if (
        Number(header.header_risk_score || 0) > 0
    ) {

        findings.push(
            `Header forensics produced a risk score of ${header.header_risk_score}/100.`
        );
    }


    // Spoofing
    if (
        header.identity_analysis?.is_spoofed
    ) {

        findings.push(
            "Sender identity shows signs of spoofing."
        );
    }


    // Domain mismatch
    if (
        domain.signals?.body_domain_mismatch
    ) {

        findings.push(
            "Body/link domain differs from the sender domain."
        );
    }


    // Lookalike
    if (
        domain.lookalike_analysis?.is_lookalike
    ) {

        findings.push(
            "A potential lookalike / brand impersonation domain was detected."
        );
    }


    // URL
    if (
        Number(
            url.summary?.max_risk_score || 0
        ) > 0
    ) {

        findings.push(
            `URL intelligence detected suspicious URL activity with a maximum score of ${url.summary.max_risk_score}.`
        );
    }


    // IP
    if (
        ip.routing_summary?.has_public_origin
    ) {

        if (
            ip.origin_ip_data?.is_proxy
        ) {

            findings.push(
                "The originating IP is associated with a proxy/VPN indicator."
            );

        } else if (
            ip.origin_ip_data?.is_hosting
        ) {

            findings.push(
                "The originating IP belongs to a hosting/cloud provider."
            );
        }
    }


    // Attachments
    if (
        attachment.summary?.has_high_risk_files
    ) {

        findings.push(
            "One or more attachments were classified as high risk."
        );
    }

    if (
        attachment.summary?.has_executable_types
    ) {

        findings.push(
            "Executable attachment types were detected."
        );
    }

    if (
        attachment.summary?.has_macros_or_scripts
    ) {

        findings.push(
            "Macros or embedded scripts were detected in attachments."
        );
    }


    if (findings.length === 0) {

        findings.push(
            "No significant malicious indicators were identified by the available analysis modules."
        );
    }


    container.innerHTML =
        findings.map(
            (finding) => `
                <div class="finding-row">

                    <div class="finding-icon info">
                        <i data-lucide="alert-circle"></i>
                    </div>

                    <span>
                        ${escapeHTML(finding)}
                    </span>

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
        document.getElementById(
            "report-url-list"
        );

    if (!container) return;

    const urls =
        urlData.urls ||
        urlData.results ||
        urlData.details ||
        [];


    if (
        !Array.isArray(urls) ||
        urls.length === 0
    ) {

        container.innerHTML = `
            <div class="finding-row">

                <div class="finding-icon info">
                    <i data-lucide="info"></i>
                </div>

                <span>
                    No URLs available for detailed inspection.
                </span>

            </div>
        `;

        lucide.createIcons();

        return;
    }


    container.innerHTML =
        urls.map(
            item => {

                const url =
                    typeof item === "string"
                        ? item
                        : item.url ||
                          item.original_url ||
                          "—";


                const score =
                    Number(
                        item.risk_score ??
                        item.score ??
                        0
                    );


                // IMPORTANT:
                // Backend has risk_level, not risk_status.
                const status =
                    item.risk_level ||
                    item.risk_status ||
                    (
                        score > 0
                            ? getScoreRisk(score)
                            : "LOW"
                    );


                return `
                    <div class="report-url-row">

                        <strong>
                            ${escapeHTML(url)}
                        </strong>

                        <span>
                            ${escapeHTML(
                                String(status)
                            )}
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

                <span>
                    No attachments detected.
                </span>

            </div>
        `;

        lucide.createIcons();

        return;
    }


    container.innerHTML =
        attachments.map(
            item => {

                const name =
                    item.filename ||
                    item.name ||
                    "Unknown attachment";


                const score =
                    Number(
                        item.risk_score ??
                        item.score ??
                        0
                    );


                const status =
                    item.risk_level ||
                    item.risk_status ||
                    (
                        score > 0
                            ? getScoreRisk(score)
                            : "LOW"
                    );


                return `
                    <div class="report-attachment-row">

                        <strong>
                            ${escapeHTML(name)}
                        </strong>

                        <span>
                            ${escapeHTML(
                                String(status)
                            )}
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

    // BACK TO CASE
    const back =
        document.getElementById(
            "backCaseBtn"
        );

    if (back) {

        back.addEventListener(
            "click",
            () => {

                window.location.href =
                    `case_detail.html?id=${encodeURIComponent(emailId)}`;
            }
        );
    }


    // PRINT
    const print =
        document.getElementById(
            "printReportBtn"
        );

    if (print) {

        print.addEventListener(
            "click",
            () => window.print()
        );
    }


    // EXPORT
    const exportBtn =
        document.getElementById(
            "exportReportBtn"
        );

    if (exportBtn) {

        exportBtn.addEventListener(
            "click",
            () => window.print()
        );
    }
}


// =====================================================
// CLOCK
// =====================================================

function startReportClock() {

    const element =
        document.getElementById(
            "report-time"
        );

    if (!element) return;


    function update() {

        const now =
            new Date();

        element.textContent =
            "UTC " +
            now.toISOString()
                .split("T")[1]
                .split(".")[0];
    }


    update();

    setInterval(
        update,
        1000
    );
}


// =====================================================
// HELPERS
// =====================================================

function setText(id, value) {

    const element =
        document.getElementById(id);

    if (!element) return;

    element.textContent =
        value === null ||
        value === undefined ||
        value === ""
            ? "—"
            : value;
}


// -----------------------------------------------------
// EXTRACT DOMAIN
// -----------------------------------------------------

function extractDomain(value) {

    if (!value) return null;

    const text =
        String(value);


    // Normal email
    const emailMatch =
        text.match(
            /@([^>\s]+)/ 
        );

    if (emailMatch) {

        return emailMatch[1]
            .trim()
            .replace(/[)>;,]+$/, "");
    }


    return null;
}


// -----------------------------------------------------
// FORMAT DATE
// -----------------------------------------------------

function formatDate(value) {

    if (!value) return "—";

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


// -----------------------------------------------------
// NORMALIZE ML CONFIDENCE
// -----------------------------------------------------

function normalizeConfidence(value) {

    if (
        value === null ||
        value === undefined
    ) {

        return 0;
    }


    let number =
        Number(value);


    if (
        !Number.isFinite(number)
    ) {

        return 0;
    }


    if (number <= 1) {

        number *= 100;
    }


    return Math.min(
        Math.max(number, 0),
        100
    );
}


// =====================================================
// IP SCORE
// =====================================================

function calculateIPScore(ip) {

    if (
        !ip ||
        !ip.origin_ip_data
    ) {

        return 0;
    }


    // Proxy / VPN = high
    if (
        ip.origin_ip_data.is_proxy
    ) {

        return 90;
    }


    // Hosting provider alone = medium
    if (
        ip.origin_ip_data.is_hosting
    ) {

        return 50;
    }


    // Public origin but no suspicious indicator
    if (
        ip.routing_summary?.has_public_origin
    ) {

        return 20;
    }


    return 0;
}


// =====================================================
// DOMAIN SCORE
// =====================================================

function calculateDomainScore(domain) {

    const signals =
        domain.signals || {};

    const lookalike =
        domain.lookalike_analysis || {};


    // Strong domain indicators
    if (
        lookalike.is_lookalike ||
        signals.reply_to_mismatch ||
        signals.return_path_mismatch
    ) {

        return 90;
    }


    // Moderate indicator
    if (
        signals.body_domain_mismatch ||
        signals.from_missing_mx
    ) {

        return 50;
    }


    return 0;
}


// =====================================================
// TOTAL URLS
// =====================================================

function getTotalUrls(url) {

    return (
        url.summary?.total_urls ??
        url.total_urls ??
        url.urls?.length ??
        url.results?.length ??
        0
    );
}


// =====================================================
// SCORE → RISK
// =====================================================

function getScoreRisk(score) {

    score =
        Number(score || 0);


    if (score >= 80) {
        return "CRITICAL";
    }

    if (score >= 60) {
        return "HIGH";
    }

    if (score >= 40) {
        return "MEDIUM";
    }

    return "LOW";
}


// =====================================================
// FINAL RISK
// =====================================================

function getRiskLevel(score) {

    return getScoreRisk(score);
}


// =====================================================
// RECOMMENDED ACTION
// =====================================================

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


// =====================================================
// EXECUTIVE DESCRIPTION
// =====================================================

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

        return `The email contains one or more suspicious signals. Composite analysis produced a score of ${score}/100. Further investigation is recommended before treating the message as benign.`;
    }


    return `Available forensic modules did not identify significant malicious indicators. Composite score: ${score}/100.`;
}


// =====================================================
// FINAL CONCLUSION
// =====================================================

function getFinalConclusion(
    risk,
    score
) {

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


// =====================================================
// ESCAPE HTML
// =====================================================

function escapeHTML(value) {

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


// =====================================================
// ERROR
// =====================================================

function showError(message) {

    console.error(
        "❌",
        message
    );


    const title =
        document.querySelector(
            ".report-title-section h1"
        );

    if (title) {

        title.textContent =
            "Unable to Load Report";
    }


    const description =
        document.getElementById(
            "executive-description"
        );

    if (description) {

        description.textContent =
            message;
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