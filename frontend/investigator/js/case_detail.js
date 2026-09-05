document.addEventListener("DOMContentLoaded", async () => {

    console.log("🔥 CASE DETAIL JS LOADED");

    lucide.createIcons();

    // =========================
    // GET ID FROM URL
    // =========================

    const params = new URLSearchParams(window.location.search);
    const emailId = params.get("id");

    console.log("🆔 Email ID:", emailId);

    if (!emailId) {
        console.error("❌ No email ID in URL");
        return;
    }


    // =========================
    // FETCH CASE
    // =========================

    try {

        const response = await fetch(
            `http://localhost:5001/api/emails/${emailId}`
        );

        console.log("🌐 API response:", response);

        const result = await response.json();

        console.log("📦 API result:", result);

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Failed to fetch case"
            );
        }

        const email = result.data;

        console.log("✅ CASE DATA:", email);

        showCaseData(email);

    } catch (error) {

        console.error("❌ CASE FETCH ERROR:", error);

    }


    // =========================
    // SHOW CASE DATA
    // =========================

    function showCaseData(email) {

        console.log("🔥🔥 NEW showCaseData RUNNING 🔥🔥");
        console.log("📦 EMAIL DATA:", email);

        const headers = email.headers || {};
        renderHeaderAnalysis(email);
        setupRawHeaderModal(headers);

        // =========================
        // CASE ID
        // =========================

        const caseId =
            email.caseId ||
            `CASE-${new Date(email.createdAt || Date.now()).getFullYear()}-${email._id.slice(-6).toUpperCase()}`;

        document.querySelectorAll(".case-id").forEach(el => {
            el.textContent = caseId;
        });


        // =========================
        // SUBJECT
        // =========================

        const title =
            document.querySelector(".case-main h1");

        if (title) {
            title.textContent =
                headers.subject || "No Subject";
        }


        // =========================
        // SENDER + RECEIVED DATE
        // =========================

        const fromLine =
            document.querySelector(".from-line");

        if (fromLine) {

            fromLine.innerHTML = `
                From:
                <span>${escapeHtml(
                    headers.from || "Unknown Sender"
                )}</span>

                <b>•</b>

                Received:
                ${escapeHtml(
                    formatDate(
                        headers.date || email.createdAt
                    )
                )}
            `;
        }


        // =========================
        // THREAT SCORE
        // =========================

        const threatScore =
            calculateThreatScore(email);

        const threatScoreElement =
            document.querySelector(".threat-score strong");

        if (threatScoreElement) {
            threatScoreElement.textContent =
                threatScore;
        }


        // =========================
        // THREAT SCORE BAR
        // =========================

        const scoreBar =
            document.querySelector(".score-line span");

        if (scoreBar) {
            scoreBar.style.width =
                `${threatScore}%`;
        }


        // =========================
        // RISK LABEL
        // =========================

        const riskLabel =
            document.querySelector(".risk-label");

        if (riskLabel) {

            let riskText = "LOW RISK";

            if (threatScore >= 80) {
                riskText = "CRITICAL RISK";
            } else if (threatScore >= 60) {
                riskText = "HIGH RISK";
            } else if (threatScore >= 30) {
                riskText = "MEDIUM RISK";
            }

            riskLabel.textContent =
                riskText;
        }


        // =========================
        // STATUS
        // =========================

        const status =
            document.querySelector(".case-labels .status");

        if (status) {
            status.textContent = "NEW";
        }


        // =========================
        // EMAIL EVIDENCE
        // =========================

        const meta =
            document.querySelectorAll(
                ".metadata-card .meta-item strong"
            );

        if (meta.length >= 7) {

            meta[0].textContent =
                headers.from || "—";

            meta[1].textContent =
                headers.to || "—";

            meta[2].textContent =
                headers.replyTo || "—";

            meta[3].textContent =
                headers.returnPath || "—";

            meta[4].textContent =
                headers.subject || "—";

            meta[5].textContent =
                headers.messageId || "—";

            meta[6].textContent =
                headers.date || "—";
        }


        // =========================
        // EMAIL BODY
        // =========================

        const body =
            document.querySelector(".email-content");

        if (body) {

            body.innerHTML = `
                <h3>
                    ${escapeHtml(
                        headers.subject || "No Subject"
                    )}
                </h3>

                <p>
                    ${escapeHtml(
                        email.body?.plainText ||
                        "No email body available."
                    )}
                </p>
            `;
        }


        // =========================
        // PREVIEW SENDER
        // =========================

        const previewSender =
            document.querySelector(
                ".sender-info strong"
            );

        if (previewSender) {
            previewSender.textContent =
                headers.from || "Unknown Sender";
        }


        // =========================
        // PREVIEW TO
        // =========================

        const previewTo =
            document.querySelector(
                ".sender-info span"
            );

        if (previewTo) {
            previewTo.textContent =
                `to ${headers.to || "Unknown"}`;
        }


        // =========================
        // THREAT TYPE
        // =========================

        const prediction =
            email.mlAnalysis?.prediction ||
            "Unknown";

        const threatType =
            document.querySelector(
                ".summary-card:nth-child(2) h2"
            );

        if (threatType) {
            threatType.textContent =
                prediction;
        }


        // =========================
        // CONFIDENCE
        // =========================

        const confidence =
            email.mlAnalysis?.confidence;

        const confidenceElement =
            document.querySelector(
                ".summary-card:nth-child(3) h2"
            );

        if (confidenceElement) {

            if (
                confidence !== undefined &&
                confidence !== null
            ) {

                let value = Number(confidence);

                if (value <= 1) {
                    value *= 100;
                }

                confidenceElement.textContent =
                    `${Math.round(value)}%`;

            } else {

                confidenceElement.textContent =
                    "—";
            }
        }


        // =========================
        // SUMMARY THREAT SCORE
        // =========================

        const summaryScore =
            document.querySelector(
                ".summary-card:nth-child(1) .big-score"
            );

        if (summaryScore) {

            summaryScore.innerHTML = `
                ${threatScore}
                <small>/100</small>
            `;
        }


        // =========================
        // SUMMARY RISK TEXT
        // =========================

        const summaryRisk =
            document.querySelector(
                ".summary-card:nth-child(1) .critical-text"
            );

        if (summaryRisk) {

            let riskText = "LOW RISK";

            if (threatScore >= 80) {
                riskText = "CRITICAL RISK";
            } else if (threatScore >= 60) {
                riskText = "HIGH RISK";
            } else if (threatScore >= 30) {
                riskText = "MEDIUM RISK";
            }

            summaryRisk.textContent =
                riskText;
        }


        // =========================
        // REPORT
        // =========================

        const reportStats =
            document.querySelectorAll(
                ".report-stat strong"
            );

        if (reportStats.length >= 3) {

            reportStats[0].textContent =
                prediction;

            reportStats[1].textContent =
                `${threatScore} / 100`;

            if (
                confidence !== undefined &&
                confidence !== null
            ) {

                let value = Number(confidence);

                if (value <= 1) {
                    value *= 100;
                }

                reportStats[2].textContent =
                    `${Math.round(value)}%`;

            } else {

                reportStats[2].textContent =
                    "—";
            }
        }


        // =========================
        // REPORT CASE INFO
        // =========================

        const reportInfo =
            document.querySelector(".report-info");

        if (reportInfo) {

            reportInfo.textContent =
                `${caseId} · Generated ${formatDate(
                    email.createdAt || headers.date
                )}`;
        }


        // =========================
        // RE-RENDER ICONS
        // =========================

        renderEmailJourney(email);
        renderIPIntelligence(email);
        lucide.createIcons();
    }

    // =========================================================
// EMAIL JOURNEY
// =========================================================

function renderEmailJourney(email) {

    console.log("🛣️ Rendering Email Journey...");

    const journeyPath =
        document.getElementById("journeyPath");

    const intelligence =
        document.getElementById("nodeIntelligence");

    if (!journeyPath || !intelligence) {
        console.error("❌ Journey elements not found");
        return;
    }

    const hops =
        email.emailJourney?.hops || [];

    console.log("📍 Journey Hops:", hops);

    // -----------------------------------------------------
    // NO JOURNEY DATA
    // -----------------------------------------------------

    if (!hops.length) {

        journeyPath.innerHTML = `
            <div class="journey-empty">
                No email infrastructure path was detected.
            </div>
        `;

        intelligence.innerHTML = `
            <div class="node-title">
                <span class="live-dot"></span>
                <span>Node intelligence</span>
                <strong>NO DATA</strong>
            </div>

            <div class="node-details">
                <div>
                    <span>status</span>
                    <strong>No journey data available</strong>
                </div>
            </div>
        `;

        return;
    }


    // -----------------------------------------------------
    // SORT HOPS
    // -----------------------------------------------------

    const sortedHops =
        [...hops].sort(
            (a, b) =>
                Number(a.hop_id || 0) -
                Number(b.hop_id || 0)
        );


    // -----------------------------------------------------
    // CREATE PATH
    // -----------------------------------------------------

    journeyPath.innerHTML = "";

    sortedHops.forEach((hop, index) => {

        const node =
            document.createElement("div");

        node.className =
            `journey-node ${
                index === 0 ? "active" : ""
            }`;

        const label =
            getJourneyLabel(
                index,
                sortedHops.length
            );

        const value =
            getJourneyValue(hop);

        node.innerHTML = `
            <span class="node-label">
                ${label}
            </span>

            <strong title="${escapeHtml(value)}">
                ${escapeHtml(value)}
            </strong>

            ${
                index < sortedHops.length - 1
                ? `<i data-lucide="chevron-right"></i>`
                : ""
            }
        `;

        node.addEventListener("click", () => {

            document
                .querySelectorAll(
                    "#journeyPath .journey-node"
                )
                .forEach(n => {
                    n.classList.remove("active");
                });

            node.classList.add("active");

            showJourneyNode(hop, label);
        });


        journeyPath.appendChild(node);


        // Connection line
        if (index < sortedHops.length - 1) {

            const line =
                document.createElement("div");

            line.className =
                "journey-line";

            journeyPath.appendChild(line);
        }

    });


    // -----------------------------------------------------
    // SHOW FIRST NODE
    // -----------------------------------------------------

    showJourneyNode(
        sortedHops[0],
        getJourneyLabel(
            0,
            sortedHops.length
        )
    );

    lucide.createIcons();

    console.log("✅ Email Journey rendered");
}

// =========================================================
// IP INTELLIGENCE
// =========================================================

function renderIPIntelligence(email) {

    console.log("🌐 Rendering IP Intelligence...");

    const ipIntel =
        email.ipIntelligence || {};

    const routing =
        ipIntel.routing_summary || {};

    const origin =
        ipIntel.origin_ip_data || {};

    const signals =
        ipIntel.signals || {};

    console.log("🌐 IP Intelligence:", ipIntel);
    console.log("🌐 Origin IP Data:", origin);


    // =====================================================
    // IP
    // =====================================================

    const ipElement =
        document.getElementById("intel-ip");

    if (ipElement) {
        ipElement.textContent =
            origin.ip ||
            routing.origin_ip_candidate ||
            "—";
    }


    // =====================================================
    // COUNTRY
    // =====================================================

    const countryElement =
        document.getElementById("intel-country");

    if (countryElement) {
        countryElement.textContent =
            origin.country ||
            "—";
    }


    // =====================================================
    // CITY
    // =====================================================

    const cityElement =
        document.getElementById("intel-city");

    if (cityElement) {
        cityElement.textContent =
            origin.city ||
            "—";
    }


    // =====================================================
    // ASN
    // =====================================================

    const asnElement =
        document.getElementById("intel-asn");

    if (asnElement) {
        asnElement.textContent =
            origin.asn ||
            "—";
    }


    // =====================================================
    // PROVIDER / ISP
    // =====================================================

    const providerElement =
        document.getElementById("intel-provider");

    if (providerElement) {
        providerElement.textContent =
            origin.isp ||
            "—";
    }


    // =====================================================
    // HOSTING
    // =====================================================

    const hostingElement =
        document.getElementById("intel-hosting");

    if (hostingElement) {

        if (origin.is_hosting === true) {
            hostingElement.textContent =
                "Yes";
        } else if (origin.is_hosting === false) {
            hostingElement.textContent =
                "No";
        } else {
            hostingElement.textContent =
                "—";
        }
    }


    // =====================================================
    // REPUTATION
    // =====================================================

    const reputationElement =
        document.getElementById("intel-reputation");

    if (reputationElement) {

        if (origin.is_proxy === true) {

            reputationElement.textContent =
                "Proxy detected";

        } else if (
            origin.lookup_status === "success"
        ) {

            reputationElement.textContent =
                "No malicious reputation data";

        } else {

            reputationElement.textContent =
                "Unknown";
        }
    }


    // =====================================================
    // RISK
    // =====================================================

    const riskElement =
        document.getElementById("intel-risk");

    if (riskElement) {

        let risk = "Low";

        if (
            signals.ip_origin_is_vpn_proxy === true
        ) {

            risk = "High";

        } else if (
            signals.ip_origin_is_hosting === true
        ) {

            risk = "Medium";
        }

        riskElement.textContent =
            risk;

        riskElement.classList.remove(
            "danger",
            "warning",
            "safe"
        );

        if (risk === "High") {

            riskElement.classList.add("danger");

        } else if (risk === "Medium") {

            riskElement.classList.add("warning");

        } else {

            riskElement.classList.add("safe");
        }
    }


    // =====================================================
    // COPY IP
    // =====================================================

    const copyBtn =
        document.getElementById("copyIpBtn");

    if (copyBtn) {

        copyBtn.onclick = async () => {

            const ip =
                origin.ip ||
                routing.origin_ip_candidate;

            if (!ip) {
                return;
            }

            try {

                await navigator.clipboard.writeText(ip);

                const original =
                    copyBtn.innerHTML;

                copyBtn.innerHTML = `
                    <i data-lucide="check"></i>
                    Copied
                `;

                lucide.createIcons();

                setTimeout(() => {

                    copyBtn.innerHTML =
                        original;

                    lucide.createIcons();

                }, 1500);

            } catch (error) {

                console.error(
                    "❌ Failed to copy IP:",
                    error
                );
            }
        };
    }


    // =====================================================
    // INVESTIGATE IP
    // =====================================================

    const investigateBtn =
        document.getElementById(
            "investigateIpBtn"
        );

    if (investigateBtn) {

        investigateBtn.onclick = () => {

            const ip =
                origin.ip ||
                routing.origin_ip_candidate;

            if (!ip) {
                return;
            }

            console.log(
                "🔎 Investigating IP:",
                ip
            );

            // Future: dedicated IP investigation page
            alert(
                `Investigating IP: ${ip}`
            );
        };
    }


    // =====================================================
    // ADD TO IOC
    // =====================================================

    const addIocBtn =
        document.getElementById("addIocBtn");

    if (addIocBtn) {

        addIocBtn.onclick = () => {

            const ip =
                origin.ip ||
                routing.origin_ip_candidate;

            if (!ip) {
                return;
            }

            console.log(
                "➕ Adding IP to IOC list:",
                ip
            );

            // Future: connect to IOC API
            alert(
                `${ip} added to IOC list`
            );
        };
    }


    lucide.createIcons();

    console.log(
        "✅ IP Intelligence rendered"
    );
}

// =========================================================
// JOURNEY LABEL
// =========================================================

function getJourneyLabel(index, total) {

    if (index === 0) {
        return "SOURCE";
    }

    if (index === total - 1) {
        return "DESTINATION";
    }

    return "RELAY";
}

// =========================================================
// RAW EMAIL HEADERS MODAL
// =========================================================

function setupRawHeaderModal(headers) {

    const modal = document.getElementById("rawHeaderModal");
    const rawHeaderBtn = document.querySelector(".raw-header-btn");
    const closeBtn = document.getElementById("closeRawHeader");
    const overlay = modal?.querySelector(".raw-header-overlay");
    const content = document.getElementById("rawHeaderContent");

    if (!modal || !rawHeaderBtn || !content) {
        console.error("❌ Raw Header modal elements not found");
        return;
    }

    console.log("✅ Raw Header modal connected");
    console.log("📨 Headers:", headers);

    // Button click
    rawHeaderBtn.onclick = () => {

        console.log("📨 RAW HEADERS BUTTON CLICKED");

        const rawHeaderText =
            buildRawHeaderText(headers);

        content.innerHTML = `
            <pre>${escapeHtml(rawHeaderText)}</pre>
        `;

        modal.classList.add("active");

        lucide.createIcons();
    };


    // Close button
    if (closeBtn) {
        closeBtn.onclick = () => {
            modal.classList.remove("active");
        };
    }


    // Click outside
    if (overlay) {
        overlay.onclick = () => {
            modal.classList.remove("active");
        };
    }


    // ESC
    document.addEventListener("keydown", (event) => {

        if (
            event.key === "Escape" &&
            modal.classList.contains("active")
        ) {
            modal.classList.remove("active");
        }

    });

}

// =========================================================
// HEADER ANALYSIS - DYNAMIC
// =========================================================

function renderHeaderAnalysis(email) {

    const headers = email.headers || {};
    const forensic = email.headerForensics || {};

    const auth =
        forensic.authentication_matrix || {};

    const identity =
        forensic.identity_analysis || {};

    const anomalies =
        forensic.anomalies || [];


    console.log("🔍 AUTH:", auth);
    console.log("🔍 IDENTITY:", identity);
    console.log("🔍 ANOMALIES:", anomalies);


    // =====================================================
    // SPF / DKIM / DMARC
    // =====================================================

    const authCards =
        document.querySelectorAll(
            "#header-analysis .auth-card"
        );

    const authValues = [
        auth.spf,
        auth.dkim,
        auth.dmarc
    ];

    authCards.forEach((card, index) => {

        const status = String(
            authValues[index] || "UNKNOWN"
        ).toUpperCase();

        const passed = status === "PASS";


        // ---------------------------------------------
        // STATUS ELEMENT
        // ---------------------------------------------

        const statusElement =
            card.querySelector(
                ".auth-top span:last-child"
            );

        if (statusElement) {

            statusElement.classList.remove(
                "pass",
                "fail"
            );

            statusElement.classList.add(
                passed ? "pass" : "fail"
            );

            statusElement.innerHTML = `
                <i data-lucide="${passed ? "check" : "x"}"></i>
                ${passed ? "PASS" : status}
            `;
        }


        // ---------------------------------------------
        // STATUS LINE
        // ---------------------------------------------

        // IMPORTANT:
        // Existing line chahe fail-line ho
        // ya success-line, dono ko find karega

        const line =
            card.querySelector(
                ".fail-line, .success-line"
            );

        if (line) {

            line.classList.remove(
                "fail-line",
                "success-line"
            );

            line.classList.add(
                passed
                    ? "success-line"
                    : "fail-line"
            );
        }

    });


    // =====================================================
    // FROM DOMAIN
    // =====================================================

    const fromDomain =
        document.querySelector(
            "#header-analysis .detail-item:nth-child(1) strong"
        );

    if (fromDomain) {

        fromDomain.textContent =
            identity.from_domain || "—";
    }


    // =====================================================
    // REPLY-TO
    // =====================================================

    const replyTo =
        document.querySelector(
            "#header-analysis .detail-item:nth-child(2) strong"
        );

    if (replyTo) {

        replyTo.textContent =
            headers.replyTo ||
            identity.reply_to_domain ||
            "—";
    }


    // =====================================================
    // FINDINGS
    // =====================================================

    const findingsList =
        document.querySelector(
            "#header-analysis .findings-list"
        );

    if (findingsList) {

        const findings = [];


        // ---------------------------------------------
        // SPOOFING
        // ---------------------------------------------

        if (identity.is_spoofed === true) {

            findings.push(
                "Sender identity mismatch"
            );
        }


        // ---------------------------------------------
        // SPF
        // ---------------------------------------------

        if (
            auth.spf &&
            String(auth.spf).toUpperCase() !== "PASS"
        ) {

            findings.push(
                `SPF authentication ${String(auth.spf).toLowerCase()}`
            );
        }


        // ---------------------------------------------
        // DKIM
        // ---------------------------------------------

        if (
            auth.dkim &&
            String(auth.dkim).toUpperCase() !== "PASS"
        ) {

            findings.push(
                `DKIM authentication ${String(auth.dkim).toLowerCase()}`
            );
        }


        // ---------------------------------------------
        // DMARC
        // ---------------------------------------------

        if (
            auth.dmarc &&
            String(auth.dmarc).toUpperCase() !== "PASS"
        ) {

            findings.push(
                `DMARC authentication ${String(auth.dmarc).toLowerCase()}`
            );
        }


        // ---------------------------------------------
        // ACTUAL BACKEND ANOMALIES
        // ---------------------------------------------

        anomalies.forEach(anomaly => {

            if (!anomaly) return;

            const text =
                anomaly.details ||
                anomaly.type ||
                "Header anomaly detected";

            findings.push(text);
        });


        // ---------------------------------------------
        // NO FINDINGS
        // ---------------------------------------------

        if (!findings.length) {

            findingsList.innerHTML = `
                <div class="finding">
                    <i data-lucide="circle-check"></i>
                    <span>No suspicious header findings</span>
                </div>
            `;

        } else {

            findingsList.innerHTML =
                findings.map(finding => `
                    <div class="finding">
                        <i data-lucide="circle-alert"></i>
                        <span>
                            ${escapeHtml(finding)}
                        </span>
                    </div>
                `).join("");
        }
    }


    // =====================================================
    // REFRESH LUCIDE ICONS
    // =====================================================

    lucide.createIcons();
}
// =========================================================
// BUILD RAW HEADER TEXT
// =========================================================

function buildRawHeaderText(headers) {

    let output = "";

    Object.entries(headers).forEach(
        ([key, value]) => {

            // -----------------------------------------
            // NULL / EMPTY
            // -----------------------------------------

            if (
                value === null ||
                value === undefined
            ) {
                return;
            }


            // -----------------------------------------
            // RECEIVED ARRAY
            // -----------------------------------------

            if (
                key.toLowerCase() === "received" &&
                Array.isArray(value)
            ) {

                value.forEach((received) => {

                    if (
                        typeof received === "object" &&
                        received !== null
                    ) {

                        const from =
                            received.from || "";

                        const by =
                            received.by || "";

                        const ip =
                            received.ip ||
                            received.address ||
                            "";

                        const timestamp =
                            received.timestamp ||
                            received.date ||
                            "";

                        const forValue =
                            received.for ||
                            "";

                        output += "Received:";

                        if (from) {
                            output += ` from ${from}`;
                        }

                        if (ip) {
                            output += ` (${ip})`;
                        }

                        if (by) {
                            output += `\n    by ${by}`;
                        }

                        if (forValue) {
                            output += `\n    for ${forValue}`;
                        }

                        if (timestamp) {
                            output += `\n    ${timestamp}`;
                        }

                        output += "\n\n";

                    } else {

                        output +=
                            `Received: ${received}\n\n`;
                    }
                });

                return;
            }


            // -----------------------------------------
            // NORMAL ARRAY
            // -----------------------------------------

            if (Array.isArray(value)) {

                output +=
                    `${formatHeaderName(key)}:\n`;

                value.forEach((item) => {

                    if (
                        typeof item === "object" &&
                        item !== null
                    ) {

                        output +=
                            `  ${JSON.stringify(
                                item,
                                null,
                                2
                            )}\n`;

                    } else {

                        output +=
                            `  ${item}\n`;
                    }
                });

                output += "\n";

                return;
            }


            // -----------------------------------------
            // OBJECT
            // -----------------------------------------

            if (
                typeof value === "object" &&
                value !== null
            ) {

                output +=
                    `${formatHeaderName(key)}: `;

                output +=
                    JSON.stringify(
                        value,
                        null,
                        2
                    );

                output += "\n\n";

                return;
            }


            // -----------------------------------------
            // NORMAL VALUE
            // -----------------------------------------

            output +=
                `${formatHeaderName(key)}: ${value}\n`;
        }
    );

    return output.trim();
}


// =========================================================
// HEADER NAME FORMAT
// =========================================================

function formatHeaderName(key) {

    return key
        .replace(/([A-Z])/g, " $1")
        .replace(/^./, char =>
            char.toUpperCase()
        );
}

// =========================================================
// JOURNEY VALUE
// =========================================================

function getJourneyValue(hop) {

    if (hop.ip) {
        return hop.ip;
    }

    if (hop.by) {
        return hop.by;
    }

    if (hop.from) {
        return hop.from;
    }

    return "Unknown";
}


// =========================================================
// JOURNEY NODE INTELLIGENCE
// =========================================================

function showJourneyNode(hop, label) {

    const intelligence =
        document.getElementById(
            "nodeIntelligence"
        );

    if (!intelligence) {
        return;
    }


    const ip =
        hop.ip || "Unknown";

    const hostname =
        hop.by ||
        hop.from ||
        "Unknown";

    const provider =
        "—";

    const asn =
        "—";

    const location =
        "—";

    const timestamp =
        formatDate(
            hop.timestamp
        );


    intelligence.innerHTML = `

        <div class="node-title">

            <span class="live-dot"></span>

            <span>
                Node intelligence
            </span>

            <strong>
                ${escapeHtml(label)}
            </strong>

        </div>


        <div class="node-details">

            <div>
                <span>IP</span>
                <strong title="${escapeHtml(ip)}">
                    ${escapeHtml(ip)}
                </strong>
            </div>


            <div>
                <span>HOSTNAME</span>
                <strong title="${escapeHtml(hostname)}">
                    ${escapeHtml(hostname)}
                </strong>
            </div>


            <div>
                <span>PROVIDER</span>
                <strong>
                    ${escapeHtml(provider)}
                </strong>
            </div>


            <div>
                <span>ASN</span>
                <strong>
                    ${escapeHtml(asn)}
                </strong>
            </div>


            <div>
                <span>LOCATION</span>
                <strong>
                    ${escapeHtml(location)}
                </strong>
            </div>


            <div>
                <span>TIMESTAMP</span>
                <strong>
                    ${escapeHtml(timestamp)}
                </strong>
            </div>

        </div>
    `;

}

    // function showCaseData(email) {

    //     const headers = email.headers || {};

    //     // CASE ID
    //     const caseId =
    //         email.caseId ||
    //         `CASE-2026-${email._id.slice(-6).toUpperCase()}`;

    //     document.querySelectorAll(".case-id").forEach(el => {
    //         el.textContent = caseId;
    //     });


    //     // SUBJECT
    //     const title =
    //         document.querySelector(".case-main h1");

    //     if (title) {
    //         title.textContent =
    //             headers.subject || "No Subject";
    //     }


    //     // SENDER
    //     const fromLine =
    //         document.querySelector(".from-line");

    //     if (fromLine) {

    //         fromLine.innerHTML = `
    //             From:
    //             <span>${escapeHtml(
    //                 headers.from || "Unknown Sender"
    //             )}</span>

    //             <b>•</b>

    //             Received:
    //             ${escapeHtml(
    //                 formatDate(
    //                     headers.date || email.createdAt
    //                 )
    //             )}
    //         `;
    //     }


    //     // EMAIL EVIDENCE

    //     const meta =
    //         document.querySelectorAll(
    //             ".metadata-card .meta-item strong"
    //         );

    //     if (meta.length >= 7) {

    //         meta[0].textContent =
    //             headers.from || "—";

    //         meta[1].textContent =
    //             headers.to || "—";

    //         meta[2].textContent =
    //             headers.replyTo || "—";

    //         meta[3].textContent =
    //             headers.returnPath || "—";

    //         meta[4].textContent =
    //             headers.subject || "—";

    //         meta[5].textContent =
    //             headers.messageId || "—";

    //         meta[6].textContent =
    //             headers.date || "—";
    //     }


    //     // EMAIL BODY

    //     const body =
    //         document.querySelector(".email-content");

    //     if (body) {

    //         body.innerHTML = `
    //             <h3>
    //                 ${escapeHtml(
    //                     headers.subject || "No Subject"
    //                 )}
    //             </h3>

    //             <p>
    //                 ${escapeHtml(
    //                     email.body?.plainText ||
    //                     "No email body available."
    //                 )}
    //             </p>
    //         `;
    //     }


    //     // PREVIEW SENDER

    //     const previewSender =
    //         document.querySelector(".sender-info strong");

    //     if (previewSender) {
    //         previewSender.textContent =
    //             headers.from || "Unknown Sender";
    //     }


    //     // PREVIEW TO

    //     const previewTo =
    //         document.querySelector(".sender-info span");

    //     if (previewTo) {
    //         previewTo.textContent =
    //             `to ${headers.to || "Unknown"}`;
    //     }


    //     // THREAT TYPE

    //     const prediction =
    //         email.mlAnalysis?.prediction ||
    //         "Unknown";

    //     const threatType =
    //         document.querySelector(
    //             ".summary-card:nth-child(2) h2"
    //         );

    //     if (threatType) {
    //         threatType.textContent =
    //             prediction;
    //     }


    //     // CONFIDENCE

    //     const confidence =
    //         email.mlAnalysis?.confidence;

    //     const confidenceElement =
    //         document.querySelector(
    //             ".summary-card:nth-child(3) h2"
    //         );

    //     if (
    //         confidenceElement &&
    //         confidence !== undefined &&
    //         confidence !== null
    //     ) {

    //         let value = Number(confidence);

    //         if (value <= 1) {
    //             value *= 100;
    //         }

    //         confidenceElement.textContent =
    //             `${Math.round(value)}%`;
    //     }


    //     // REPORT

    //     const reportStats =
    //         document.querySelectorAll(
    //             ".report-stat strong"
    //         );

    //     if (reportStats.length >= 3) {

    //         reportStats[0].textContent =
    //             prediction;

    //         reportStats[1].textContent =
    //             `${calculateThreatScore(email)} / 100`;

    //         if (
    //             confidence !== undefined &&
    //             confidence !== null
    //         ) {

    //             let value = Number(confidence);

    //             if (value <= 1) {
    //                 value *= 100;
    //             }

    //             reportStats[2].textContent =
    //                 `${Math.round(value)}%`;
    //         }
    //     }


    //     lucide.createIcons();
    // }


    // =========================
    // THREAT SCORE
    // =========================

    function calculateThreatScore(email) {

        const ml =
            Number(
                email.mlAnalysis?.confidence || 0
            );

        const header =
            Number(
                email.headerForensics
                    ?.header_risk_score || 0
            );

        const url =
            Number(
                email.urlIntelligence
                    ?.summary
                    ?.max_risk_score || 0
            );

        const attachment =
            Number(
                email.attachmentIntelligence
                    ?.summary
                    ?.max_attachment_risk_score || 0
            );

        const values = [
            ml <= 1 ? ml * 100 : ml,
            header,
            url,
            attachment
        ];

        return Math.min(
            100,
            Math.round(Math.max(...values))
        );
    }


    // =========================
    // DATE
    // =========================

    function formatDate(value) {

        if (!value) {
            return "—";
        }

        const date = new Date(value);

        if (isNaN(date.getTime())) {
            return value;
        }

        return date.toLocaleString(
            "en-GB",
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

        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }


    // =========================
    // TABS
    // =========================

    const tabs =
        document.querySelectorAll(".tab");

    const panels =
        document.querySelectorAll(".tab-panel");

    panels.forEach(panel => {
        panel.style.display = "none";
    });

    const overview =
        document.getElementById("overview");

    if (overview) {
        overview.style.display = "block";
    }

    tabs.forEach(tab => {

        tab.addEventListener("click", () => {

            const targetId =
                tab.dataset.tab;

            panels.forEach(panel => {
                panel.style.display = "none";
            });

            tabs.forEach(t => {
                t.classList.remove("active");
            });

            tab.classList.add("active");

            const target =
                document.getElementById(targetId);

            if (target) {
                target.style.display = "block";
            }

            lucide.createIcons();
        });

    });

});