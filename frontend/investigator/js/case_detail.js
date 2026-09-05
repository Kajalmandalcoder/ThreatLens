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