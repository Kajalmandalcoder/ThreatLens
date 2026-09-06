document.addEventListener("DOMContentLoaded", () => {

    /* =========================================================
       LUCIDE
       ========================================================= */

    function refreshIcons() {
        if (window.lucide) {
            lucide.createIcons();
        }
    }

    refreshIcons();


    /* =========================================================
       ELEMENTS
       ========================================================= */

    const drawer =
        document.getElementById("evidenceDrawer");

    const closeDrawer =
        document.getElementById("closeDrawer");

    const currentNode =
        document.querySelector(".current-node");

    const graphArea =
        document.querySelector(".graph-area");

    const connectionsSvg =
        document.querySelector(".connections");

    const filters =
        document.querySelectorAll(".filter");

    const viewTabs =
        document.querySelectorAll(".view-tab");


    /* =========================================================
       API
       ========================================================= */

    const API_URL =
        "http://localhost:5001/api/campaigns/graph";


    /* =========================================================
       GRAPH STATE
       ========================================================= */

    let campaignData = null;

    let graphState = {
        cases: [],
        caseNodes: [],
        indicators: [],
        indicatorNodes: {}
    };

    window.__campaignGraph = graphState;


    /* =========================================================
       GRAPH DRAW SCHEDULER
       ========================================================= */

    let graphDrawFrame = null;

    function scheduleGraphDraw() {

        if (graphDrawFrame) {
            cancelAnimationFrame(graphDrawFrame);
        }

        graphDrawFrame =
            requestAnimationFrame(() => {

                requestAnimationFrame(() => {

                    drawConnections();

                });

            });

    }


    /* =========================================================
       NORMALIZE INDICATOR TYPE
       ========================================================= */

    function normalizeIndicatorType(type) {

        const value =
            String(type || "")
                .trim()
                .toLowerCase();

        if (value === "attachment") {
            return "hash";
        }

        return value;
    }


    /* =========================================================
       FORMAT EVIDENCE VALUE
       ========================================================= */

    function formatEvidenceValue(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return "—";
        }


        if (Array.isArray(value)) {

            return value
                .map(item =>
                    formatEvidenceValue(item)
                )
                .join(", ");

        }


        if (typeof value === "object") {

            const subjectSimilarity =
                value.subject_similarity ??
                value.subjectSimilarity;

            const bodySimilarity =
                value.body_similarity ??
                value.bodySimilarity;

            const strongestSimilarity =
                value.strongest_similarity ??
                value.strongestSimilarity;


            const parts = [];


            if (
                subjectSimilarity !== undefined &&
                subjectSimilarity !== null
            ) {

                parts.push(
                    `Subject ${subjectSimilarity}%`
                );

            }


            if (
                bodySimilarity !== undefined &&
                bodySimilarity !== null
            ) {

                parts.push(
                    `Body ${bodySimilarity}%`
                );

            }


            if (parts.length) {
                return parts.join(" · ");
            }


            if (
                strongestSimilarity !== undefined &&
                strongestSimilarity !== null
            ) {

                return `Strongest ${strongestSimilarity}%`;

            }


            if (value.text !== undefined) {
                return String(value.text);
            }


            if (value.similarity !== undefined) {
                return `${value.similarity}% similarity`;
            }


            if (value.value !== undefined) {
                return formatEvidenceValue(
                    value.value
                );
            }


            try {

                return JSON.stringify(value);

            } catch (error) {

                return "—";

            }

        }


        return String(value);

    }


    /* =========================================================
       MATCH VALUE
       ========================================================= */

    function getMatchValue(match) {

        if (!match) {
            return "—";
        }

        return formatEvidenceValue(
            match.currentValue ??
            match.value ??
            match.relatedValue ??
            match.details ??
            "—"
        );

    }


    /* =========================================================
       DRAWER
       ========================================================= */

    function openDrawer(caseIndex) {

        if (!drawer) {
            return;
        }


        const index =
            Number(caseIndex);


        const selectedCase =
            graphState.cases[index];


        if (!selectedCase) {
            return;
        }


        const matches =
            Array.isArray(selectedCase.matches)
                ? selectedCase.matches
                : [];


        const caseId =
            selectedCase.caseId ||
            selectedCase.id ||
            "Related Case";


        const subject =
            selectedCase.subject ||
            "Related email";


        const score =
            Number(
                selectedCase.correlationScore ??
                selectedCase.score ??
                0
            );

            // updateCorrelationDrawer({
            //     currentEmail: selectedCase,

            //     stats: {
            //         correlationStrength:
            //             selectedCase.correlationScore ??
            //             selectedCase.score ??
            //             0
            //     },

            //     evidence: matches
            // });

        const drawerCase =
            document.getElementById(
                "drawerCase"
            );

        const drawerSubject =
            document.getElementById(
                "drawerSubject"
            );

        const drawerScore =
            document.getElementById(
                "drawerScore"
            );

        const drawerCorrelation =
            document.getElementById(
                "drawerCorrelation"
            );

        const drawerProgress =
            document.getElementById(
                "drawerProgress"
            );

        const drawerIndicatorCount =
            document.getElementById(
                "drawerIndicatorCount"
            );

        const drawerEvidenceList =
            document.getElementById(
                "drawerEvidenceList"
            );

        const drawerFoundBox =
            document.getElementById(
                "drawerFoundBox"
            );


        const safeScore =
            Math.min(
                Math.max(
                    score,
                    0
                ),
                100
            );


        if (drawerCase) {
            drawerCase.textContent =
                caseId;
        }


        if (drawerSubject) {
            drawerSubject.textContent =
                subject;
        }


        if (drawerScore) {
            drawerScore.textContent =
                `● ${safeScore}`;
        }


        if (drawerCorrelation) {
            drawerCorrelation.textContent =
                `${safeScore}%`;
        }


        if (drawerProgress) {
            drawerProgress.style.width =
                `${safeScore}%`;
        }


        const count =
            matches.length;


        if (drawerIndicatorCount) {

            drawerIndicatorCount.textContent =
                `Based on ${count} matching indicator${
                    count === 1 ? "" : "s"
                }`;

        }


        if (drawerFoundBox) {

            drawerFoundBox.textContent =
                `✓  ${count} matching indicator${
                    count === 1 ? "" : "s"
                } found`;

        }


        if (drawerEvidenceList) {

            if (count === 0) {

                drawerEvidenceList.innerHTML = `
                    <div class="evidence-item">

                        <span>—</span>

                        <div>
                            <strong>
                                No matching indicators
                            </strong>

                            <small>
                                No correlation evidence found
                            </small>
                        </div>

                    </div>
                `;

            } else {

                drawerEvidenceList.innerHTML =
                    matches.map(match => {

                        const type =
                            normalizeIndicatorType(
                                match.type
                            );


                        const label =
                            match.label ||
                            match.name ||
                            getCorrelationLabel(type);


                        const value =
                            getMatchValue(match);


                        const strength =
                            Number(
                                match.strength ??
                                match.score ??
                                0
                            );


                        const className =
                            strength >= 20
                                ? "strong"
                                : "weak";


                        return `
                            <div class="evidence-item ${className}">

                                <span>✓</span>

                                <div>

                                    <strong>
                                        ${escapeHtml(label)}
                                    </strong>

                                    <small>
                                        ${escapeHtml(value)}
                                    </small>

                                </div>

                            </div>
                        `;

                    }).join("");

            }

        }


        drawer.classList.remove("hidden");
        drawer.style.display = "";

        refreshIcons();

    }


    function hideDrawer() {

        if (!drawer) {
            return;
        }

        drawer.style.display = "none";

    }


    if (closeDrawer) {

        closeDrawer.addEventListener(
            "click",
            hideDrawer
        );

    }


    /* =========================================================
       CASE NODE CLICK
       ========================================================= */

    if (graphArea) {

        graphArea.addEventListener(
            "click",
            event => {

                const caseNode =
                    event.target.closest(
                        ".dynamic-case"
                    );


                if (!caseNode) {
                    return;
                }


                openDrawer(
                    caseNode.dataset.index
                );

            }
        );

    }


    /* =========================================================
       FILTERS
       ========================================================= */

    filters.forEach(button => {

        button.addEventListener(
            "click",
            () => {

                filters.forEach(btn => {
                    btn.classList.remove("active");
                });


                button.classList.add("active");


                applyFilter(
                    button.dataset.filter
                );

            }
        );

    });


    function applyFilter(filter) {

        const selectedFilter =
            normalizeIndicatorType(filter);


        const lines =
            document.querySelectorAll(
                ".connections line"
            );


        const indicatorNodes =
            document.querySelectorAll(
                ".dynamic-indicator"
            );


        const caseNodes =
            document.querySelectorAll(
                ".dynamic-case"
            );


        /* =====================================================
           ALL
           ===================================================== */

        if (selectedFilter === "all") {

            lines.forEach(line => {

                line.style.opacity = "0.8";
                line.style.strokeWidth = "1";

            });


            indicatorNodes.forEach(node => {

                node.style.opacity = "1";
                node.style.display = "";

            });


            caseNodes.forEach(node => {

                node.style.opacity = "1";
                node.style.display = "";

            });


            return;

        }


        /* =====================================================
           HIGH CONFIDENCE
           ===================================================== */

        if (selectedFilter === "high") {

            lines.forEach(line => {

                const score =
                    Number(
                        line.dataset.score || 0
                    );


                if (score >= 70) {

                    line.style.opacity = "1";
                    line.style.strokeWidth = "2";

                } else {

                    line.style.opacity = "0.08";
                    line.style.strokeWidth = "1";

                }

            });


            indicatorNodes.forEach(node => {

                const type =
                    normalizeIndicatorType(
                        node.dataset.type
                    );


                const evidence =
                    graphState.indicators.find(
                        item =>
                            normalizeIndicatorType(
                                item.indicator
                            ) === type
                    );


                const score =
                    Number(
                        evidence?.score ??
                        evidence?.strength ??
                        0
                    );


                node.style.display = "";


                node.style.opacity =
                    score >= 70
                        ? "1"
                        : "0.25";

            });


            caseNodes.forEach(node => {

                const score =
                    Number(
                        node.dataset.score || 0
                    );


                node.style.display = "";


                node.style.opacity =
                    score >= 70
                        ? "1"
                        : "0.25";

            });


            return;

        }


        /* =====================================================
           INDICATOR FILTER
           ===================================================== */

        lines.forEach(line => {

            const lineType =
                normalizeIndicatorType(
                    line.dataset.type
                );


            if (
                lineType ===
                selectedFilter
            ) {

                line.style.opacity = "1";
                line.style.strokeWidth = "2";

            } else {

                line.style.opacity = "0.08";
                line.style.strokeWidth = "1";

            }

        });


        indicatorNodes.forEach(node => {

            const nodeType =
                normalizeIndicatorType(
                    node.dataset.type
                );


            node.style.display = "";


            node.style.opacity =
                nodeType === selectedFilter
                    ? "1"
                    : "0.25";

        });


        caseNodes.forEach(node => {

            const caseIndex =
                Number(
                    node.dataset.index
                );


            const email =
                graphState.cases[
                    caseIndex
                ];


            const matches =
                Array.isArray(
                    email?.matches
                )
                    ? email.matches
                    : [];


            const hasMatch =
                matches.some(
                    match =>
                        normalizeIndicatorType(
                            match.type
                        ) === selectedFilter
                );


            node.style.display = "";


            node.style.opacity =
                hasMatch
                    ? "1"
                    : "0.25";

        });

    }


    /* =========================================================
       VIEW TABS
       ========================================================= */

    viewTabs.forEach(tab => {

        tab.addEventListener(
            "click",
            () => {

                viewTabs.forEach(item => {
                    item.classList.remove("active");
                });


                tab.classList.add("active");


                const text =
                    tab.textContent
                        .trim();


                if (
                    text.includes(
                        "Network View"
                    )
                ) {
                const networkPanel =
                    document.querySelector(".network-panel");

                if (networkPanel) {
                    networkPanel.style.display = "";
                }

                const clustersPanel =
                    document.getElementById(
                        "campaignClustersPanel"
                    );

                if (clustersPanel) {
                    clustersPanel.style.display = "none";
                }
                if (graphArea) {
                        graphArea.style.display = "";
                    }

                scheduleGraphDraw();
                return;
                }
                if (
                    text.includes(
                        "Campaign Clusters"
                    )
                ) {

                    window.location.href =
                        "campaignCluster.html";

                    return;

                }


                
            }
        );

    });


    /* =========================================================
       CHECKBOXES
       ========================================================= */

    const checkboxes =
        document.querySelectorAll(
            ".network-footer input[type='checkbox']"
        );


    checkboxes.forEach(
        (checkbox, index) => {

            checkbox.addEventListener(
                "change",
                () => {

                    if (index === 0) {

                        document
                            .querySelectorAll(
                                ".dynamic-case"
                            )
                            .forEach(node => {

                                node.style.display =
                                    checkbox.checked
                                        ? ""
                                        : "none";

                            });

                    }


                    if (index === 1) {

                        document
                            .querySelectorAll(
                                ".dynamic-indicator"
                            )
                            .forEach(node => {

                                node.style.display =
                                    checkbox.checked
                                        ? ""
                                        : "none";

                            });

                    }


                    scheduleGraphDraw();

                }
            );

        }
    );


    /* =========================================================
       PIN EVIDENCE
       ========================================================= */

    const pinButton =
        document.querySelector(
            ".pin-button"
        );


    if (pinButton) {

        pinButton.addEventListener(
            "click",
            () => {

                pinButton.innerHTML =
                    "✓ Evidence pinned to investigation";


                pinButton.style.color =
                    "#29d1b2";


                pinButton.style.borderColor =
                    "#187d6d";

            }
        );

    }
        async function loadCampaignClusters() {

            try {

                const response =
                    await fetch(
                        "http://localhost:5001/api/campaigns/clusters",
                        {
                            cache: "no-store"
                        }
                    );


                if (!response.ok) {

                    throw new Error(
                        `Clusters API returned ${response.status}`
                    );

                }


                const result =
                    await response.json();


                if (!result.success) {

                    throw new Error(
                        result.message ||
                        "Campaign clusters API failed"
                    );

                }


                console.log(
                    "CAMPAIGN CLUSTERS:",
                    result.data
                );
                const clustersContainer =
                    document.getElementById(
                        "campaignClusters"
                    );

                if (!clustersContainer) {
                    return;
                }

            const clusters =
                Array.isArray(result.data?.clusters)
                    ? result.data.clusters
                    : [];

            clustersContainer.innerHTML = "";

            if (!clusters.length) {

                clustersContainer.innerHTML = `
                    <div class="cluster-empty">
                        No campaign clusters found
                    </div>
                `;

                return;
            }
            const clustersPanel =
                document.getElementById("campaignClustersPanel");

            if (clustersPanel) {
                clustersPanel.style.display = "";
            }

        clusters.forEach(cluster => {

            const card =
                document.createElement("div");

            card.className =
                "campaign-cluster-card";

            const emails =
                Array.isArray(cluster.emails)
                    ? cluster.emails
                    : [];

            card.innerHTML = `
                <div class="cluster-header">

                    <strong>
                        ${escapeHtml(
                            cluster.clusterId
                        )}
                    </strong>

                    <span>
                        ${emails.length} emails
                    </span>

                </div>

                <div class="cluster-emails">

                    ${emails.map(email => `
                        <div class="cluster-email">

                            <strong>
                                ${escapeHtml(
                                    email.subject ||
                                    "No subject"
                                )}
                            </strong>

                            <small>
                                ${escapeHtml(
                                    email.sender ||
                                    ""
                                )}
                            </small>

                            <small>
                                ${escapeHtml(
                                    email.id ||
                                    ""
                                )}
                            </small>

                        </div>
                    `).join("")}

                </div>
            `;

            clustersContainer.appendChild(
                card
            );

        });


                    } catch (error) {

                        console.error(
                            "Campaign clusters failed:",
                            error
                        );

                    }

                }
                

    /* =========================================================
       LOAD CAMPAIGN DATA
       ========================================================= */
                /* =========================================================
   LOAD CAMPAIGN DATA
   ========================================================= */

async function loadCampaignData() {

    try {

        const emailId =
            new URLSearchParams(
                window.location.search
            ).get("emailId");

        const graphUrl =
            emailId
                ? `${API_URL}?emailId=${encodeURIComponent(emailId)}`
                : API_URL;

        const response =
            await fetch(
                graphUrl,
                {
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            throw new Error(
                `API returned ${response.status}`
            );

        }

        const result =
            await response.json();

        if (!result.success) {

            throw new Error(
                result.message ||
                "Campaign API failed"
            );

        }

        campaignData =
            result.data || {};

        console.log(
            "CAMPAIGN API DATA:",
            campaignData
        );

        updateStats(
            campaignData
        );

        updateCurrentEmail(
            campaignData
        );

        buildGraph(
            campaignData
        );

        updateTimeline(
            campaignData
        );

        updateSummary(
            campaignData
        );

        updateEvidenceTable(
            campaignData
        );

        updateCorrelationDrawer(
            campaignData
        );

        refreshIcons();

        scheduleGraphDraw();

        setTimeout(
            scheduleGraphDraw,
            100
        );

    } catch (error) {

        console.error(
            "Campaign API failed:",
            error
        );

    }

}
    /* =========================================================
       STATS
       ========================================================= */

    function updateStats(data) {

        const statValues =
            document.querySelectorAll(
                ".stats-grid .stat-value"
            );


        if (statValues.length < 3) {
            return;
        }


        const stats =
            data.stats || {};


        const relatedCases =
            Number(
                stats.relatedCases || 0
            );


        const matchingIndicators =
            Number(
                stats.matchingIndicators || 0
            );


        const correlationStrength =
            Number(
                stats.correlationStrength || 0
            );


        const evidence =
            Array.isArray(data.evidence)
                ? data.evidence
                : [];


        const relatedEmails =
            Array.isArray(data.relatedEmails)
                ? data.relatedEmails
                : [];


        const evidenceTypes =
            new Set(
                evidence
                    .map(
                        item =>
                            normalizeIndicatorType(
                                item.indicator
                            )
                    )
                    .filter(Boolean)
            ).size;


        const now =
            new Date();


        const sevenDaysAgo =
            new Date(
                now.getTime() -
                7 * 24 * 60 * 60 * 1000
            );


        const newThisWeek =
            relatedEmails.filter(
                email => {

                    const date =
                        new Date(
                            email.date
                        );


                    return (
                        !Number.isNaN(
                            date.getTime()
                        ) &&
                        date >= sevenDaysAgo &&
                        date <= now
                    );

                }
            ).length;


        const safeCorrelation =
            Math.min(
                Math.max(
                    correlationStrength,
                    0
                ),
                100
            );


        statValues[0].textContent =
            String(
                relatedCases
            ).padStart(
                2,
                "0"
            );


        statValues[1].textContent =
            String(
                matchingIndicators
            ).padStart(
                2,
                "0"
            );


        statValues[2].innerHTML =
            `${safeCorrelation}<span>%</span>`;


        const progressFill =
            document.querySelector(
                ".progress-fill"
            );


        if (progressFill) {

            progressFill.style.width =
                `${safeCorrelation}%`;

        }


        const info =
            document.querySelector(
                ".info-bar strong"
            );


        if (info) {

            info.textContent =
                `${relatedCases} previous cases`;

        }


        const relatedCasesChange =
            document.getElementById(
                "relatedCasesChange"
            );


        if (relatedCasesChange) {

            relatedCasesChange.textContent =
                `↗ ${newThisWeek} new this week`;

        }


        const indicatorTypesSummary =
            document.getElementById(
                "indicatorTypesSummary"
            );


        if (indicatorTypesSummary) {

            indicatorTypesSummary.textContent =
                `Across ${evidenceTypes} evidence type${
                    evidenceTypes === 1
                        ? ""
                        : "s"
                }`;

        }

    }


    /* =========================================================
       CURRENT EMAIL
       ========================================================= */

    function updateCurrentEmail(data) {

        if (
            !currentNode ||
            !data.currentEmail
        ) {

            return;

        }


        const email =
            data.currentEmail;


        const caseElement =
            currentNode.querySelector(
                "strong"
            );


        const subjectElement =
            currentNode.querySelector(
                "small"
            );


        if (caseElement) {

            caseElement.textContent =
                email.caseId ||
                email.id ||
                "Current Email";

        }


        if (subjectElement) {

            subjectElement.textContent =
                email.subject ||
                "Current email";

        }


        const riskElement =
            currentNode.querySelector(
                ".risk"
            );


        if (riskElement) {

            const risk =
                email.risk ??
                email.riskScore ??
                email.threatScore ??
                email.threatAnalysis?.score ??
                email.mlAnalysis?.riskScore;


            if (
                risk !== undefined &&
                risk !== null &&
                risk !== ""
            ) {

                riskElement.textContent =
                    `RISK ${risk}`;

                riskElement.style.display = "";

            } else {

                riskElement.textContent = "";
                riskElement.style.display = "none";

            }

        }


        const phishingElement =
            currentNode.querySelector(
                ".phishing"
            );


        if (phishingElement) {

            const classification =
                email.phishing ??
                email.classification ??
                email.threatAnalysis?.classification ??
                email.threatAnalysis?.verdict ??
                email.mlAnalysis?.prediction;


            if (
                classification !== undefined &&
                classification !== null &&
                classification !== ""
            ) {

                phishingElement.textContent =
                    String(
                        classification
                    ).toUpperCase();

                phishingElement.style.display = "";

            } else {

                phishingElement.textContent = "";
                phishingElement.style.display = "none";

            }

        }

    }


    /* =========================================================
       CORRELATION DRAWER - CURRENT EMAIL
       ========================================================= */

    function updateCorrelationDrawer(data) {

        const currentEmail =
            data.currentEmail || {};

        const stats =
            data.stats || {};

        const evidence =
            Array.isArray(data.evidence)
                ? data.evidence
                : [];
        const uniqueEvidence = [];
        const seenEvidence = new Set();

        evidence.forEach(item => {

            const type =
                normalizeIndicatorType(
                    item.indicator ||
                    item.type
                );

                const value =
                    formatEvidenceValue(
                        item.currentValue ??
                        item.value ??
                        item.relatedValue ??
                        item.details ??
                        "—"
                    );

                const key =
                    `${type}|${value}`;

                if (
                    !type ||
                    seenEvidence.has(key)
                ) {
                    return;
                }

                seenEvidence.add(key);

                uniqueEvidence.push({
                    ...item,
                    indicator: type
                });

            });

        const drawerCase =
            document.getElementById(
                "drawerCase"
            );

        const drawerSubject =
            document.getElementById(
                "drawerSubject"
            );

        const drawerScore =
            document.getElementById(
                "drawerScore"
            );

        const drawerCorrelation =
            document.getElementById(
                "drawerCorrelation"
            );

        const drawerProgress =
            document.getElementById(
                "drawerProgress"
            );

        const drawerIndicatorCount =
            document.getElementById(
                "drawerIndicatorCount"
            );

        const drawerEvidenceList =
            document.getElementById(
                "drawerEvidenceList"
            );

        const drawerFoundBox =
            document.getElementById(
                "drawerFoundBox"
            );


        if (drawerCase) {

            drawerCase.textContent =
                currentEmail.caseId ||
                currentEmail.id ||
                "";

        }


        if (drawerSubject) {

            drawerSubject.textContent =
                currentEmail.subject ||
                "";

        }


        const correlation =
            Number(
                stats.correlationStrength || 0
            );


        const safeCorrelation =
            Math.min(
                Math.max(
                    correlation,
                    0
                ),
                100
            );


        if (drawerCorrelation) {

            drawerCorrelation.textContent =
                `${safeCorrelation}%`;

        }


        if (drawerScore) {

            drawerScore.textContent =
                `● ${safeCorrelation}`;

        }


        if (drawerProgress) {

            drawerProgress.style.width =
                `${safeCorrelation}%`;

        }


        const count =uniqueEvidence.length;


        if (drawerIndicatorCount) {

            drawerIndicatorCount.textContent =
                `Based on ${count} matching indicator${
                    count === 1 ? "" : "s"
                }`;

        }


        if (drawerFoundBox) {

            drawerFoundBox.textContent =
                `✓  ${count} matching indicator${
                    count === 1 ? "" : "s"
                } found`;

        }


        if (!drawerEvidenceList) {
            return;
        }


        if (count === 0) {

            drawerEvidenceList.innerHTML = `
                <div class="evidence-item">

                    <span>—</span>

                    <div>

                        <strong>
                            No matching indicators
                        </strong>

                        <small>
                            No correlation evidence found
                        </small>

                    </div>

                </div>
            `;

            return;

        }


        drawerEvidenceList.innerHTML =
            uniqueEvidence.map(item => {

                const indicator =
                    normalizeIndicatorType(
                        item.indicator
                    );


                const label =
                    item.label ||
                    getCorrelationLabel(
                        indicator
                    );


                const rawValue =
                    item.currentValue ??
                    item.value ??
                    item.relatedValue ??
                    "—";


                const value =
                    formatEvidenceValue(
                        rawValue
                    );


                const score =
                    Number(
                        item.score ??
                        item.strength ??
                        0
                    );


                const strengthClass =
                    score >= 20
                        ? "strong"
                        : "weak";


                return `
                    <div class="evidence-item ${strengthClass}">

                        <span>✓</span>

                        <div>

                            <strong>
                                ${escapeHtml(label)}
                            </strong>

                            <small>
                                ${escapeHtml(value)}
                            </small>

                        </div>

                    </div>
                `;

            }).join("");


        refreshIcons();

    }


    /* =========================================================
       CORRELATION LABEL
       ========================================================= */

    function getCorrelationLabel(type) {

        const normalized =
            normalizeIndicatorType(
                type
            );


        const labels = {

            sender:
                "Same Sender",

            domain:
                "Same Domain",

            url:
                "Same URL",

            hash:
                "Same Attachment Hash",

            ip:
                "Same IP",

            subject:
                "Similar Subject",

            content:
                "Similar Content"

        };


        return (
            labels[normalized] ||
            formatIndicatorName(normalized)
        );

    }


    /* =========================================================
       ESCAPE HTML
       ========================================================= */

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


    /* =========================================================
       BUILD GRAPH
       ========================================================= */

    function buildGraph(data) {

        if (!graphArea) {

            console.error(
                "Graph area not found"
            );

            return;

        }


        /* =====================================================
           SAVE ORIGINAL TEMPLATES FIRST
           ===================================================== */

        const originalCase =
            document.querySelector(
                ".case-node:not(.current-node)"
            );


        const originalIndicators =
            Array.from(
                document.querySelectorAll(
                    ".indicator"
                )
            );


        const caseTemplate =
            originalCase
                ? originalCase.cloneNode(true)
                : null;


        const indicatorTemplates = {};


        originalIndicators.forEach(
            node => {

                Array.from(
                    node.classList
                ).forEach(
                    className => {

                        if (
                            className.endsWith(
                                "-node"
                            ) &&
                            className !== "node"
                        ) {

                            const rawType =
                                className.replace(
                                    "-node",
                                    ""
                                );


                            const type =
                                normalizeIndicatorType(
                                    rawType
                                );


                            if (
                                !indicatorTemplates[type]
                            ) {

                                indicatorTemplates[type] =
                                    node.cloneNode(true);

                            }

                        }

                    }
                );

            }
        );


        /* =====================================================
           REMOVE OLD RELATED CASES
           ===================================================== */

        document
            .querySelectorAll(
                ".dynamic-case, .case-node:not(.current-node)"
            )
            .forEach(
                node => {
                    node.remove();
                }
            );


        /* =====================================================
           REMOVE ALL STATIC/DYNAMIC INDICATORS
           ===================================================== */

        document
            .querySelectorAll(
                ".dynamic-indicator, .indicator"
            )
            .forEach(
                node => {
                    node.remove();
                }
            );


        /* =====================================================
           CLEAR OLD CONNECTIONS
           ===================================================== */

        if (connectionsSvg) {
            connectionsSvg.innerHTML = "";
        }


        /* =====================================================
           API DATA
           ===================================================== */

        const relatedEmails =
            Array.isArray(data.relatedEmails)
                ? data.relatedEmails
                : [];


        const evidence =
            Array.isArray(data.evidence)
                ? data.evidence
                : [];


        /* =====================================================
           CREATE RELATED CASE NODES
           ===================================================== */

        const caseNodes = [];


        relatedEmails.forEach(
            (email, index) => {

                if (
                    !email ||
                    !(
                        email.caseId ||
                        email.id
                    )
                ) {

                    return;

                }


                let node;


                if (caseTemplate) {

                    node =
                        caseTemplate.cloneNode(true);

                } else {

                    node =
                        document.createElement(
                            "div"
                        );


                    node.className =
                        "node case-node";


                    node.innerHTML = `
                        <div class="node-title"></div>
                        <small></small>
                        <p></p>
                    `;

                }


                node.classList.remove(
                    "current-node"
                );


                node.classList.add(
                    "case-node",
                    "dynamic-case"
                );


                node.dataset.case =
                    String(
                        email.caseId ||
                        email.id
                    );


                node.dataset.index =
                    String(index);


                node.dataset.score =
                    String(
                        Number(
                            email.correlationScore ??
                            email.score ??
                            0
                        )
                    );


                const title =
                    node.querySelector(
                        ".node-title"
                    );


                if (title) {

                    title.textContent =
                        email.caseId ||
                        email.id;

                }


                const score =
                    node.querySelector(
                        "small"
                    );


                if (score) {

                    const caseScore =
                        Number(
                            email.correlationScore ??
                            email.score ??
                            0
                        );


                    score.textContent =
                        `CORRELATED · ${caseScore}`;

                }


                const subject =
                    node.querySelector(
                        "p"
                    );


                if (subject) {

                    subject.textContent =
                        email.subject ||
                        "";

                }


                positionCase(
                    node,
                    index,
                    relatedEmails.length
                );


                graphArea.appendChild(
                    node
                );


                caseNodes.push(
                    node
                );

            }
        );


        /* =====================================================
           UNIQUE EVIDENCE TYPES
           ===================================================== */

        const uniqueEvidence = [];

        const seenTypes = new Set();


        evidence.forEach(
            item => {

                const type =
                    normalizeIndicatorType(
                        item.indicator
                    );


                if (!type) {
                    return;
                }


                if (
                    seenTypes.has(type)
                ) {

                    return;

                }


                seenTypes.add(type);


                uniqueEvidence.push({
                    ...item,
                    indicator: type
                });

            }
        );


        /* =====================================================
           CREATE INDICATOR NODES
           ===================================================== */

        const indicatorNodes = {};


        uniqueEvidence.forEach(
            (item, index) => {

                const type =
                    normalizeIndicatorType(
                        item.indicator
                    );


                let template =
                    indicatorTemplates[type];


                /*
                 * Fallback for IP/subject/content/etc.
                 */

                if (!template) {

                    template =
                        indicatorTemplates.content ||
                        indicatorTemplates.hash ||
                        indicatorTemplates.sender ||
                        originalIndicators[0] ||
                        null;

                }


                if (!template) {

                    console.warn(
                        "No indicator template available:",
                        type
                    );

                    return;

                }


                const node =
                    template.cloneNode(true);


                /* =================================================
                   CLEAN OLD CLASSES
                   ================================================= */

                Array.from(
                    node.classList
                ).forEach(
                    className => {

                        if (
                            className.endsWith(
                                "-node"
                            ) &&
                            className !== "node"
                        ) {

                            node.classList.remove(
                                className
                            );

                        }

                    }
                );


                node.classList.add(
                    "dynamic-indicator",
                    `${type}-node`
                );


                node.classList.remove(
                    "indicator"
                );


                node.dataset.type =
                    type;


                node.dataset.score =
                    String(
                        Number(
                            item.score ??
                            item.strength ??
                            0
                        )
                    );


                /* =================================================
                   LABEL
                   ================================================= */

                const labels = {

                    sender:
                        "SAME SENDER",

                    domain:
                        "SAME DOMAIN",

                    url:
                        "SAME URL",

                    hash:
                        "SAME ATTACHMENT HASH",

                    ip:
                        "SAME IP",

                    subject:
                        "SIMILAR SUBJECT",

                    content:
                        "SIMILAR SUBJECT / BODY"

                };


                const title =
                    node.querySelector(
                        ".node-title"
                    );


                if (title) {

                    title.textContent =
                        labels[type] ||
                        formatIndicatorName(
                            type
                        );

                }


                /* =================================================
                   VALUE
                   ================================================= */

                const valueElement =
                    node.querySelector(
                        "small"
                    );


                if (valueElement) {

                    const rawValue =
                        item.currentValue ??
                        item.value ??
                        item.relatedValue ??
                        item.details ??
                        "—";


                    valueElement.textContent =
                        formatEvidenceValue(
                            rawValue
                        );

                }


                /* =================================================
                   POSITION
                   ================================================= */

                positionIndicator(
                    node,
                    index,
                    uniqueEvidence.length
                );


                graphArea.appendChild(
                    node
                );


                indicatorNodes[type] =
                    node;

            }
        );


        /* =====================================================
           SAVE STATE
           ===================================================== */

        graphState = {

            cases:
                relatedEmails,

            caseNodes:
                caseNodes,

            indicators:
                uniqueEvidence,

            indicatorNodes:
                indicatorNodes

        };


        window.__campaignGraph =
            graphState;


        /* =====================================================
           GRAPH SIZE
           ===================================================== */

        resizeGraphArea(
            caseNodes.length,
            uniqueEvidence.length
        );


        /* =====================================================
           FILTER BUTTONS
           ===================================================== */

        updateFilterButtons(
            uniqueEvidence
        );


        /* =====================================================
           DRAW AFTER LAYOUT
           ===================================================== */

        scheduleGraphDraw();

    }


    /* =========================================================
       DYNAMIC GRAPH SIZE
       ========================================================= */

    function resizeGraphArea(
        caseCount,
        indicatorCount
    ) {

        if (!graphArea) {
            return;
        }


        const maxCount =
            Math.max(
                caseCount,
                indicatorCount,
                1
            );


        let height;


        if (maxCount <= 2) {

            height = 430;

        } else if (maxCount <= 4) {

            height = 520;

        } else if (maxCount <= 6) {

            height = 620;

        } else if (maxCount <= 10) {

            height = 780;

        } else {

            height =
                780 +
                (
                    maxCount - 10
                ) * 70;

        }


        height =
            Math.min(
                Math.max(
                    height,
                    430
                ),
                1800
            );


        graphArea.style.height =
            `${height}px`;


        graphArea.style.minHeight =
            `${height}px`;

    }


    /* =========================================================
       CASE POSITION
       ========================================================= */

    function positionCase(
        node,
        index,
        total
    ) {

        if (
            !node ||
            !total
        ) {
            return;
        }


        /*
         * Explicit layouts for small graphs.
         * These keep the cases away from
         * the center email and each other.
         */

        const layouts = {

            1: [
                [84, 50]
            ],

            2: [
                [17, 22],
                [83, 22]
            ],

            3: [
                [17, 22],
                [83, 22],
                [50, 86]
            ],

            4: [
                [17, 20],
                [83, 20],
                [17, 82],
                [83, 82]
            ],

            5: [
                [50, 13],
                [13, 32],
                [87, 32],
                [24, 84],
                [76, 84]
            ],

            6: [
                [50, 13],
                [13, 27],
                [87, 27],
                [13, 73],
                [87, 73],
                [50, 87]
            ]

        };


        let point =
            layouts[total]?.[index];


        /*
         * For large graphs use a grid,
         * not an ever-growing circle.
         */

        if (!point) {

            const columns =
                total <= 9
                    ? 3
                    : 4;


            const rows =
                Math.ceil(
                    total /
                    columns
                );


            const col =
                index % columns;


            const row =
                Math.floor(
                    index / columns
                );


            const left =
                10 +
                (
                    col /
                    Math.max(
                        columns - 1,
                        1
                    )
                ) * 80;


            const top =
                12 +
                (
                    row /
                    Math.max(
                        rows - 1,
                        1
                    )
                ) * 76;


            point = [
                left,
                top
            ];

        }


        node.style.left =
            `${point[0]}%`;


        node.style.top =
            `${point[1]}%`;


        node.style.transform =
            "translate(-50%, -50%)";

    }


    /* =========================================================
       INDICATOR POSITION
       ========================================================= */

    function positionIndicator(
        node,
        index,
        total
    ) {

        if (
            !node ||
            !total
        ) {
            return;
        }


        const angle =
            (
                index /
                total
            ) *
            Math.PI *
            2 -
            Math.PI / 2;


        let radiusX = 25;
        let radiusY = 22;


        if (total >= 4) {

            radiusX = 27;
            radiusY = 25;

        }


        if (total >= 6) {

            radiusX = 29;
            radiusY = 28;

        }


        const left =
            50 +
            Math.cos(angle) *
            radiusX;


        const top =
            50 +
            Math.sin(angle) *
            radiusY;


        node.style.left =
            `${left}%`;


        node.style.top =
            `${top}%`;


        node.style.transform =
            "translate(-50%, -50%)";

    }


    /* =========================================================
       DRAW CONNECTIONS
       ========================================================= */

    function drawConnections() {

        if (
            !connectionsSvg ||
            !graphArea ||
            !currentNode
        ) {

            return;

        }


        /*
         * Always remove old lines first.
         */

        connectionsSvg.innerHTML = "";


        const graphRect =
            graphArea.getBoundingClientRect();


        if (
            graphRect.width <= 0 ||
            graphRect.height <= 0
        ) {

            return;

        }


        /*
         * SVG coordinate system is exactly
         * the same size as graph-area.
         */

        connectionsSvg.setAttribute(
            "viewBox",
            `0 0 ${graphRect.width} ${graphRect.height}`
        );


        connectionsSvg.setAttribute(
            "width",
            graphRect.width
        );


        connectionsSvg.setAttribute(
            "height",
            graphRect.height
        );


        connectionsSvg.setAttribute(
            "preserveAspectRatio",
            "none"
        );


        connectionsSvg.style.width =
            `${graphRect.width}px`;


        connectionsSvg.style.height =
            `${graphRect.height}px`;


        /* =====================================================
           ARROW MARKER
           ===================================================== */

        const defs =
            document.createElementNS(
                "http://www.w3.org/2000/svg",
                "defs"
            );


        const marker =
            document.createElementNS(
                "http://www.w3.org/2000/svg",
                "marker"
            );


        marker.setAttribute(
            "id",
            "campaign-arrow"
        );


        marker.setAttribute(
            "viewBox",
            "0 0 10 10"
        );


        marker.setAttribute(
            "refX",
            "8"
        );


        marker.setAttribute(
            "refY",
            "5"
        );


        marker.setAttribute(
            "markerWidth",
            "5"
        );


        marker.setAttribute(
            "markerHeight",
            "5"
        );


        marker.setAttribute(
            "orient",
            "auto"
        );


        marker.setAttribute(
            "markerUnits",
            "strokeWidth"
        );


        const arrow =
            document.createElementNS(
                "http://www.w3.org/2000/svg",
                "path"
            );


        arrow.setAttribute(
            "d",
            "M 0 0 L 10 5 L 0 10 z"
        );


        arrow.setAttribute(
            "fill",
            "#225568"
        );


        marker.appendChild(
            arrow
        );


        defs.appendChild(
            marker
        );


        connectionsSvg.appendChild(
            defs
        );


        /* =====================================================
           CENTER
           ===================================================== */

        function getCenter(element) {

            if (!element) {
                return null;
            }


            const rect =
                element.getBoundingClientRect();


            if (
                rect.width <= 0 ||
                rect.height <= 0
            ) {

                return null;

            }


            return {

                x:
                    rect.left +
                    rect.width / 2 -
                    graphRect.left,

                y:
                    rect.top +
                    rect.height / 2 -
                    graphRect.top

            };

        }


        /* =====================================================
           EDGE POINT
           ===================================================== */

        function getEdgePoint(
            element,
            targetPoint
        ) {

            if (
                !element ||
                !targetPoint
            ) {

                return null;

            }


            const rect =
                element.getBoundingClientRect();


            if (
                rect.width <= 0 ||
                rect.height <= 0
            ) {

                return null;

            }


            const center =
                getCenter(
                    element
                );


            if (!center) {
                return null;
            }


            const dx =
                targetPoint.x -
                center.x;


            const dy =
                targetPoint.y -
                center.y;


            if (
                dx === 0 &&
                dy === 0
            ) {

                return center;

            }


            const halfWidth =
                rect.width / 2;


            const halfHeight =
                rect.height / 2;


            const scaleX =
                dx === 0
                    ? Infinity
                    : halfWidth /
                      Math.abs(dx);


            const scaleY =
                dy === 0
                    ? Infinity
                    : halfHeight /
                      Math.abs(dy);


            const scale =
                Math.min(
                    scaleX,
                    scaleY
                );


            return {

                x:
                    center.x +
                    dx * scale,

                y:
                    center.y +
                    dy * scale

            };

        }


        /* =====================================================
           APPEND ONE CONNECTION
           ===================================================== */

        function appendConnection(
            fromElement,
            toElement,
            type,
            score
        ) {

            if (
                !fromElement ||
                !toElement
            ) {

                return;

            }


            /*
             * Do not create an edge if
             * either node isn't visible.
             */

            const fromStyle =
                window.getComputedStyle(
                    fromElement
                );


            const toStyle =
                window.getComputedStyle(
                    toElement
                );


            if (
                fromStyle.display === "none" ||
                toStyle.display === "none" ||
                fromStyle.visibility === "hidden" ||
                toStyle.visibility === "hidden"
            ) {

                return;

            }


            const fromCenter =
                getCenter(
                    fromElement
                );


            const toCenter =
                getCenter(
                    toElement
                );


            if (
                !fromCenter ||
                !toCenter
            ) {

                return;

            }


            const start =
                getEdgePoint(
                    fromElement,
                    toCenter
                );


            const end =
                getEdgePoint(
                    toElement,
                    fromCenter
                );


            if (
                !start ||
                !end
            ) {

                return;

            }


            const line =
                makeLine(
                    start,
                    end,
                    type,
                    score
                );


            connectionsSvg.appendChild(
                line
            );

        }


        /* =====================================================
           CURRENT EMAIL -> INDICATORS
           ===================================================== */

        Object.entries(
            graphState.indicatorNodes || {}
        ).forEach(
            ([type, indicatorNode]) => {

                if (!indicatorNode) {
                    return;
                }


                const evidenceItem =
                    graphState.indicators.find(
                        item =>
                            normalizeIndicatorType(
                                item.indicator
                            ) === type
                    );


                if (!evidenceItem) {
                    return;
                }


                appendConnection(
                    currentNode,
                    indicatorNode,
                    type,
                    Number(
                        evidenceItem.score ??
                        evidenceItem.strength ??
                        0
                    )
                );

            }
        );


        /* =====================================================
           INDICATORS -> RELATED CASES
           ===================================================== */

        graphState.cases.forEach(
            (email, caseIndex) => {

                if (!email) {
                    return;
                }


                const caseNode =
                    graphState.caseNodes[
                        caseIndex
                    ];


                if (!caseNode) {
                    return;
                }


                const matches =
                    Array.isArray(
                        email.matches
                    )
                        ? email.matches
                        : [];


                /*
                 * No matches = no edges.
                 */

                if (
                    matches.length === 0
                ) {

                    return;

                }


                matches.forEach(
                    match => {

                        const type =
                            normalizeIndicatorType(
                                match?.type
                            );


                        if (!type) {
                            return;
                        }


                        const indicatorNode =
                            graphState
                                .indicatorNodes[
                                    type
                                ];


                        /*
                         * No actual indicator node
                         * means absolutely no arrow.
                         */

                        if (!indicatorNode) {
                            return;
                        }


                        const score =
                            Number(
                                match?.score ??
                                match?.strength ??
                                email.correlationScore ??
                                0
                            );


                        appendConnection(
                            indicatorNode,
                            caseNode,
                            type,
                            score
                        );

                    }
                );

            }
        );


        /* =====================================================
           ACTIVE FILTER
           ===================================================== */

        const activeFilter =
            document.querySelector(
                ".filter.active"
            );


        if (
            activeFilter &&
            activeFilter.dataset.filter &&
            normalizeIndicatorType(
                activeFilter.dataset.filter
            ) !== "all"
        ) {

            applyFilter(
                activeFilter.dataset.filter
            );

        }

    }


    /* =========================================================
       CREATE SVG LINE
       ========================================================= */

    function makeLine(
        start,
        end,
        type,
        score
    ) {

        const line =
            document.createElementNS(
                "http://www.w3.org/2000/svg",
                "line"
            );


        line.setAttribute(
            "x1",
            start.x
        );


        line.setAttribute(
            "y1",
            start.y
        );


        line.setAttribute(
            "x2",
            end.x
        );


        line.setAttribute(
            "y2",
            end.y
        );


        line.dataset.type =
            normalizeIndicatorType(
                type
            );


        line.dataset.score =
            String(
                Number(
                    score || 0
                )
            );


        line.style.opacity =
            "0.8";


        line.style.strokeWidth =
            "1";


        line.setAttribute(
            "marker-end",
            "url(#campaign-arrow)"
        );


        return line;

    }


    /* =========================================================
       FILTER BUTTONS
       ========================================================= */

    function updateFilterButtons(
        evidence
    ) {

        const available =
            new Set(
                evidence.map(
                    item =>
                        normalizeIndicatorType(
                            item.indicator
                        )
                )
            );


        filters.forEach(button => {

            const type =
                normalizeIndicatorType(
                    button.dataset.filter
                );


            if (
                type === "all" ||
                type === "high"
            ) {

                button.style.display =
                    "";

                return;

            }


            button.style.display =
                available.has(type)
                    ? ""
                    : "none";

        });


        const highButton =
            document.querySelector(
                '.filter[data-filter="high"]'
            );


        if (highButton) {

            const highCount =
                evidence.filter(
                    item =>
                        Number(
                            item.score ??
                            item.strength ??
                            0
                        ) >= 70
                ).length;


            const count =
                highButton.querySelector(
                    "b"
                );


            if (count) {

                count.textContent =
                    highCount;

            }

        }

    }


    /* =========================================================
       TIMELINE
       ========================================================= */

    function updateTimeline(data) {

        const timelineContainer =
            document.querySelector(
                ".timeline"
            );


        if (!timelineContainer) {
            return;
        }


        const timeline =
            Array.isArray(
                data.timeline
            )
                ? data.timeline
                : [];


        timelineContainer
            .querySelectorAll(
                ".timeline-item"
            )
            .forEach(
                item => {
                    item.remove();
                }
            );


        if (
            timeline.length === 0
        ) {

            return;
        }
        const uniqueTimeline = [];
        const seenTimeline = new Set();
        timeline.forEach(event => {

            const caseId =
                event.caseId ||
                event.id ||
                "";

            const title =
                String(
                    event.title ||
                    event.subject ||
                    event.type ||
                    ""
                )
                    .replace(
                        /\bobserved\s+observed\b/gi,
                        "observed"
                    )
                    .replace(
                        /\s+/g,
                        " "
                    )
                    .trim();

            const date =
                event.date
                    ? new Date(
                        event.date
                    ).toISOString()
                    : "";

            const key =
                `${date}|${caseId}|${title}`;

            if (
                seenTimeline.has(key)
            ) {
                return;
            }

            seenTimeline.add(key);

            uniqueTimeline.push(event);

        });

        uniqueTimeline.forEach(
            event => {

                const item =
                    document.createElement(
                        "div"
                    );


                item.className =
                    "timeline-item";


                if (
                    event.type === "current"
                ) {

                    item.classList.add(
                        "current"
                    );

                }


                const dot =
                    document.createElement(
                        "div"
                    );


                dot.className =
                    "timeline-dot";


                const date =
                    document.createElement(
                        "small"
                    );


                date.textContent =
                    formatDate(
                        event.date
                    );


                const title =
                    document.createElement(
                        "strong"
                    );


                title.textContent =
                    String(
                        event.title ||
                        event.subject ||
                        event.type ||
                        "Campaign activity"
                    )
                        .replace(
                            /\bobserved\s+observed\b/gi,
                            "observed"
                        )
                        .replace(
                            /\s+/g,
                            " "
                        )
                        .trim();


                const caseId =
                    document.createElement(
                        "span"
                    );


                caseId.textContent =
                    event.caseId ||
                    event.id ||
                    "";


                item.appendChild(dot);
                item.appendChild(date);
                item.appendChild(title);
                item.appendChild(caseId);


                timelineContainer.appendChild(
                    item
                );

            }
        );

    }


    /* =========================================================
       SUMMARY
       ========================================================= */

    function updateSummary(data) {

        const summary =
            document.querySelector(
                ".campaign-summary"
            );


        if (!summary) {
            return;
        }


        const title =
            summary.querySelector(
                "h3"
            );


        if (
            title &&
            data.currentEmail
        ) {

            title.textContent =
                data.currentEmail.subject ||
                "";

        }


        const rows =
            summary.querySelectorAll(
                ".summary-row strong"
            );


        if (rows.length) {

            rows[0].textContent =
                String(
                    data.stats?.relatedCases || 0
                ).padStart(
                    2,
                    "0"
                );

        }


        const chips =
            summary.querySelector(
                ".chips"
            );


        if (
            chips &&
            Array.isArray(
                data.evidence
            )
        ) {

            chips.innerHTML = "";
            const seenTypes = new Set();
            data.evidence.forEach(evidence => {

                const type =
                    normalizeIndicatorType(
                        evidence.indicator
                    );

                if (
                    !type ||
                    seenTypes.has(type)
                ) {
                    return;
                }

                seenTypes.add(type);

                const chip =
                    document.createElement(
                        "span"
                    );

                chip.textContent =
                    getCorrelationLabel(
                        type
                    );

                chips.appendChild(
                    chip
                );

            });

            

        }

    }


    /* =========================================================
       EVIDENCE TABLE
       ========================================================= */

    function updateEvidenceTable(data) {

        const tbody =
            document.querySelector(
                ".evidence-table-panel table tbody"
            );


        if (!tbody) {
            return;
        }


        tbody.innerHTML = "";


        const evidence =
            Array.isArray(
                data.evidence
            )
                ? data.evidence
                : [];

        const uniqueEvidence = [];
        const seenTypes = new Set();

        evidence.forEach(item => {

            const type =
                normalizeIndicatorType(
                    item.indicator
                );

            if (
                !type ||
                seenTypes.has(type)
            ) {
                return;
            }

            seenTypes.add(type);

            uniqueEvidence.push({
                ...item,
                indicator: type
            });

        });
        uniqueEvidence.forEach(
            item => {

                const row =
                    document.createElement(
                        "tr"
                    );


                const indicator =
                    document.createElement(
                        "td"
                    );


                const current =
                    document.createElement(
                        "td"
                    );


                const previous =
                    document.createElement(
                        "td"
                    );


                const match =
                    document.createElement(
                        "td"
                    );


                const type =
                    normalizeIndicatorType(
                        item.indicator
                    );


                indicator.textContent =
                    `✓  ${formatIndicatorName(
                        type
                    )}`;


                current.textContent =
                    formatEvidenceValue(
                        item.currentValue ??
                        item.value ??
                        "—"
                    );


                previous.textContent =
                    formatEvidenceValue(
                        item.relatedValue ??
                        "—"
                    );


                match.innerHTML =
                    item.match
                        ? '<span class="match">MATCH</span>'
                        : '<span class="similar">SIMILAR</span>';


                row.appendChild(indicator);
                row.appendChild(current);
                row.appendChild(previous);
                row.appendChild(match);


                tbody.appendChild(row);

            }
        );

    }


    /* =========================================================
       FORMAT INDICATOR
       ========================================================= */

    function formatIndicatorName(value) {

        const type =
            normalizeIndicatorType(
                value
            );


        if (!type) {
            return "Indicator";
        }


        if (type === "hash") {
            return "Attachment Hash";
        }


        if (type === "url") {
            return "URL";
        }


        if (type === "ip") {
            return "IP";
        }


        return String(type)
            .replace(
                /[-_]/g,
                " "
            )
            .replace(
                /\b\w/g,
                char =>
                    char.toUpperCase()
            );

    }


    /* =========================================================
       FORMAT DATE
       ========================================================= */

    function formatDate(value) {

        if (!value) {
            return "—";
        }


        const date =
            new Date(value);


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {

            return String(value);

        }


        return date.toLocaleDateString(
            "en-US",
            {
                month: "short",
                day: "2-digit",
                year: "numeric"
            }
        );

    }


    /* =========================================================
       RESIZE
       ========================================================= */

    window.addEventListener(
        "resize",
        () => {

            scheduleGraphDraw();

        }
    );


    /* =========================================================
       INITIAL LOAD
       ========================================================= */

    loadCampaignData();


    /* =========================================================
       FOOTER
       ========================================================= */

    const footer =
        document.querySelector(
            "footer span:first-child"
        );


    if (footer) {

        footer.addEventListener(
            "click",
            () => {
                footer.textContent =
                    "◷ Last synced just now";

            }
        );

    }

});