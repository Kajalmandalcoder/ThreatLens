/* =========================================================
   THREATLENS — CAMPAIGN CORRELATION
========================================================= */


/* =========================================================
   CONFIG
========================================================= */

const API_BASE_URL = "http://localhost:5001/api/emails";


/* =========================================================
   STATE
========================================================= */

let currentCaseId = null;
let correlationData = null;
let cy = null;


/* =========================================================
   DOM ELEMENTS
========================================================= */

const graphContainer = document.getElementById("campaignGraph");
const graphLoading = document.getElementById("graphLoading");

const currentCaseIdEl =
    document.getElementById("currentCaseId");

const currentCaseSubjectEl =
    document.getElementById("currentCaseSubject");

const currentCaseSenderEl =
    document.getElementById("currentCaseSender");

const relatedCaseCountEl =
    document.getElementById("relatedCaseCount");

const detailsEmpty =
    document.getElementById("detailsEmpty");

const caseDetailsContent =
    document.getElementById("caseDetailsContent");

const detailCaseId =
    document.getElementById("detailCaseId");

const detailSubject =
    document.getElementById("detailSubject");

const detailSender =
    document.getElementById("detailSender");

const detailStrength =
    document.getElementById("detailStrength");

const detailMatchCount =
    document.getElementById("detailMatchCount");

const matchedIndicatorsList =
    document.getElementById("matchedIndicatorsList");

const noCorrelation =
    document.getElementById("noCorrelation");

const fitGraphBtn =
    document.getElementById("fitGraphBtn");

const resetGraphBtn =
    document.getElementById("resetGraphBtn");

const closeDetailsBtn =
    document.getElementById("closeDetailsBtn");

const openCaseBtn =
    document.getElementById("openCaseBtn");


/* =========================================================
   GET CASE ID FROM URL
========================================================= */

function getCaseIdFromURL() {

    const params =
        new URLSearchParams(window.location.search);

    return params.get("caseId");
}


/* =========================================================
   INITIALIZE
========================================================= */

document.addEventListener("DOMContentLoaded", () => {

    currentCaseId = getCaseIdFromURL();

    if (!currentCaseId) {

        showError(
            "No case ID was provided in the URL."
        );

        return;
    }

    loadCampaignCorrelations();
});


/* =========================================================
   LOAD CORRELATIONS
========================================================= */

async function loadCampaignCorrelations() {

    showLoading(true);

    try {

        const response = await fetch(
            `${API_BASE_URL}/case/${encodeURIComponent(
                currentCaseId
            )}/correlations`
        );


        if (!response.ok) {

            throw new Error(
                `API request failed: ${response.status}`
            );
        }


        const result = await response.json();

        console.log("Correlation API response:", result);

        if (!result.success || !result.data) {
            throw new Error("Invalid correlation API response");
        }

        correlationData = result.data;

        renderCurrentCase();

        renderCorrelationGraph();


    } catch (error) {

        console.error(
            "Campaign correlation error:",
            error
        );

        showError(
            "Unable to load campaign correlations."
        );

    } finally {

        showLoading(false);
    }
}


/* =========================================================
   CURRENT CASE
========================================================= */

function renderCurrentCase() {
    const currentCase = correlationData?.currentCase;

    if (!currentCase) {
        currentCaseIdEl.textContent = currentCaseId || "Unknown";
        currentCaseSubjectEl.textContent = "Unknown subject";
        currentCaseSenderEl.textContent = "Unknown sender";
        relatedCaseCountEl.textContent = "0";
        return;
    }

    currentCaseIdEl.textContent =
        currentCase.caseId || currentCaseId || "Unknown";

    currentCaseSubjectEl.textContent =
        currentCase.subject || "Unknown subject";

    currentCaseSenderEl.textContent =
        currentCase.sender || "Unknown sender";

    const relatedCases = correlationData?.relatedCases || [];

    relatedCaseCountEl.textContent = relatedCases.length;
}
/* =========================================================
   CREATE GRAPH
========================================================= */

/* =========================================================
   CREATE GRAPH
========================================================= */

function renderCorrelationGraph() {

    const currentCase =
        correlationData?.currentCase;

    const relatedCases =
        correlationData?.relatedCases || [];


    /* =====================================================
       VALIDATE CURRENT CASE
    ===================================================== */

    if (!currentCase) {

        showError(
            "Current case information is unavailable."
        );

        return;
    }


    /* =====================================================
       NO CORRELATIONS
    ===================================================== */

    if (relatedCases.length === 0) {

        noCorrelation.classList.remove("hidden");

        graphContainer.innerHTML = "";

        return;
    }


    noCorrelation.classList.add("hidden");


    /* =====================================================
       GRAPH ELEMENTS
    ===================================================== */

    const elements = [];


    /* =====================================================
       CURRENT CASE NODE
    ===================================================== */

    elements.push({

        data: {

            id: "current-case",

            label:
                formatCaseLabel(
                    currentCase.caseId
                ),

            caseId:
                currentCase.caseId,

            subject:
                currentCase.subject || "",

            sender:
                currentCase.sender || "",

            type: "current",

            strength: "CURRENT"

        }

    });


    /* =====================================================
       RELATED CASES + EDGES
    ===================================================== */

    relatedCases.forEach(
        (relatedCase, index) => {

            const nodeId =
                `case-${index}`;


            const strength =
                normalizeStrength(
                    relatedCase.strength
                );


            const matchCount =
                Number(
                    relatedCase.matchCount || 0
                );


            /* =============================================
               RELATED CASE NODE
            ============================================= */

            elements.push({

                data: {

                    id: nodeId,

                    label:
                        formatCaseLabel(
                            relatedCase.caseId
                        ),

                    caseId:
                        relatedCase.caseId,

                    subject:
                        relatedCase.subject || "",

                    sender:
                        relatedCase.sender || "",

                    matchCount,

                    strength,

                    type: "related",

                    correlation:
                        relatedCase

                }

            });


            /* =============================================
               CONNECTION
            ============================================= */

            elements.push({

                data: {

                    id:
                        `edge-${index}`,

                    source:
                        "current-case",

                    target:
                        nodeId,

                    label:
                        `${matchCount} MATCHES`,

                    strength,

                    matchCount,

                    correlation:
                        relatedCase

                }

            });

        }
    );


    /* =====================================================
       DESTROY OLD GRAPH
    ===================================================== */

    if (cy) {

        cy.destroy();

        cy = null;
    }


    /* =====================================================
       CREATE CYTOSCAPE GRAPH
    ===================================================== */

    cy = cytoscape({

        container:
            graphContainer,

        elements,


        /* =================================================
           CLEAN RADIAL LAYOUT
        ================================================= */

        layout: {

            name: "concentric",

            animate: true,

            animationDuration: 800,

            fit: true,

            padding: 80,

            avoidOverlap: true,

            minNodeSpacing: 110,

            concentric: function(node) {

                return node.data("type") ===
                    "current"
                    ? 2
                    : 1;
            },

            levelWidth: function() {

                return 1;
            }

        },


        /* =================================================
           GRAPH STYLE
        ================================================= */

        style: [

            /* =============================================
               RELATED CASE BOXES
            ============================================= */

            {
                selector:
                    'node[type="related"]',

                style: {

                    "shape":
                        "roundrectangle",

                    "width":
                        155,

                    "height":
                        78,

                    "background-color":
                        "#111c2b",

                    "border-width":
                        2,

                    "border-color":
                        "#34445a",

                    "label":
                        "data(label)",

                    "color":
                        "#dce5ef",

                    "font-size":
                        10,

                    "font-weight":
                        700,

                    "text-wrap":
                        "wrap",

                    "text-max-width":
                        125,

                    "text-valign":
                        "center",

                    "text-halign":
                        "center",

                    "padding":
                        8,

                    "overlay-opacity":
                        0,

                    "z-index":
                        10
                }

            },


            /* =============================================
               CURRENT CASE BOX
            ============================================= */

            {
                selector:
                    'node[type="current"]',

                style: {

                    "shape":
                        "roundrectangle",

                    "width":
                        185,

                    "height":
                        98,

                    "background-color":
                        "#0d2a38",

                    "border-width":
                        3,

                    "border-color":
                        "#27c7e8",

                    "label":
                        "data(label)",

                    "color":
                        "#ffffff",

                    "font-size":
                        11,

                    "font-weight":
                        750,

                    "text-wrap":
                        "wrap",

                    "text-max-width":
                        155,

                    "text-valign":
                        "center",

                    "text-halign":
                        "center",

                    "padding":
                        10,

                    "shadow-blur":
                        28,

                    "shadow-color":
                        "#20b8dc",

                    "shadow-opacity":
                        0.28,

                    "shadow-offset-x":
                        0,

                    "shadow-offset-y":
                        0,

                    "z-index":
                        20
                }

            },


            /* =============================================
               STRONG CASE
            ============================================= */

            {
                selector:
                    'node[type="related"][strength="STRONG"]',

                style: {

                    "background-color":
                        "#28151d",

                    "border-color":
                        "#e85d75",

                    "border-width":
                        2.5,

                    "shadow-blur":
                        16,

                    "shadow-color":
                        "#e85d75",

                    "shadow-opacity":
                        0.20
                }

            },


            /* =============================================
               MEDIUM CASE
            ============================================= */

            {
                selector:
                    'node[type="related"][strength="MEDIUM"]',

                style: {

                    "background-color":
                        "#251e12",

                    "border-color":
                        "#e7ad4e",

                    "border-width":
                        2.5,

                    "shadow-blur":
                        14,

                    "shadow-color":
                        "#e7ad4e",

                    "shadow-opacity":
                        0.18
                }

            },


            /* =============================================
               WEAK CASE
            ============================================= */

            {
                selector:
                    'node[type="related"][strength="WEAK"]',

                style: {

                    "background-color":
                        "#111d2b",

                    "border-color":
                        "#4d91c5",

                    "border-width":
                        2
                }

            },


            /* =============================================
               ALL EDGES
            ============================================= */

            {
                selector:
                    "edge",

                style: {

                    "width":
                        2,

                    "line-color":
                        "#3b536a",

                    "target-arrow-color":
                        "#3b536a",

                    "target-arrow-shape":
                        "triangle",

                    "arrow-scale":
                        0.65,

                    "curve-style":
                        "bezier",

                    "control-point-step-size":
                        40,

                    "label":
                        "data(label)",

                    "color":
                        "#9aabbd",

                    "font-size":
                        8,

                    "font-weight":
                        750,

                    "text-rotation":
                        "autorotate",

                    "text-background-color":
                        "#090e16",

                    "text-background-opacity":
                        1,

                    "text-background-padding":
                        5,

                    "text-border-width":
                        1,

                    "text-border-color":
                        "#263344",

                    "text-border-opacity":
                        1,

                    "overlay-opacity":
                        0,

                    "z-index":
                        5
                }

            },


            /* =============================================
               STRONG EDGE
            ============================================= */

            {
                selector:
                    'edge[strength="STRONG"]',

                style: {

                    "line-color":
                        "#e85d75",

                    "target-arrow-color":
                        "#e85d75",

                    "width":
                        3,

                    "color":
                        "#f08a9c",

                    "shadow-blur":
                        8,

                    "shadow-color":
                        "#e85d75",

                    "shadow-opacity":
                        0.30
                }

            },


            /* =============================================
               MEDIUM EDGE
            ============================================= */

            {
                selector:
                    'edge[strength="MEDIUM"]',

                style: {

                    "line-color":
                        "#e7ad4e",

                    "target-arrow-color":
                        "#e7ad4e",

                    "width":
                        2.5,

                    "color":
                        "#e9b85e"
                }

            },


            /* =============================================
               WEAK EDGE
            ============================================= */

            {
                selector:
                    'edge[strength="WEAK"]',

                style: {

                    "line-color":
                        "#4d91c5",

                    "target-arrow-color":
                        "#4d91c5",

                    "width":
                        2,

                    "color":
                        "#69b3e8"
                }

            },


            /* =============================================
               SELECTED NODE / EDGE
            ============================================= */

            {
                selector:
                    ":selected",

                style: {

                    "border-color":
                        "#ffffff",

                    "border-width":
                        3,

                    "line-color":
                        "#ffffff",

                    "target-arrow-color":
                        "#ffffff",

                    "z-index":
                        999
                }

            }

        ]

    });


    /* =====================================================
       NODE CLICK
    ===================================================== */

    cy.on(
        "tap",
        "node",
        function(event) {

            const node =
                event.target;


            /* CURRENT CASE */

            if (
                node.data("type") ===
                "current"
            ) {

                showCurrentCaseDetails();

                return;
            }


            /* RELATED CASE */

            const correlation =
                node.data("correlation");


            if (correlation) {

                showCorrelationDetails(
                    correlation
                );
            }

        }
    );


    /* =====================================================
       EDGE CLICK
    ===================================================== */

    cy.on(
        "tap",
        "edge",
        function(event) {

            const edge =
                event.target;


            const correlation =
                edge.data("correlation");


            if (correlation) {

                showCorrelationDetails(
                    correlation
                );
            }

        }
    );


    /* =====================================================
       NODE HOVER
    ===================================================== */

    cy.on(
        "mouseover",
        "node",
        function(event) {

            const node =
                event.target;


            if (
                node.data("type") ===
                "current"
            ) {

                node.animate({

                    style: {

                        width: 195,

                        height: 106
                    }

                }, {

                    duration: 180

                });

            } else {

                node.animate({

                    style: {

                        width: 165,

                        height: 84
                    }

                }, {

                    duration: 180

                });

            }

        }
    );


    /* =====================================================
       NODE MOUSE OUT
    ===================================================== */

    cy.on(
        "mouseout",
        "node",
        function(event) {

            const node =
                event.target;


            if (
                node.data("type") ===
                "current"
            ) {

                node.animate({

                    style: {

                        width: 185,

                        height: 98
                    }

                }, {

                    duration: 180

                });

            } else {

                node.animate({

                    style: {

                        width: 155,

                        height: 78
                    }

                }, {

                    duration: 180

                });

            }

        }
    );


    /* =====================================================
       FIT GRAPH AFTER RENDER
    ===================================================== */

    setTimeout(() => {

        if (!cy) {
            return;
        }

        cy.resize();

        cy.fit(
            cy.elements(),
            80
        );

    }, 100);


    /* =====================================================
       FINAL LAYOUT
    ===================================================== */

    cy.layout({

        name:
            "concentric",

        animate:
            true,

        animationDuration:
            700,

        fit:
            true,

        padding:
            80,

        avoidOverlap:
            true,

        minNodeSpacing:
            110,

        concentric: function(node) {

            return node.data("type") ===
                "current"
                ? 2
                : 1;
        },

        levelWidth: function() {

            return 1;
        }

    }).run();

}


/* =========================================================
   SHOW CORRELATION DETAILS
========================================================= */

function showCorrelationDetails(
    correlation
) {

    if (!correlation) {
        return;
    }


    detailsEmpty.classList.add(
        "hidden"
    );

    caseDetailsContent.classList.remove(
        "hidden"
    );


    detailCaseId.textContent =
        correlation.caseId || "-";


    detailSubject.textContent =
        correlation.subject ||
        "Unknown subject";


    detailSender.textContent =
        correlation.sender ||
        "Unknown sender";


    detailMatchCount.textContent =
        correlation.matchCount || 0;


    const strength =
        normalizeStrength(
            correlation.strength
        );


    detailStrength.textContent =
        strength;


    detailStrength.className =
        `strength-badge ${strength.toLowerCase()}`;


    renderMatchedIndicators(
        correlation
    );


    /* Open Case button */

    openCaseBtn.onclick = () => {

        openCaseDetails(
            correlation.caseId
        );
    };
}


/* =========================================================
   CURRENT CASE DETAILS
========================================================= */

function showCurrentCaseDetails() {

    const currentCase =
        correlationData?.currentCase;


    if (!currentCase) {
        return;
    }


    detailsEmpty.classList.add(
        "hidden"
    );

    caseDetailsContent.classList.remove(
        "hidden"
    );


    detailCaseId.textContent =
        currentCase.caseId || "-";


    detailSubject.textContent =
        currentCase.subject ||
        "Unknown subject";


    detailSender.textContent =
        currentCase.sender ||
        "Unknown sender";


    detailMatchCount.textContent =
        "CURRENT";


    detailStrength.textContent =
        "CURRENT CASE";


    detailStrength.className =
        "strength-badge weak";


    matchedIndicatorsList.innerHTML = `

        <div class="indicator-item">

            <div class="indicator-icon">
                ◎
            </div>

            <div class="indicator-info">

                <div class="indicator-type">
                    Case
                </div>

                <div class="indicator-value">
                    Currently investigated case
                </div>

            </div>

        </div>

    `;


    openCaseBtn.onclick = () => {

        openCaseDetails(
            currentCase.caseId
        );
    };
}


/* =========================================================
   MATCHED INDICATORS
========================================================= */

function renderMatchedIndicators(
    correlation
) {

    matchedIndicatorsList.innerHTML = "";


    const matches =
        correlation.matches || {};


    let hasIndicator = false;


    /* =========================
       IP
    ========================== */

    if (
        Array.isArray(matches.ip) &&
        matches.ip.length > 0
    ) {

        hasIndicator = true;

        matches.ip.forEach(ip => {

            addIndicator(
                "IP",
                ip,
                "◉",
                "IP Intelligence"
            );

        });
    }


    /* =========================
       DOMAIN
    ========================== */

    if (
        Array.isArray(matches.domain) &&
        matches.domain.length > 0
    ) {

        hasIndicator = true;

        matches.domain.forEach(domain => {

            addIndicator(
                "DOMAIN",
                domain,
                "◎",
                "Domain Intelligence"
            );

        });
    }


    /* =========================
       URL
    ========================== */

    if (
        Array.isArray(matches.url) &&
        matches.url.length > 0
    ) {

        hasIndicator = true;

        matches.url.forEach(url => {

            addIndicator(
                "URL",
                url,
                "↗",
                "URL Intelligence"
            );

        });
    }


    /* =========================
       ATTACHMENT
    ========================== */

    if (
        Array.isArray(matches.attachment) &&
        matches.attachment.length > 0
    ) {

        hasIndicator = true;

        matches.attachment.forEach(hash => {

            addIndicator(
                "ATTACHMENT",
                hash,
                "▣",
                "Attachment Intelligence"
            );

        });
    }


    /* =========================
       HEADER
    ========================== */

    if (
        matches.header
    ) {

        hasIndicator = true;

        addIndicator(
            "HEADER",
            matches.header,
            "≡",
            "Header Forensics"
        );
    }


    /* =========================
       FALLBACK
    ========================== */

    if (!hasIndicator) {

        matchedIndicatorsList.innerHTML = `

            <div class="indicator-item">

                <div class="indicator-icon">
                    ?
                </div>

                <div class="indicator-info">

                    <div class="indicator-type">
                        Correlation
                    </div>

                    <div class="indicator-value">
                        ${correlation.matchCount || 0}
                        matching indicators detected
                    </div>

                </div>

            </div>

        `;
    }
}


/* =========================================================
   ADD INDICATOR
========================================================= */

function addIndicator(
    type,
    value,
    icon,
    destination
) {

    const item =
        document.createElement("div");


    item.className =
        "indicator-item";


    item.title =
        `Open ${destination}`;


    item.innerHTML = `

        <div class="indicator-icon">
            ${escapeHTML(icon)}
        </div>

        <div class="indicator-info">

            <div class="indicator-type">
                ${escapeHTML(type)}
            </div>

            <div class="indicator-value">
                ${escapeHTML(String(value))}
            </div>

        </div>

    `;


    item.addEventListener(
        "click",
        () => {

            handleIndicatorClick(
                type,
                value
            );

        }
    );


    matchedIndicatorsList.appendChild(
        item
    );
}


/* =========================================================
   INDICATOR CLICK
========================================================= */

function handleIndicatorClick(
    type,
    value
) {

    console.log(
        "Indicator selected:",
        type,
        value
    );


    /*
       Abhi existing intelligence pages
       connect nahi kar rahe.

       Next phase mein:
       IP       → IP Intelligence
       DOMAIN   → Domain Intelligence
       URL      → URL Intelligence
       ATTACHMENT→ Attachment Intelligence
       HEADER   → Header Forensics

       connect kar sakte hain.
    */
}


/* =========================================================
   OPEN CASE DETAILS
========================================================= */

function openCaseDetails(
    caseId
) {

    if (!caseId) {
        return;
    }


    /*
       Current case_detail.html
       ko caseId ke saath open karega.
    */

    window.location.href =
        `case_detail.html?caseId=${encodeURIComponent(
            caseId
        )}`;
}


/* =========================================================
   FIT GRAPH
========================================================= */

if (fitGraphBtn) {

    fitGraphBtn.addEventListener(
        "click",
        () => {

            if (!cy) {
                return;
            }

            cy.fit(
                cy.elements(),
                70
            );

        }
    );
}


/* =========================================================
   RESET GRAPH
========================================================= */

if (resetGraphBtn) {

    resetGraphBtn.addEventListener(
        "click",
        () => {

            if (!cy) {
                return;
            }


            cy.elements().unselect();


            cy.layout({

                name: "cose",

                animate: true,

                animationDuration: 600,

                fit: true,

                padding: 70,

                nodeRepulsion: 10000,

                idealEdgeLength: 180

            }).run();


            showCurrentCaseDetails();

        }
    );
}


/* =========================================================
   CLOSE DETAILS
========================================================= */

if (closeDetailsBtn) {

    closeDetailsBtn.addEventListener(
        "click",
        () => {

            detailsEmpty.classList.remove(
                "hidden"
            );

            caseDetailsContent.classList.add(
                "hidden"
            );


            if (cy) {

                cy.elements().unselect();

            }

        }
    );
}


/* =========================================================
   LOADING
========================================================= */

function showLoading(
    isLoading
) {

    if (!graphLoading) {
        return;
    }


    if (isLoading) {

        graphLoading.style.display =
            "flex";

    } else {

        graphLoading.style.display =
            "none";
    }
}


/* =========================================================
   ERROR
========================================================= */

function showError(
    message
) {

    showLoading(false);


    graphContainer.innerHTML = `

        <div
            style="
                height:100%;
                min-height:400px;
                display:flex;
                flex-direction:column;
                align-items:center;
                justify-content:center;
                text-align:center;
                padding:30px;
                color:#8793a4;
            "
        >

            <div
                style="
                    font-size:30px;
                    margin-bottom:15px;
                "
            >
                ⚠
            </div>

            <h3
                style="
                    color:#cbd4df;
                    font-size:14px;
                    margin-bottom:8px;
                "
            >
                Correlation Analysis Failed
            </h3>

            <p
                style="
                    font-size:11px;
                    max-width:400px;
                    line-height:1.6;
                "
            >
                ${escapeHTML(message)}
            </p>

        </div>

    `;
}


/* =========================================================
   HELPERS
========================================================= */

function normalizeStrength(
    strength
) {

    if (!strength) {
        return "WEAK";
    }


    return String(strength)
        .trim()
        .toUpperCase();
}


function formatCaseLabel(
    caseId
) {

    if (!caseId) {
        return "CASE";
    }


    return caseId
        .replace("CASE-", "CASE\n");
}


function escapeHTML(
    value
) {

    const div =
        document.createElement("div");

    div.textContent =
        value ?? "";

    return div.innerHTML;
}