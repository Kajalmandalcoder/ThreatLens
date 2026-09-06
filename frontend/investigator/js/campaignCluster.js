document.addEventListener("DOMContentLoaded", () => {

    /* =========================================================
       API
       ========================================================= */

    const CLUSTERS_API =
        "http://localhost:5001/api/campaigns/clusters";

    const GRAPH_API =
        "http://localhost:5001/api/campaigns/graph";


    /* =========================================================
       ELEMENTS
       ========================================================= */

    const clustersGrid =
        document.getElementById(
            "clustersGrid"
        );

    const status =
        document.getElementById(
            "clustersStatus"
        );

    const campaignCount =
        document.getElementById(
            "campaignCount"
        );

    const emailCount =
        document.getElementById(
            "emailCount"
        );

    const refreshButton =
        document.getElementById(
            "refreshClusters"
        );

    const drawer =
        document.getElementById(
            "clusterDrawer"
        );

    const drawerClose =
        document.getElementById(
            "drawerClose"
        );

    const drawerCaseId =
        document.getElementById(
            "drawerCaseId"
        );

    const drawerSubject =
        document.getElementById(
            "drawerSubject"
        );

    const drawerScore =
        document.getElementById(
            "drawerScore"
        );

    const drawerMatchCount =
        document.getElementById(
            "drawerMatchCount"
        );

    const drawerMatches =
        document.getElementById(
            "drawerMatches"
        );

    const drawerDate =
        document.getElementById(
            "drawerDate"
        );


    /* =========================================================
       HELPERS
       ========================================================= */

    function escapeHtml(value) {

        return String(
            value ?? ""
        )
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
    function normalizeRelationType(type) {

            const value =
                String(type || "")
                    .trim()
                    .toLowerCase();

            if (value === "attachment") {
                return "attachment";
            }

            if (value === "hash") {
                return "hash";
            }

            if (value === "sender") {
                return "sender";
            }

            if (value === "domain") {
                return "domain";
            }

            if (value === "url") {
                return "url";
            }

            if (value === "ip") {
                return "ip";
            }

            if (value === "content") {
                return "content";
            }

            if (value === "subject") {
                return "subject";
            }

            return "unknown";
        }


    function formatMatchValue(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return "—";

        }


        if (
            typeof value === "object"
        ) {

            const subject =
                value.subject_similarity ??
                value.subjectSimilarity;


            const body =
                value.body_similarity ??
                value.bodySimilarity;


            const strongest =
                value.strongest_similarity ??
                value.strongestSimilarity;


            const parts = [];


            if (
                subject !== undefined &&
                subject !== null
            ) {

                parts.push(
                    `Subject ${subject}%`
                );

            }


            if (
                body !== undefined &&
                body !== null
            ) {

                parts.push(
                    `Body ${body}%`
                );

            }


            if (parts.length) {

                return parts.join(
                    " · "
                );

            }


            if (
                strongest !== undefined &&
                strongest !== null
            ) {

                return (
                    `Strongest ${strongest}%`
                );

            }


            try {

                return JSON.stringify(
                    value
                );

            } catch {

                return "—";

            }

        }


        return String(value);

    }


    /* =========================================================
       FETCH ALL CLUSTERS
       ========================================================= */

    async function fetchClusters() {

        const response =
            await fetch(
                CLUSTERS_API,
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
                "Clusters API failed"
            );

        }


        return Array.isArray(
            result.data?.clusters
        )
            ? result.data.clusters
            : [];

    }


    /* =========================================================
       FETCH PARTICULAR EMAIL GRAPH
       ========================================================= */

    async function fetchEmailGraph(
        emailId
    ) {

        const response =
            await fetch(
                `${GRAPH_API}?emailId=${encodeURIComponent(
                    emailId
                )}`,
                {
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Graph API returned ${response.status}`
            );

        }


        const result =
            await response.json();


        if (!result.success) {

            throw new Error(
                result.message ||
                "Graph API failed"
            );

        }


        return result.data || {};

    }


    /* =========================================================
       BUILD RELATIONS INSIDE ONE CLUSTER
       ========================================================= */

    async function buildClusterRelations(
        cluster
    ) {

        const members =
            Array.isArray(
                cluster.emails
            )
                ? cluster.emails
                : [];


        const memberIds =
            new Set(
                members.map(
                    email =>
                        String(
                            email.id
                        )
                )
            );


        const relationMap =
            new Map();


        await Promise.all(

            members.map(
                async email => {

                    if (!email?.id) {
                        return;
                    }


                    try {

                        const graph =
                            await fetchEmailGraph(
                                email.id
                            );


                        const related =
                            Array.isArray(
                                graph.relatedEmails
                            )
                                ? graph.relatedEmails
                                : [];


                        related.forEach(
                            relation => {

                                const source =
                                    String(
                                        email.id
                                    );


                                const target =
                                    String(
                                        relation.id
                                    );


                                /*
                                 * Only keep relations
                                 * inside this cluster.
                                 */

                                if (
                                    !memberIds.has(
                                        target
                                    )
                                ) {

                                    return;

                                }


                                if (
                                    source ===
                                    target
                                ) {

                                    return;

                                }


                                const key =
                                    [
                                        source,
                                        target
                                    ]
                                        .sort()
                                        .join("::");


                                if (
                                    relationMap.has(
                                        key
                                    )
                                ) {

                                    return;

                                }


                                relationMap.set(
                                    key,
                                    {

                                        source,

                                        target,

                                        score:
                                            Number(
                                                relation
                                                    .correlationScore ||
                                                0
                                            ),

                                        matches:
                                            Array.isArray(
                                                relation.matches
                                            )
                                                ? relation.matches
                                                : []

                                    }

                                );

                            }
                        );

                    } catch (error) {

                        console.warn(
                            "Could not fetch relation for",
                            email.id,
                            error
                        );

                    }

                }
            )

        );


        return [
            ...relationMap.values()
        ];

    }



    //    NODE POSITIONS
    function getNodePosition(
    index,
    total
) {

    if (total === 1) {

        return {
            x: 50,
            y: 50
        };

    }


    if (total === 2) {

        return [
            {
                x: 32,
                y: 50
            },
            {
                x: 68,
                y: 50
            }
        ][index];

    }


    if (total === 3) {

        return [
            {
                x: 25,
                y: 35
            },
            {
                x: 75,
                y: 35
            },
            {
                x: 50,
                y: 72
            }
        ][index];

    }


    if (total === 4) {

        return [
            {
                x: 28,
                y: 30
            },
            {
                x: 72,
                y: 30
            },
            {
                x: 28,
                y: 70
            },
            {
                x: 72,
                y: 70
            }
        ][index];

    }


    if (total === 5) {

        return [
            {
                x: 50,
                y: 20
            },
            {
                x: 24,
                y: 42
            },
            {
                x: 76,
                y: 42
            },
            {
                x: 32,
                y: 76
            },
            {
                x: 68,
                y: 76
            }
        ][index];

    }


    if (total === 6) {

        return [
            {
                x: 28,
                y: 20
            },
            {
                x: 72,
                y: 20
            },
            {
                x: 20,
                y: 50
            },
            {
                x: 80,
                y: 50
            },
            {
                x: 28,
                y: 80
            },
            {
                x: 72,
                y: 80
            }
        ][index];

    }


    /*
     * 7–9 emails:
     * clean 3 × 3 layout
     */

    const positions = [

        {
            x: 22,
            y: 20
        },

        {
            x: 50,
            y: 20
        },

        {
            x: 78,
            y: 20
        },

        {
            x: 22,
            y: 50
        },

        {
            x: 50,
            y: 50
        },

        {
            x: 78,
            y: 50
        },

        {
            x: 22,
            y: 80
        },

        {
            x: 50,
            y: 80
        },

        {
            x: 78,
            y: 80
        }

    ];


    return positions[index];

}


    /* =========================================================
       DRAW ONE CLUSTER
       ========================================================= */

    function renderCluster(
        cluster,
        relations
    ) {

        const card =
            document.createElement(
                "article"
            );


        card.className =
            "cluster-card";


        const members =
            Array.isArray(
                cluster.emails
            )
                ? cluster.emails
                : [];


        card.innerHTML = `

            <div class="cluster-card-head">

                <div class="cluster-title">

                    <span class="cluster-dot"></span>

                    <strong>
                        ${escapeHtml(
                            cluster.clusterId
                        )}
                    </strong>

                </div>

                <span class="cluster-count">
                    ${members.length}
                    email${members.length === 1 ? "" : "s"}
                </span>

            </div>

            <div class="cluster-map"></div>

        `;


        const map =
            card.querySelector(
                ".cluster-map"
            );


        const svg =
            document.createElementNS(
                "http://www.w3.org/2000/svg",
                "svg"
            );


        svg.classList.add(
            "cluster-svg"
        );


        map.appendChild(
            svg
        );


        const positions = {};


        /*
         * Create small case nodes
         */

        members.forEach(
            (email, index) => {

                const position =
                    getNodePosition(
                        index,
                        members.length
                    );


                const id =
                    String(
                        email.id
                    );


                positions[id] =
                    position;


                const node =
                    document.createElement(
                        "button"
                    );


                node.type =
                    "button";


                node.className =
                    "cluster-node";


                node.style.left =
                    `${position.x}%`;


                node.style.top =
                    `${position.y}%`;


                node.innerHTML = `

                    <span
                        class="cluster-node-title">
                        ${escapeHtml(
                            email.subject ||
                            "No subject"
                        )}
                    </span>

                    <span
                        class="cluster-node-id">
                        ${escapeHtml(
                            email.id ||
                            ""
                        )}
                    </span>

                `;


                /*
                 * Click node ->
                 * show complete connection info.
                 */

                node.addEventListener(
                    "click",
                    () => {

                        const nodeRelations =
                            relations.filter(
                                relation =>
                                    relation.source === id ||
                                    relation.target === id
                            );


                        openDrawer(
                            email,
                            nodeRelations,
                            members
                        );

                    }
                );


                map.appendChild(
                    node
                );

            }
        );


        /*
         * Set SVG dimensions
         */

        const width =
            map.clientWidth ||
            360;


        const height =
            map.clientHeight ||
            230;


        svg.setAttribute(
            "viewBox",
            `0 0 ${width} ${height}`
        );


        /*
         * Draw edges
         */

        relations.forEach(
            relation => {

                const from =
                    positions[
                        relation.source
                    ];


                const to =
                    positions[
                        relation.target
                    ];


                if (
                    !from ||
                    !to
                ) {

                    return;

                }


                const line =
                    document.createElementNS(
                        "http://www.w3.org/2000/svg",
                        "line"
                    );


                const relationType =
                    normalizeRelationType(
                        relation.matches?.[0]?.type
                    );

                line.classList.add(
                    "cluster-edge",
                    relationType
                );

                line.setAttribute(
                    "x1",
                    (
                        from.x *
                        width /
                        100
                    )
                );


                line.setAttribute(
                    "y1",
                    (
                        from.y *
                        height /
                        100
                    )
                );


                line.setAttribute(
                    "x2",
                    (
                        to.x *
                        width /
                        100
                    )
                );


                line.setAttribute(
                    "y2",
                    (
                        to.y *
                        height /
                        100
                    )
                );


                svg.appendChild(
                    line
                );

            }
        );


        clustersGrid.appendChild(
            card
        );

    }


    /* =========================================================
       DRAWER
       ========================================================= */

    function openDrawer(
        email,
        relations
    ) {

        if (!drawer) {
            return;
        }


        drawerCaseId.textContent =
            email.id ||
            "—";


        drawerSubject.textContent =
            email.subject ||
            "—";


        drawerDate.textContent =
            formatDate(
                email.date
            );


        drawerMatchCount.textContent =
            relations.length;


        if (
            relations.length === 0
        ) {

            drawerScore.textContent =
                "—";


            drawerMatches.innerHTML = `

                <div class="match-row">

                    <strong>
                        No direct relationship details
                    </strong>

                    <small>
                        This email is part of the campaign
                        cluster, but no direct pairwise
                        relationship was returned.
                    </small>

                </div>

            `;

        } else {

            const strongest =
                Math.max(
                    ...relations.map(
                        relation =>
                            Number(
                                relation.score || 0
                            )
                    )
                );


            drawerScore.textContent =
                `${strongest}%`;


            drawerMatches.innerHTML =
                relations.map(
                    relation => {

                        const currentId =
                            String(
                                email.id
                            );


                        const otherId =
                            relation.source ===
                                currentId
                                ? relation.target
                                : relation.source;


                        const matchText =
                            relation.matches
                                .map(
                                    match => {

                                        const label =
                                            match.label ||
                                            match.type ||
                                            "Match";


                                        const value =
                                            formatMatchValue(
                                                match.value ??
                                                match.currentValue ??
                                                match.relatedValue
                                            );


                                        return `
                                            ${escapeHtml(
                                                label
                                            )}
                                            ·
                                            ${escapeHtml(
                                                value
                                            )}
                                        `;

                                    }
                                )
                                .join(
                                    "<br>"
                                );


                        return `

                            <div class="match-row">

                                <strong>
                                    Connected case:
                                    ${escapeHtml(
                                        otherId
                                    )}
                                </strong>

                                <small>
                                    Correlation:
                                    ${Number(
                                        relation.score || 0
                                    )}%
                                </small>

                                <small>
                                    ${matchText ||
                                    "Shared correlation"}
                                </small>

                            </div>

                        `;

                    }
                ).join("");

        }


        drawer.classList.add(
            "open"
        );


        drawer.setAttribute(
            "aria-hidden",
            "false"
        );


        if (window.lucide) {

            lucide.createIcons();

        }

    }


    function closeDrawerPanel() {

        if (!drawer) {
            return;
        }


        drawer.classList.remove(
            "open"
        );


        drawer.setAttribute(
            "aria-hidden",
            "true"
        );

    }


    /* =========================================================
       LOAD CLUSTERS
       ========================================================= */

    async function loadClusters() {

        try {

            if (status) {

                status.textContent =
                    "Loading campaign clusters...";

            }


            const clusters =
                await fetchClusters();


            if (campaignCount) {

                campaignCount.textContent =
                    clusters.length;

            }


            if (emailCount) {

                emailCount.textContent =
                    clusters.reduce(
                        (
                            total,
                            cluster
                        ) =>
                            total +
                            (
                                Array.isArray(
                                    cluster.emails
                                )
                                    ? cluster.emails.length
                                    : 0
                            ),
                        0
                    );

            }


            if (!clustersGrid) {
                return;
            }


            clustersGrid.innerHTML =
                "";


            if (
                !clusters.length
            ) {

                clustersGrid.innerHTML = `

                    <div class="cluster-empty">
                        No campaign clusters found.
                    </div>

                `;


                if (status) {

                    status.textContent =
                        "No connected campaigns found.";

                }


                return;

            }


            if (status) {

                status.textContent =
                    `${clusters.length} campaign cluster${
                        clusters.length === 1
                            ? ""
                            : "s"
                    } found`;

            }


            /*
             * Build and render each mini graph.
             */

            for (
                const cluster of clusters
            ) {

                const relations =
                    await buildClusterRelations(
                        cluster
                    );


                renderCluster(
                    cluster,
                    relations
                );

            }


            if (window.lucide) {

                lucide.createIcons();

            }

        } catch (error) {

            console.error(
                "Campaign clusters failed:",
                error
            );


            if (status) {

                status.textContent =
                    "Unable to load campaign clusters.";

            }


            if (clustersGrid) {

                clustersGrid.innerHTML = `

                    <div class="cluster-empty">

                        Could not load campaign clusters.
                        Check that the backend server
                        is running on port 5001.

                    </div>

                `;

            }

        }

    }


    /* =========================================================
       EVENTS
       ========================================================= */

    if (refreshButton) {

        refreshButton.addEventListener(
            "click",
            loadClusters
        );

    }


    if (drawerClose) {

        drawerClose.addEventListener(
            "click",
            closeDrawerPanel
        );

    }


    /*
     * Escape closes drawer.
     */

    document.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Escape"
            ) {

                closeDrawerPanel();

            }

        }
    );


    /* =========================================================
       INITIAL LOAD
       ========================================================= */

    loadClusters();

});