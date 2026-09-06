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

        switch (value) {

            case "sender":
                return "sender";

            case "domain":
                return "domain";

            case "url":
                return "url";

            case "ip":
                return "ip";

            case "content":
                return "content";

            case "subject":
                return "subject";

            case "hash":
                return "hash";

            case "attachment":
                return "attachment";

            default:
                return "unknown";

        }

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


    function getMatchLabel(match) {

        return (
            match?.label ||
            match?.name ||
            match?.type ||
            "Shared indicator"
        );

    }


    function getIndicatorColor(type) {

        const normalized =
            normalizeRelationType(
                type
            );

        const colors = {

            sender:
                "#24d8ca",

            domain:
                "#a78bfa",

            url:
                "#f59e0b",

            ip:
                "#60a5fa",

            content:
                "#38bdf8",

            subject:
                "#38bdf8",

            hash:
                "#fb923c",

            attachment:
                "#fb923c",

            unknown:
                "#648299"

        };

        return (
            colors[normalized] ||
            colors.unknown
        );

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
       FETCH ONE EMAIL'S CORRELATION GRAPH
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
       BUILD RELATIONS FOR ONE CLUSTER
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
                members
                    .map(
                        email =>
                            String(
                                email?.id ||
                                email?._id ||
                                ""
                            )
                    )
                    .filter(Boolean)
            );


        const relationMap =
            new Map();


        await Promise.all(

            members.map(
                async email => {

                    const source =
                        String(
                            email?.id ||
                            email?._id ||
                            ""
                        );


                    if (!source) {
                        return;
                    }


                    try {

                        const graph =
                            await fetchEmailGraph(
                                source
                            );


                        const related =
                            Array.isArray(
                                graph.relatedEmails
                            )
                                ? graph.relatedEmails
                                : [];


                        related.forEach(
                            relation => {

                                const target =
                                    String(
                                        relation?.id ||
                                        relation?._id ||
                                        ""
                                    );


                                if (
                                    !target ||
                                    target === source
                                ) {
                                    return;
                                }


                                if (
                                    !memberIds.has(
                                        target
                                    )
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


                                const relationScore =
                                    Number(
                                        relation?.correlationScore ??
                                        relation?.score ??
                                        0
                                    );


                                const relationMatches =
                                    Array.isArray(
                                        relation?.matches
                                    )
                                        ? relation.matches
                                        : [];


                                if (
                                    !relationMap.has(
                                        key
                                    )
                                ) {

                                    relationMap.set(
                                        key,
                                        {
                                            source,
                                            target,
                                            score:
                                                relationScore,
                                            matches:
                                                [
                                                    ...relationMatches
                                                ]
                                        }
                                    );

                                } else {

                                    const existing =
                                        relationMap.get(
                                            key
                                        );


                                    existing.score =
                                        Math.max(
                                            existing.score,
                                            relationScore
                                        );


                                    existing.matches.push(
                                        ...relationMatches
                                    );


                                    /*
                                     * Keep one match
                                     * per indicator type.
                                     */

                                    const seen =
                                        new Set();


                                    existing.matches =
                                        existing.matches.filter(
                                            match => {

                                                const type =
                                                    normalizeRelationType(
                                                        match?.type
                                                    );


                                                if (
                                                    seen.has(
                                                        type
                                                    )
                                                ) {
                                                    return false;
                                                }


                                                seen.add(
                                                    type
                                                );


                                                return true;

                                            }
                                        );

                                }

                            }
                        );

                    } catch (error) {

                        console.warn(
                            "Could not fetch relation for",
                            source,
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


    /* =========================================================
       DYNAMIC NODE POSITION
       ========================================================= */

    function getNodePosition(
        index,
        total
    ) {

        if (
            total <= 0
        ) {

            return {
                x: 50,
                y: 50
            };

        }


        /*
         * Automatically choose the number
         * of columns from the cluster size.
         */

        let columns;

        if (total <= 2) {

            columns = total;

        } else if (total <= 6) {

            columns = 2;

        } else if (total <= 12) {

            columns = 3;

        } else if (total <= 20) {

            columns = 4;

        } else {

            columns = 5;

        }


        const rows =
            Math.ceil(
                total /
                columns
            );


        const paddingX = 15;
        const paddingY = 16;


        const usableWidth =
            100 -
            paddingX * 2;


        const usableHeight =
            100 -
            paddingY * 2;


        const column =
            index %
            columns;


        const row =
            Math.floor(
                index /
                columns
            );


        const x =
            columns === 1
                ? 50
                : paddingX +
                  (
                      column /
                      (
                          columns - 1
                      )
                  ) *
                  usableWidth;


        const y =
            rows === 1
                ? 50
                : paddingY +
                  (
                      row /
                      (
                          rows - 1
                      )
                  ) *
                  usableHeight;


        return {
            x,
            y
        };

    }


    /* =========================================================
       RENDER ONE CLUSTER
       ========================================================= */

    function renderCluster(
        cluster,
        relations
    ) {

        if (!clustersGrid) {
            return;
        }


        const members =
            Array.isArray(
                cluster.emails
            )
                ? cluster.emails
                : [];


        const card =
            document.createElement(
                "article"
            );


        card.className =
            "cluster-card";


        card.innerHTML = `

            <div class="cluster-card-head">

                <div class="cluster-title">

                    <span
                        class="cluster-dot">
                    </span>

                    <strong>
                        ${escapeHtml(
                            cluster.clusterId ||
                            "Campaign"
                        )}
                    </strong>

                </div>

                <span
                    class="cluster-count">

                    ${members.length}
                    email${
                        members.length === 1
                            ? ""
                            : "s"
                    }

                </span>

            </div>

            <div class="cluster-map"></div>

        `;


        const map =
            card.querySelector(
                ".cluster-map"
            );


        if (!map) {
            return;
        }


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
         * Create nodes.
         */

        members.forEach(
            (email, index) => {

                const id =
                    String(
                        email?.id ||
                        email?._id ||
                        ""
                    );


                if (!id) {
                    return;
                }


                const position =
                    getNodePosition(
                        index,
                        members.length
                    );


                if (!position) {
                    return;
                }


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


                node.dataset.caseId =
                    id;


                node.style.left =
                    `${position.x}%`;


                node.style.top =
                    `${position.y}%`;


                const relationTypes =
                    relations
                        .filter(
                            relation =>
                                relation.source === id ||
                                relation.target === id
                        )
                        .flatMap(
                            relation =>
                                (
                                    relation.matches ||
                                    []
                                ).map(
                                    match =>
                                        normalizeRelationType(
                                            match?.type
                                        )
                                )
                        );


                const primaryType =
                    relationTypes[0] ||
                    "unknown";


                node.dataset.relationType =
                    primaryType;


                const subject =
                    email?.subject ||
                    "No subject";


                node.innerHTML = `

                    <span
                        class="cluster-node-title">

                        ${escapeHtml(
                            subject
                        )}

                    </span>

                    <span
                        class="cluster-node-id">

                        ${escapeHtml(
                            id
                        )}

                    </span>

                `;


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
                            nodeRelations
                        );

                    }
                );


                map.appendChild(
                    node
                );

            }
        );


        /*
         * Draw SVG after the card is in the DOM,
         * so width/height are real.
         */

        clustersGrid.appendChild(
            card
        );


        requestAnimationFrame(
            () => {

                const width =
                    map.clientWidth ||
                    400;


                const height =
                    map.clientHeight ||
                    300;


                svg.setAttribute(
                    "viewBox",
                    `0 0 ${width} ${height}`
                );


                svg.setAttribute(
                    "width",
                    width
                );


                svg.setAttribute(
                    "height",
                    height
                );


                /*
                 * Draw every indicator type
                 * between connected cases.
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

                        const matches =
                            Array.isArray(
                                relation.matches
                            )
                                ? relation.matches
                                : [];

                        const strongestMatch =
                            matches.reduce(
                                (
                                    strongest,
                                    match
                                ) => {

                                    const strength =
                                        Number(
                                            match?.strength ??
                                            match?.score ??
                                            0
                                        );

                                    if (!strongest) {

                                        return {
                                            ...match,
                                            __strength:
                                                strength
                                        };

                                    }

                                    return (
                                        strength >
                                        strongest.__strength
                                    )
                                        ? {
                                            ...match,
                                            __strength:
                                                strength
                                        }
                                        : strongest;

                                },
                                null
                            );

                        const type =
                            normalizeRelationType(
                                strongestMatch?.type ||
                                "unknown"
                            );

                        const line =
                            document.createElementNS(
                                "http://www.w3.org/2000/svg",
                                "line"
                            );

                        line.classList.add(
                            "cluster-edge",
                            type
                        );

                        line.setAttribute(
                            "x1",
                            from.x *
                            width /
                            100
                        );

                        line.setAttribute(
                            "y1",
                            from.y *
                            height /
                            100
                        );

                        line.setAttribute(
                            "x2",
                            to.x *
                            width /
                            100
                        );

                        line.setAttribute(
                            "y2",
                            to.y *
                            height /
                            100
                        );

                        line.dataset.score =
                            String(
                                Number(
                                    relation.score ||
                                    0
                                )
                            );

                        line.dataset.type =
                            type;

                        line.setAttribute(
                            "stroke",
                            getIndicatorColor(
                                type
                            )
                        );

                        svg.appendChild(
                            line
                        );

                    }
                );

            }
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


        const emailId =
            String(
                email?.id ||
                email?._id ||
                "—"
            );


        const subject =
            email?.subject ||
            "No subject";


        const date =
            email?.date ||
            email?.createdAt ||
            null;


        if (drawerCaseId) {

            drawerCaseId.textContent =
                emailId;

        }


        if (drawerSubject) {

            drawerSubject.textContent =
                subject;

        }


        if (drawerDate) {

            drawerDate.textContent =
                formatDate(
                    date
                );

        }


        const safeRelations =
            Array.isArray(
                relations
            )
                ? relations
                : [];


        if (drawerMatchCount) {

            drawerMatchCount.textContent =
                safeRelations.length;

        }


        if (!safeRelations.length) {

            if (drawerScore) {

                drawerScore.textContent =
                    "—";

            }


            if (drawerMatches) {

                drawerMatches.innerHTML = `

                    <div class="match-row">

                        <strong>
                            No direct relationship details
                        </strong>

                        <small>
                            This email belongs to the
                            campaign cluster, but no
                            direct pairwise relationship
                            was returned.
                        </small>

                    </div>

                `;

            }

        } else {

            const strongest =
                Math.max(
                    ...safeRelations.map(
                        relation =>
                            Number(
                                relation.score ||
                                0
                            )
                    )
                );


            if (drawerScore) {

                drawerScore.textContent =
                    `${strongest}%`;

            }


            if (drawerMatches) {

                drawerMatches.innerHTML =
                    safeRelations
                        .map(
                            relation => {

                                const currentId =
                                    emailId;


                                const otherId =
                                    relation.source ===
                                        currentId
                                        ? relation.target
                                        : relation.source;


                                const matches =
                                    Array.isArray(
                                        relation.matches
                                    )
                                        ? relation.matches
                                        : [];


                                /*
                                 * Remove duplicate
                                 * indicator types.
                                 */

                                const uniqueMatches =
                                    [];


                                const seenTypes =
                                    new Set();


                                matches.forEach(
                                    match => {

                                        const type =
                                            normalizeRelationType(
                                                match?.type
                                            );


                                        if (
                                            seenTypes.has(
                                                type
                                            )
                                        ) {
                                            return;
                                        }


                                        seenTypes.add(
                                            type
                                        );


                                        uniqueMatches.push(
                                            match
                                        );

                                    }
                                );


                                const basis =
                                    uniqueMatches
                                        .map(
                                            match => {

                                                const label =
                                                    getMatchLabel(
                                                        match
                                                    );


                                                const value =
                                                    formatMatchValue(
                                                        match.value ??
                                                        match.currentValue ??
                                                        match.relatedValue
                                                    );


                                                const color =
                                                    getIndicatorColor(
                                                        match?.type
                                                    );


                                                return `

                                                    <div
                                                        class="match-indicator"
                                                        style="
                                                            border-left: 3px solid ${color};
                                                            padding-left: 8px;
                                                            margin: 7px 0;
                                                        ">

                                                        <strong>
                                                            ${escapeHtml(
                                                                label
                                                            )}
                                                        </strong>

                                                        <small>
                                                            ${escapeHtml(
                                                                value
                                                            )}
                                                        </small>

                                                    </div>

                                                `;

                                            }
                                        )
                                        .join("");


                                return `

                                    <div
                                        class="match-row">

                                        <strong>
                                            Connected case:
                                            ${escapeHtml(
                                                otherId
                                            )}
                                        </strong>

                                        <small>
                                            Correlation:
                                            ${Number(
                                                relation.score ||
                                                0
                                            )}%
                                        </small>

                                        ${
                                            basis ||
                                            `
                                            <small>
                                                Shared correlation
                                            </small>
                                            `
                                        }

                                    </div>

                                `;

                            }
                        )
                        .join("");

            }

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


            /*
             * Dynamic summary.
             */

            if (campaignCount) {

                campaignCount.textContent =
                    clusters.length;

            }


            const totalEmails =
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


            if (emailCount) {

                emailCount.textContent =
                    totalEmails;

            }


            if (!clustersGrid) {
                return;
            }


            clustersGrid.innerHTML =
                "";


            if (!clusters.length) {

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
             * One graph per API cluster.
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