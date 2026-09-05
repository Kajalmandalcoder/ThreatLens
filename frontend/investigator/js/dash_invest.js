console.log("🔥 DASH INVEST JS LOADED");
document.addEventListener("DOMContentLoaded", async function () {

    lucide.createIcons();

    // =========================
    // ELEMENTS
    // =========================

    const searchInput =
        document.getElementById("searchInput");

    const severityFilter =
        document.getElementById("severityFilter");

    const statusFilter =
        document.getElementById("statusFilter");

    const threatFilter =
        document.getElementById("threatFilter");

    const resetFilters =
        document.getElementById("resetFilters");

    const tableBody =
        document.getElementById("caseTableBody");

    const resultCount =
        document.getElementById("resultCount");


    // =========================
    // FETCH CASES
    // =========================

    let cases = [];

    // async function fetchCases() {

    //     try {

    //         const response = await fetch(
    //             "http://localhost:5000/api/emails"
    //         );

    //         const result = await response.json();

    //         if (!response.ok || !result.success) {
    //             throw new Error(
    //                 result.message || "Failed to fetch cases"
    //             );
    //         }

    //         cases = result.data || [];

    //         console.log("📥 Cases fetched:", cases);

    //         renderCases(cases);

    //     } catch (error) {

    //         console.error(
    //             "❌ Failed to fetch cases:",
    //             error
    //         );

    //         tableBody.innerHTML = `
    //             <tr>
    //                 <td colspan="9" style="text-align:center;">
    //                     Failed to load cases
    //                 </td>
    //             </tr>
    //         `;

    //         resultCount.textContent =
    //             "Showing 0 cases";
    //     }
    // }

    async function fetchCases() {

    console.log("🚀 fetchCases STARTED");

    try {

        console.log("🌐 Calling API...");

        const response = await fetch(
            "http://localhost:5001/api/emails"
        );

        console.log("✅ API response received:", response);

        const result = await response.json();

        console.log("📦 API data:", result);

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Failed to fetch cases"
            );
        }

        cases = result.data || [];

        console.log("📥 Cases fetched:", cases);

        renderCases(cases);

    } catch (error) {

        console.error("❌ Failed to fetch cases:", error);

        tableBody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align:center;">
                    Failed to load cases
                </td>
            </tr>
        `;

        resultCount.textContent = "Showing 0 cases";
    }
}


    // =========================
    // GENERATE CASE ID
    // =========================

    function getCaseId(email) {

        // New records: backend-generated Case ID
        if (email.caseId) {
            return email.caseId;
        }

        // Old records: stable Case ID using MongoDB _id
        if (email._id) {
            const year = new Date(
                email.createdAt || Date.now()
            ).getFullYear();

            return `CASE-${year}-${email._id.slice(-6).toUpperCase()}`;
        }

        return "CASE-UNKNOWN";
    }


    // =========================
    // FORMAT DATE
    // =========================

    function formatDate(dateValue) {

        if (!dateValue) {
            return "—";
        }

        const date = new Date(dateValue);

        if (isNaN(date.getTime())) {
            return dateValue;
        }

        return date.toLocaleDateString(
            "en-GB",
            {
                day: "2-digit",
                month: "short",
                year: "numeric"
            }
        );
    }


    // =========================
    // RENDER CASES
    // =========================

    function renderCases(data) {

        tableBody.innerHTML = "";

        if (!data.length) {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="9" style="text-align:center;">
                        No cases found
                    </td>
                </tr>
            `;

            resultCount.textContent =
                "Showing 0 cases";

            return;
        }


        data.forEach((email, index) => {

            const caseId =
                getCaseId(email);

            const subject =
                email.headers?.subject ||
                "No Subject";

            const sender =
                email.headers?.from ||
                "Unknown Sender";

            const created = formatDate(email.headers?.date);


            const row =
                document.createElement("tr");


            // =========================
            // DATA ATTRIBUTES
            // =========================

            row.dataset.case =
                caseId;

            row.dataset.subject =
                subject;

            row.dataset.sender =
                sender;

            // Not fetched yet
            row.dataset.threat = "";

            row.dataset.severity = "";

            row.dataset.status = "";


            // =========================
            // ROW HTML
            // =========================

            row.innerHTML = `

                <td class="case-id">
                    ${escapeHtml(caseId)}
                </td>

                <td class="subject">
                    ${escapeHtml(subject)}
                </td>

                <td class="sender">
                    ${escapeHtml(sender)}
                </td>

                <td>
                    —
                </td>

                <td>
                    —
                </td>

                <td>
                    —
                </td>

                <td>
                    —
                </td>

                <td>
                    ${escapeHtml(created)}
                </td>

                <td>
                    <button
                        class="view-btn"
                        data-id="${email._id}"
                    >
                        View
                        <i data-lucide="chevron-right"></i>
                    </button>
                </td>

            `;


            tableBody.appendChild(row);

        });


        lucide.createIcons();

        resultCount.textContent =
            `Showing ${data.length} of ${data.length} cases`;
    }


    // =========================
    // HTML ESCAPE
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
    // FILTER FUNCTION
    // =========================

    function filterCases() {

        const searchValue =
            searchInput.value
                .trim()
                .toLowerCase();

        const selectedSeverity =
            severityFilter.value;

        const selectedStatus =
            statusFilter.value;

        const selectedThreat =
            threatFilter.value;


        const rows =
            document.querySelectorAll(
                "#caseTableBody tr"
            );


        let visibleCount = 0;


        rows.forEach(row => {

            if (!row.dataset.case) {
                return;
            }


            const caseId =
                row.dataset.case.toLowerCase();

            const subject =
                row.dataset.subject.toLowerCase();

            const sender =
                row.dataset.sender.toLowerCase();

            const threat =
                row.dataset.threat || "";

            const severity =
                row.dataset.severity || "";

            const status =
                row.dataset.status || "";


            const matchesSearch =
                searchValue === "" ||
                caseId.includes(searchValue) ||
                subject.includes(searchValue) ||
                sender.includes(searchValue);


            // Since these fields are NOT fetched yet
            // only "all" will show the records

            const matchesSeverity =
                selectedSeverity === "all" ||
                severity === selectedSeverity;

            const matchesStatus =
                selectedStatus === "all" ||
                status === selectedStatus;

            const matchesThreat =
                selectedThreat === "all" ||
                threat === selectedThreat;


            if (
                matchesSearch &&
                matchesSeverity &&
                matchesStatus &&
                matchesThreat
            ) {

                row.style.display = "";

                visibleCount++;

            } else {

                row.style.display = "none";

            }

        });


        resultCount.textContent =
            `Showing ${visibleCount} of ${cases.length} cases`;
    }


    // =========================
    // SEARCH
    // =========================

    searchInput.addEventListener(
        "input",
        filterCases
    );


    // =========================
    // FILTERS
    // =========================

    severityFilter.addEventListener(
        "change",
        filterCases
    );

    statusFilter.addEventListener(
        "change",
        filterCases
    );

    threatFilter.addEventListener(
        "change",
        filterCases
    );


    // =========================
    // RESET
    // =========================

    resetFilters.addEventListener(
        "click",
        function () {

            searchInput.value = "";

            severityFilter.value = "all";

            statusFilter.value = "all";

            threatFilter.value = "all";

            renderCases(cases);

        }
    );


    // =========================
    // VIEW BUTTON
    // =========================

    tableBody.addEventListener(
        "click",
        function (event) {

            const button =
                event.target.closest(".view-btn");

            if (!button) {
                return;
            }


            const emailId =
                button.dataset.id;


            console.log(
                "🔎 Opening case:",
                emailId
            );


            // Later case detail page
            window.location.href =
                `case_detail.html?id=${emailId}`;
        }
    );


    // =========================
    // INITIAL LOAD
    // =========================

    await fetchCases();

});