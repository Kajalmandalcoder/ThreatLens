document.addEventListener("DOMContentLoaded", function () {

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

    const rows =
        document.querySelectorAll("#caseTableBody tr");

    const resultCount =
        document.getElementById("resultCount");


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


        let visibleCount = 0;


        rows.forEach(row => {

            const caseId =
                row.dataset.case.toLowerCase();

            const subject =
                row.dataset.subject.toLowerCase();

            const sender =
                row.dataset.sender.toLowerCase();

            const threat =
                row.dataset.threat;

            const severity =
                row.dataset.severity;

            const status =
                row.dataset.status;


            // SEARCH

            const matchesSearch =
                searchValue === "" ||
                caseId.includes(searchValue) ||
                subject.includes(searchValue) ||
                sender.includes(searchValue) ||
                threat.toLowerCase().includes(searchValue);


            // SEVERITY

            const matchesSeverity =
                selectedSeverity === "all" ||
                severity === selectedSeverity;


            // STATUS

            const matchesStatus =
                selectedStatus === "all" ||
                status === selectedStatus;


            // THREAT TYPE

            const matchesThreat =
                selectedThreat === "all" ||
                threat === selectedThreat;


            // FINAL RESULT

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


        // UPDATE COUNT

        resultCount.textContent =
            `Showing ${visibleCount} of 24 cases`;

    }


    // =========================
    // EVENTS
    // =========================

    searchInput.addEventListener(
        "input",
        filterCases
    );


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

            filterCases();

        }
    );


    // =========================
    // VIEW BUTTONS
    // =========================

    document
        .querySelectorAll(".view-btn")
        .forEach(button => {

            button.addEventListener(
                "click",
                function () {

                    const row =
                        this.closest("tr");

                    const caseId =
                        row.dataset.case;

                    console.log(
                        "Opening case:",
                        caseId
                    );

                    // Baad me yahan:
                    // window.location.href =
                    // `analysis.html?case=${caseId}`;

                }
            );

        });

});