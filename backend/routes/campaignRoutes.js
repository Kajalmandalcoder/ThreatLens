const express = require("express");
const {
    buildCampaignGraph,
    buildCampaignClusters
} = require("../services/campaignCorrelationsService");

const router = express.Router();

router.get("/graph", async (req, res) => {
    try {

        const emailId =req.query.emailId || null;
        const result =await buildCampaignGraph(emailId);

        res.status(200).json({
            success: true,
            data: result
        });

    } catch (error) {
        console.error("Campaign correlation failed:", error);

        res.status(500).json({
            success: false,
            message: "Failed to build campaign correlation graph",
            error: error.message
        });
    }
});
router.get("/clusters", async (req, res) => {

    try {

        const result =
            await buildCampaignClusters();

        res.json({
            success: true,
            data: result
        });

    } catch (error) {

        console.error(
            "Campaign clusters error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Failed to build campaign clusters"
        });

    }

});

module.exports = router;