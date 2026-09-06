const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, ".env") });

const dns = require("dns");
const mongoose = require("mongoose");

dns.setServers([
    "8.8.8.8",
    "1.1.1.1"
]);
const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const emailRoutes = require("./routes/emailRoutes");
const campaignRoutes = require("./routes/campaignRoutes");
const app = express();

const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());
app.use("/api/campaigns", campaignRoutes);
app.use("/api/emails", emailRoutes);
app.use("/api/auth", authRoutes);

async function startServer() {
    try {
        await connectDB();

        console.log("Connected database:", mongoose.connection.name);
        console.log("Connected host:", mongoose.connection.host);


        app.get("/", (req, res) => {
            res.json({
                message: "ThreadLens backend is running"
            });
        });

        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });

    } catch (error) {
        console.error("Server startup failed:", error);
    }
}

startServer();