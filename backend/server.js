const dns = require("dns");

dns.setServers([
    "8.8.8.8",
    "1.1.1.1"
]);

require("dotenv").config();

const express = require("express");
const cors = require("cors");

const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const emailRoutes = require("./routes/emailRoutes");
const app = express();
app.use(cors());
app.use(express.json());

app.use("/api/emails", emailRoutes);
app.use("/api/auth", authRoutes);

async function startServer() {
    try {
        await connectDB();

        app.get("/", (req, res) => {
            res.json({
                message: "ThreadLens backend is running"
            });
        });

        app.listen(5000, () => {
            console.log("Server running on http://localhost:5000");
        });

    } catch (error) {
        console.error("Server startup failed:", error);
    }
}

startServer();