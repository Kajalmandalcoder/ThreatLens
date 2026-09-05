const { spawn } = require("child_process");
const path = require("path");

function runMLPrediction(text) {
    return new Promise((resolve, reject) => {

        const projectRoot = path.join(__dirname, "../..");

        const mlScript = path.join(
            projectRoot,
            "ml_predict.py"
        );

        const pythonProcess = spawn(
            "python",
            [mlScript, text]
        );

        let output = "";
        let errorOutput = "";

        pythonProcess.stdout.on("data", (data) => {
            output += data.toString();
        });

        pythonProcess.stderr.on("data", (data) => {
            errorOutput += data.toString();
        });

        pythonProcess.on("close", (code) => {

            if (code !== 0) {
                console.error("❌ ML process failed:", errorOutput);

                return reject(
                    new Error(
                        errorOutput || "ML prediction failed"
                    )
                );
            }

            try {
                const result = JSON.parse(output.trim());

                resolve(result);

            } catch (error) {

                console.error("❌ Invalid ML JSON output:", output);

                reject(
                    new Error(
                        "Invalid response from ML model"
                    )
                );
            }

        });

        pythonProcess.on("error", (error) => {
            reject(error);
        });

    });
}

module.exports = {
    runMLPrediction
};