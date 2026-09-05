const { spawn } = require("child_process");
const path = require("path");

function runHeaderForensics(filePath) {
    return new Promise((resolve, reject) => {

        const scriptPath = path.join(
            __dirname,
            "../../header_forensics.py"
        );

        const pythonProcess = spawn(
            "python",
            [scriptPath, filePath]
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
                return reject(
                    new Error(
                        errorOutput || "Header Forensics failed"
                    )
                );
            }

            try {
                const result = JSON.parse(output);
                resolve(result);
            } catch (error) {
                reject(
                    new Error(
                        "Invalid JSON returned by Header Forensics"
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
    runHeaderForensics
};