const { spawn } = require("child_process");
const path = require("path");

function runHeaderForensics(filePath) {
    return new Promise((resolve, reject) => {
        const isWindows = process.platform === "win32";
        const pythonExecutable = isWindows
            ? path.resolve(__dirname, "../../.venv/Scripts/python.exe")
            : path.resolve(__dirname, "../../.venv/bin/python");

        const scriptPath = path.resolve(
            __dirname,
            "../../header_forensics.py"
        );

        const pythonProcess = spawn(
            pythonExecutable,
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
                const result = JSON.parse(output.trim());
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