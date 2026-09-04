const { spawn } = require("child_process");
const path = require("path");

function parseEmailWithPython(filePath) {
    return new Promise((resolve, reject) => {
        const isWindows = process.platform === "win32";
        const pythonExecutable = isWindows
            ? path.resolve(__dirname, "../../.venv/Scripts/python.exe")
            : path.resolve(__dirname, "../../.venv/bin/python");

        const parserPath = path.resolve(
            __dirname,
            "../../email_parser/parser.py"
        );

        const pythonProcess = spawn(
            pythonExecutable,
            [parserPath, filePath]
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
                console.error("❌ Python parser exit code:", code);
                console.error("❌ Python stderr:", errorOutput);
                console.error("❌ Python stdout:", output);
                return reject(
                    new Error(
                        errorOutput || "Python parser failed"
                    )
                );
            }

            try {
                const parsedEmail = JSON.parse(output.trim());
                resolve(parsedEmail);
            } catch (error) {
                reject(
                    new Error(
                        "Invalid JSON returned by Python parser"
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
    parseEmailWithPython
};