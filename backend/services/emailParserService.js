const { spawn } = require("child_process");
const path = require("path");

function parseEmailWithPython(filePath) {
    return new Promise((resolve, reject) => {
        const isWindows = process.platform === "win32";

        const projectRoot = path.resolve(
            __dirname,
            "../.."
        );

        const pythonExecutable = isWindows
            ? path.join(
                projectRoot,
                ".venv",
                "Scripts",
                "python.exe"
            )
            : path.join(
                projectRoot,
                ".venv",
                "bin",
                "python"
            );

        const parserPath = path.join(
            projectRoot,
            "email_parser",
            "parser.py"
        );

        const pythonProcess = spawn(
            pythonExecutable,
            [
                parserPath,
                filePath
            ],
            {
                cwd: projectRoot,
                env: {
                    ...process.env,
                    PYTHONPATH: projectRoot
                }
            }
        );

        let output = "";
        let errorOutput = "";

        pythonProcess.stdout.on(
            "data",
            (data) => {
                output += data.toString("utf8");
            }
        );

        pythonProcess.stderr.on(
            "data",
            (data) => {
                errorOutput += data.toString("utf8");
            }
        );

        pythonProcess.on(
            "close",
            (code) => {

                if (code !== 0) {

                    console.error(
                        "❌ Python parser exit code:",
                        code
                    );

                    console.error(
                        "❌ Python stderr:",
                        errorOutput
                    );

                    console.error(
                        "❌ Python stdout:",
                        output
                    );

                    return reject(
                        new Error(
                            errorOutput ||
                            "Python parser failed"
                        )
                    );
                }

                const trimmedOutput =
                    output.trim();

                if (!trimmedOutput) {

                    return reject(
                        new Error(
                            "Python parser returned empty output"
                        )
                    );
                }

                try {

                    const parsedEmail =
                        JSON.parse(
                            trimmedOutput
                        );

                    resolve(
                        parsedEmail
                    );

                } catch (error) {

                    console.error(
                        "❌ Invalid JSON from Python parser"
                    );

                    console.error(
                        "Python output:",
                        trimmedOutput
                    );

                    return reject(
                        new Error(
                            "Invalid JSON returned by Python parser"
                        )
                    );
                }
            }
        );

        pythonProcess.on(
            "error",
            (error) => {
                console.error(
                    "❌ Failed to start Python parser:",
                    error
                );

                reject(
                    error
                );
            }
        );
    });
}

module.exports = {
    parseEmailWithPython
};