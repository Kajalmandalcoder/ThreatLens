const { spawn } = require("child_process");
const path = require("path");

function parseEmailWithPython(filePath) {
    return new Promise((resolve, reject) => {

        // Path to parser.py
        const parserPath = path.join(
            __dirname,
            "../../email_parser/parser.py"
        );

        // Run Python parser
        const pythonProcess = spawn(
            "python3",  // python3 is used to ensure compatibility with Python 3 mac pr pyhton 3 windows pr python 
            [parserPath, filePath]
        );

        let output = "";
        let errorOutput = "";

        // Receive Python output
        pythonProcess.stdout.on("data", (data) => {
            output += data.toString();
        });

        // Receive Python errors
        pythonProcess.stderr.on("data", (data) => {
            errorOutput += data.toString();
        });

        // Python process finished
        pythonProcess.on("close", (code) => {

            if (code !== 0) {
                return reject(
                    new Error(
                        errorOutput || "Python parser failed"
                    )
                );
            }

            try {
                const parsedEmail = JSON.parse(output);

                resolve(parsedEmail);

            } catch (error) {
                reject(
                    new Error(
                        "Invalid JSON returned by Python parser"
                    )
                );
            }
        });

        // Python process error
        pythonProcess.on("error", (error) => {
            reject(error);
        });
    });
}

module.exports = {
    parseEmailWithPython
};