const { spawn } = require("child_process");
const path = require("path");

/**
 * Executes the Python URL intelligence analyzer.
 *
 * @param {Array<string>} urls
 * @param {string} senderEmail
 * @returns {Promise<Object>}
 */
function analyzeUrls(urls, senderEmail = "") {
  return new Promise((resolve, reject) => {

    // No URLs
    if (!urls || urls.length === 0) {
      return resolve({
        summary: {
          total_urls: 0,
          critical_risk_urls: 0,
          high_risk_urls: 0,
          medium_risk_urls: 0,
          low_risk_urls: 0,
          max_risk_score: 0,
          overall_status: "LOW"
        },
        urls: []
      });
    }

    // Project root:
    // C:\Users\kajal\Desktop\sih2026
    const projectRoot =
      path.resolve(__dirname, "../..");

    // Python executable from project virtual environment
    const isWindows =
      process.platform === "win32";

    const pythonExecutable = isWindows
      ? path.resolve(
          projectRoot,
          ".venv/Scripts/python.exe"
        )
      : path.resolve(
          projectRoot,
          ".venv/bin/python"
        );

    const pythonProcess = spawn(
      pythonExecutable,
      ["-m", "url_intelligence.analyzer"],
      {
        cwd: projectRoot
      }
    );

    let output = "";
    let errorOutput = "";

    // Send input to Python
    const inputData = JSON.stringify({
      urls: urls || [],
      sender_email: senderEmail || null
    });

    pythonProcess.stdin.write(inputData);
    pythonProcess.stdin.end();

    // Receive Python output
    pythonProcess.stdout.on(
      "data",
      (data) => {
        output += data.toString();
      }
    );

    // Receive Python errors/warnings
    pythonProcess.stderr.on(
      "data",
      (data) => {
        errorOutput += data.toString();
      }
    );

    // Python process completed
    pythonProcess.on(
      "close",
      (code) => {

        if (code !== 0) {
          console.error(
            "URL Intelligence Python error:",
            errorOutput
          );

          return reject(
            new Error(
              errorOutput ||
              "URL Intelligence failed"
            )
          );
        }

        try {
          const result =
            JSON.parse(output.trim());

          resolve(result);

        } catch (error) {
          console.error(
            "Invalid URL Intelligence JSON:",
            output
          );

          reject(
            new Error(
              "Invalid JSON returned by URL Intelligence"
            )
          );
        }
      }
    );

    // Python process error
    pythonProcess.on(
      "error",
      (error) => {
        reject(error);
      }
    );
  });
}

module.exports = {
  analyzeUrls
};