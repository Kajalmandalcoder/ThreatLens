const { spawn } = require("child_process");
const path = require("path");

function runImageIntelligence(emlPath) {
    return new Promise((resolve, reject) => {

        const pythonScript = path.resolve(
            __dirname,
            "../../image_intelligence/run_image_intelligence.py"
        );

        const python = spawn("python", [
            pythonScript,
            emlPath
        ]);

        let output = "";
        let errorOutput = "";

        // Python stdout = ONLY JSON
        python.stdout.on("data", (data) => {
            output += data.toString();
        });

        // Python logs / warnings
        python.stderr.on("data", (data) => {
            errorOutput += data.toString();
        });

        python.on("error", (error) => {
            reject(
                new Error(
                    `Failed to start Image Intelligence: ${error.message}`
                )
            );
        });

        python.on("close", (code) => {

            if (code !== 0) {
                return reject(
                    new Error(
                        errorOutput ||
                        `Image Intelligence exited with code ${code}`
                    )
                );
            }

            try {

                const result = JSON.parse(output.trim());

                if (!result.success) {
                    return reject(
                        new Error(
                            result.message ||
                            "Image Intelligence failed"
                        )
                    );
                }

                resolve(result.imageIntelligence);

            } catch (error) {

                console.error(
                    "Image Intelligence stderr:",
                    errorOutput
                );

                console.error(
                    "Image Intelligence stdout:",
                    output
                );

                reject(
                    new Error(
                        `Invalid Image Intelligence output: ${error.message}`
                    )
                );
            }
        });
    });
}

module.exports = {
    runImageIntelligence
};