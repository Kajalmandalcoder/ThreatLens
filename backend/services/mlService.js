const { spawn } = require("child_process");
const path = require("path");

function runMLPrediction(text, explanationText = text) {
    return new Promise((resolve, reject) => {

        const projectRoot =
            path.join(__dirname, "../..");

        const mlScript =
            path.join(
                projectRoot,
                "ml_predict.py"
            );

        const pythonPath = path.join(projectRoot, ".venv", "Scripts", "python.exe");

        let output = "";
        let errorOutput = "";
        let settled = false;


        function fail(error) {

            if (settled) {
                return;
            }

            settled = true;
            reject(error);

        }


        function succeed(result) {

            if (settled) {
                return;
            }

            settled = true;
            resolve(result);

        }


        let pythonProcess;

        try {

            pythonProcess =
    spawn(
        pythonPath,
        [mlScript],
        {
            windowsHide: true
        }
    );

pythonProcess.stdin.write(
    JSON.stringify({
        text,
        explanationText
    })
);

pythonProcess.stdin.end();

        } catch (error) {

            console.warn(
                "⚠️ ML process could not start:",
                error.message
            );

            return fail(error);

        }


        /*
         * Prevent an unhandled child-process/socket error
         * from crashing the Node.js server.
         */

        pythonProcess.on(
            "error",
            (error) => {

                console.warn(
                    "⚠️ ML process error:",
                    error.message
                );

                fail(error);

            }
        );


        if (pythonProcess.stdout) {

            pythonProcess.stdout.on(
                "data",
                (data) => {

                    output +=
                        data.toString();

                }
            );

        }


        if (pythonProcess.stderr) {

            pythonProcess.stderr.on(
                "data",
                (data) => {

                    errorOutput +=
                        data.toString();

                }
            );

        }


        /*
         * Important:
         * close fires after stdout/stderr streams
         * have closed, so parse only here.
         */

        pythonProcess.on(
            "close",
            (code) => {

                if (settled) {
                    return;
                }


                if (code !== 0) {

                   const message = errorOutput.trim() || `ML process exited with code ${code}`;
                    console.warn(
                        "⚠️ ML prediction unavailable:",
                        message
                    );

                    return fail(
                        new Error(
                            message
                        )
                    );

                }


                const rawOutput =
                    output.trim();


                if (!rawOutput) {

                    return fail(
                        new Error(
                            "ML process returned empty output"
                        )
                    );

                }


                try {

                    const result =
                        JSON.parse(
                            rawOutput
                        );

                    succeed(result);

                } catch (error) {

                    console.warn(
                        "⚠️ ML returned invalid JSON:",
                        rawOutput
                    );

                    fail(
                        new Error(
                            "Invalid response from ML model"
                        )
                    );

                }

            }
        );


        /*
         * Some child-process failures can surface
         * through the underlying stdio streams.
         */

        if (pythonProcess.stdin) {

            pythonProcess.stdin.on(
                "error",
                (error) => {

                    console.warn(
                        "⚠️ ML stdin error:",
                        error.message
                    );

                }
            );

        }


        if (pythonProcess.stdout) {

            pythonProcess.stdout.on(
                "error",
                (error) => {

                    console.warn(
                        "⚠️ ML stdout error:",
                        error.message
                    );

                }
            );

        }


        if (pythonProcess.stderr) {

            pythonProcess.stderr.on(
                "error",
                (error) => {

                    console.warn(
                        "⚠️ ML stderr error:",
                        error.message
                    );

                }
            );

        }

    });
}
 

module.exports = {
    runMLPrediction
};



