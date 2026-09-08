const { spawn } = require("child_process");
const path = require("path");

/**
 * Runs Domain and IP Intelligence
 *
 * @param {Object} parsedEmail
 * @param {Object} headerForensics
 * @returns {Promise<Object>}
 */
function analyzeNetworkAndDomains(
  parsedEmail,
  headerForensics = {}
) {
  return new Promise((resolve, reject) => {

    const isWindows =
      process.platform === "win32";


    const pythonExecutable =
      isWindows
        ? path.resolve(
            __dirname,
            "../../.venv/Scripts/python.exe"
          )
        : path.resolve(
            __dirname,
            "../../.venv/bin/python"
          );


    const projectRoot =
      path.resolve(
        __dirname,
        "../../"
      );


    const pythonScript = `
import sys
import json

from intelligence.domain_intelligence import analyze_domain_intelligence
from intelligence.ip_intelligence import analyze_ip_intelligence


payload = json.loads(
    sys.stdin.read()
)


parsed = payload.get(
    "parsedEmail",
    {}
)


forensics = payload.get(
    "headerForensics",
    {}
)


# ============================================================
# PARSED EMAIL DATA
# ============================================================

headers = parsed.get(
    "headers",
    {}
)


links = parsed.get(
    "links",
    []
)


body_urls = [
    l
    if isinstance(l, str)
    else l.get("url", "")
    for l in links
]


from_hdr = (
    headers.get("from")
    or ""
)


reply_to_hdr = (
    headers.get("replyTo")
    or headers.get("reply-to")
    or ""
)


return_path_hdr = (
    headers.get("returnPath")
    or headers.get("return-path")
    or ""
)


# ============================================================
# 1. DOMAIN INTELLIGENCE
# ============================================================

domain_report = (
    analyze_domain_intelligence(
        from_header=from_hdr,
        reply_to_header=reply_to_hdr,
        return_path_header=return_path_hdr,
        body_urls=body_urls
    )
)


# ============================================================
# 2. IP INTELLIGENCE
# ============================================================

routing = (
    forensics.get(
        "network_hops",
        {}
    )
)


origin_ip = (
    routing.get(
        "origin_ip_candidate"
    )
)


extracted_ips = (
    routing.get(
        "all_extracted_ips"
    )
    or []
)


if not extracted_ips:

    for hop in routing.get(
        "hop_chain",
        []
    ):

        if isinstance(
            hop,
            dict
        ):

            extracted_ips.extend(
                hop.get(
                    "extracted_public_ips",
                    []
                )
            )


# Remove duplicates while preserving order
extracted_ips = list(
    dict.fromkeys(
        extracted_ips
    )
)


ip_report = (
    analyze_ip_intelligence(
        origin_ip=origin_ip,
        all_extracted_ips=extracted_ips
    )
)


# ============================================================
# 3. AGGREGATE INTELLIGENCE SIGNALS
# ============================================================

signals = {}


if isinstance(
    domain_report,
    dict
):

    signals.update(
        domain_report.get(
            "signals",
            {}
        )
    )


if isinstance(
    ip_report,
    dict
):

    signals.update(
        ip_report.get(
            "signals",
            {}
        )
    )


# ============================================================
# 4. FINAL OUTPUT
# ============================================================

output = {

    "domainIntelligence":
        domain_report,

    "ipIntelligence":
        ip_report,

    "intelligenceSignals":
        signals
}


print(
    json.dumps(
        output,
        default=str
    )
)
`;


    let pyProcess;


    try {

      pyProcess = spawn(
        pythonExecutable,
        [
          "-c",
          pythonScript
        ],
        {
          cwd: projectRoot,

          windowsHide:
            true,

          stdio: [
            "pipe",
            "pipe",
            "pipe"
          ]
        }
      );

    } catch (error) {

      return reject(
        error
      );

    }


    let output = "";
    let errorOutput = "";

    let settled = false;
    let stdinClosed = false;


    // ============================================================
    // SAFE RESOLVE / REJECT
    // ============================================================

    function safeResolve(value) {

      if (settled) {
        return;
      }

      settled = true;

      resolve(value);

    }


    function safeReject(error) {

      if (settled) {
        return;
      }

      settled = true;

      reject(error);

    }


    // ============================================================
    // STDIN SAFETY
    // ============================================================

    function closeStdinSafely() {

      if (
        stdinClosed ||
        !pyProcess ||
        !pyProcess.stdin
      ) {

        return;

      }


      stdinClosed = true;


      try {

        if (
          !pyProcess.stdin.destroyed
        ) {

          pyProcess.stdin.end();

        }

      } catch (error) {

        console.warn(
          "⚠️ Intelligence stdin close warning:",
          error.message
        );

      }

    }


    // ============================================================
    // PROCESS ERROR
    // ============================================================

    pyProcess.on(
      "error",
      (error) => {

        console.warn(
          "⚠️ Intelligence process error:",
          error.message
        );


        safeReject(
          error
        );

      }
    );


    // ============================================================
    // STDOUT
    // ============================================================

    if (pyProcess.stdout) {

      pyProcess.stdout.on(
        "data",
        (chunk) => {

          output +=
            chunk.toString();

        }
      );


      pyProcess.stdout.on(
        "error",
        (error) => {

          console.warn(
            "⚠️ Intelligence stdout error:",
            error.message
          );

        }
      );

    }


    // ============================================================
    // STDERR
    // ============================================================

    if (pyProcess.stderr) {

      pyProcess.stderr.on(
        "data",
        (chunk) => {

          errorOutput +=
            chunk.toString();

        }
      );


      pyProcess.stderr.on(
        "error",
        (error) => {

          console.warn(
            "⚠️ Intelligence stderr error:",
            error.message
          );

        }
      );

    }


    // ============================================================
    // STDIN ERROR
    // ============================================================

    if (pyProcess.stdin) {

      pyProcess.stdin.on(
        "error",
        (error) => {

          /*
           * IMPORTANT:
           *
           * A closed Python process can cause
           * EPIPE / EOF on stdin.
           *
           * Do NOT allow that to become an
           * uncaught Node.js exception.
           */

          console.warn(
            "⚠️ Intelligence stdin error:",
            error.message
          );

          /*
           * If the process itself is already
           * terminating, close handling below
           * will determine final success/failure.
           */

        }
      );

    }


    // ============================================================
    // SEND DATA TO PYTHON
    // ============================================================

    try {

      const payload =
        JSON.stringify({

          parsedEmail,

          headerForensics

        });


      if (
        pyProcess.stdin &&
        !pyProcess.stdin.destroyed &&
        pyProcess.stdin.writable
      ) {

        pyProcess.stdin.write(
          payload,
          "utf8",
          (error) => {

            if (error) {

              console.warn(
                "⚠️ Intelligence stdin write warning:",
                error.message
              );

            }


            closeStdinSafely();

          }
        );

      } else {

        closeStdinSafely();

      }

    } catch (error) {

      console.warn(
        "⚠️ Failed to send data to intelligence process:",
        error.message
      );


      closeStdinSafely();

    }


    // ============================================================
    // PYTHON PROCESS CLOSED
    // ============================================================

    pyProcess.on(
      "close",
      (code) => {

        closeStdinSafely();


        if (code !== 0) {

          const message =
            errorOutput.trim()
            ||
            `Intelligence analysis failed (code ${code})`;


          return safeReject(
            new Error(
              message
            )
          );

        }


        const rawOutput =
          output.trim();


        if (!rawOutput) {

          return safeReject(
            new Error(
              "Intelligence analysis returned empty output"
            )
          );

        }


        try {

          const result =
            JSON.parse(
              rawOutput
            );


          safeResolve(
            result
          );

        } catch (error) {

          safeReject(
            new Error(
              `Failed to parse intelligence JSON output: ${error.message}`
            )
          );

        }

      }
    );

  });
}


module.exports = {
  analyzeNetworkAndDomains
};