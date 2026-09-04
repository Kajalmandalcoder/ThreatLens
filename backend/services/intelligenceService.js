const { spawn } = require("child_process");
const path = require("path");

/**
 * Runs Domain and IP Intelligence
 * @param {Object} parsedEmail - Parsed email object from parser.py
 * @param {Object} headerForensics - Forensic data from header_forensics.py
 * @returns {Promise<Object>}
 */
function analyzeNetworkAndDomains(parsedEmail, headerForensics = {}) {
  return new Promise((resolve, reject) => {
    const isWindows = process.platform === "win32";

    const pythonExecutable = isWindows
      ? path.resolve(__dirname, "../../.venv/Scripts/python.exe")
      : path.resolve(__dirname, "../../.venv/bin/python");

    const projectRoot = path.resolve(__dirname, "../../");

    const pythonScript = `
import sys
import json

from intelligence.domain_intelligence import analyze_domain_intelligence
from intelligence.ip_intelligence import analyze_ip_intelligence


payload = json.loads(sys.stdin.read())

parsed = payload.get("parsedEmail", {})
forensics = payload.get("headerForensics", {})


# ============================================================
# Parsed Email Data
# ============================================================

headers = parsed.get("headers", {})
links = parsed.get("links", [])

body_urls = [
    l if isinstance(l, str) else l.get("url", "")
    for l in links
]


from_hdr = headers.get("from") or ""

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

domain_report = analyze_domain_intelligence(
    from_header=from_hdr,
    reply_to_header=reply_to_hdr,
    return_path_header=return_path_hdr,
    body_urls=body_urls
)


# ============================================================
# 2. IP INTELLIGENCE
# ============================================================

# Header Forensics stores routing information
# inside "network_hops"
routing = forensics.get("network_hops", {})


# Header Forensics uses "origin_ip_candidate"
origin_ip = routing.get("origin_ip_candidate")


# Header Forensics directly provides all extracted public IPs
extracted_ips = routing.get("all_extracted_ips") or []


# If all_extracted_ips is empty, extract IPs
# from each hop in hop_chain
if not extracted_ips:
    for hop in routing.get("hop_chain", []):
        if isinstance(hop, dict):
            extracted_ips.extend(
                hop.get("extracted_public_ips", [])
            )


# Remove duplicate IPs while preserving order
extracted_ips = list(dict.fromkeys(extracted_ips))


# Run IP Intelligence
ip_report = analyze_ip_intelligence(
    origin_ip=origin_ip,
    all_extracted_ips=extracted_ips
)


# ============================================================
# 3. AGGREGATE INTELLIGENCE SIGNALS
# ============================================================

signals = {}


if isinstance(domain_report, dict):
    signals.update(
        domain_report.get("signals", {})
    )


if isinstance(ip_report, dict):
    signals.update(
        ip_report.get("signals", {})
    )


# ============================================================
# 4. FINAL OUTPUT
# ============================================================

output = {
    "domainIntelligence": domain_report,
    "ipIntelligence": ip_report,
    "intelligenceSignals": signals
}


print(json.dumps(output, default=str))
`;

    const pyProcess = spawn(
      pythonExecutable,
      ["-c", pythonScript],
      {
        cwd: projectRoot
      }
    );

    let output = "";
    let errorOutput = "";


    // ============================================================
    // Send data to Python
    // ============================================================

    pyProcess.stdin.write(
      JSON.stringify({
        parsedEmail,
        headerForensics
      })
    );

    pyProcess.stdin.end();


    // ============================================================
    // Capture Python Output
    // ============================================================

    pyProcess.stdout.on("data", (chunk) => {
      output += chunk.toString();
    });


    // ============================================================
    // Capture Python Errors
    // ============================================================

    pyProcess.stderr.on("data", (chunk) => {
      errorOutput += chunk.toString();
    });


    // ============================================================
    // Python Process Finished
    // ============================================================

    pyProcess.on("close", (code) => {

      if (code !== 0) {
        return reject(
          new Error(
            `Intelligence analysis failed (code ${code}): ${errorOutput}`
          )
        );
      }


      try {

        const result = JSON.parse(
          output.trim()
        );

        resolve(result);

      } catch (err) {

        reject(
          new Error(
            `Failed to parse intelligence JSON output: ${err.message}`
          )
        );

      }

    });


    // ============================================================
    // Process Error
    // ============================================================

    pyProcess.on("error", (err) => {
      reject(err);
    });

  });
}


module.exports = {
  analyzeNetworkAndDomains
};