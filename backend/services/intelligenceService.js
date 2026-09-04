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

headers = parsed.get("headers", {})
links = parsed.get("links", [])
body_urls = [l if isinstance(l, str) else l.get("url", "") for l in links]

from_hdr = headers.get("from") or ""
reply_to_hdr = headers.get("replyTo") or headers.get("reply-to") or ""
return_path_hdr = headers.get("returnPath") or headers.get("return-path") or ""

# 1. Domain Intelligence
domain_report = analyze_domain_intelligence(
    from_header=from_hdr,
    reply_to_header=reply_to_hdr,
    return_path_header=return_path_hdr,
    body_urls=body_urls
)

# 2. IP Intelligence
routing = forensics.get("routing_analysis", {})
origin_ip = routing.get("origin_ip")
extracted_ips = routing.get("all_extracted_ips") or []

if not extracted_ips and "hops" in routing:
    extracted_ips = [h.get("ip") for h in routing["hops"] if h.get("ip")]

ip_report = analyze_ip_intelligence(
    origin_ip=origin_ip,
    all_extracted_ips=extracted_ips
)

# 3. Aggregate Signals
signals = {}
if isinstance(domain_report, dict):
    signals.update(domain_report.get("signals", {}))
if isinstance(ip_report, dict):
    signals.update(ip_report.get("signals", {}))

output = {
    "domainIntelligence": domain_report,
    "ipIntelligence": ip_report,
    "intelligenceSignals": signals
}

print(json.dumps(output, default=str))
`;

    const pyProcess = spawn(pythonExecutable, ["-c", pythonScript], {
      cwd: projectRoot
    });

    let output = "";
    let errorOutput = "";

    pyProcess.stdin.write(JSON.stringify({ parsedEmail, headerForensics }));
    pyProcess.stdin.end();

    pyProcess.stdout.on("data", (chunk) => {
      output += chunk.toString();
    });

    pyProcess.stderr.on("data", (chunk) => {
      errorOutput += chunk.toString();
    });

    pyProcess.on("close", (code) => {
      if (code !== 0) {
        return reject(
          new Error(`Intelligence analysis failed (code ${code}): ${errorOutput}`)
        );
      }
      try {
        const result = JSON.parse(output.trim());
        resolve(result);
      } catch (err) {
        reject(
          new Error(`Failed to parse intelligence JSON output: ${err.message}`)
        );
      }
    });

    pyProcess.on("error", (err) => {
      reject(err);
    });
  });
}

module.exports = {
  analyzeNetworkAndDomains
};