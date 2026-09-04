const crypto = require("crypto");
const path = require("path");

const DANGEROUS_EXTENSIONS = [
  ".exe", ".scr", ".vbs", ".js", ".bat", ".ps1", 
  ".cmd", ".hqx", ".msi", ".jar", ".iso", ".img"
];

const ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z", ".tar", ".gz"];
const MACRO_OFFICE_EXTENSIONS = [".docm", ".xlsm", ".pptm"];

/**
 * Analyze an array of attachments extracted from the parser.
 * @param {Array} attachments - Array of attachment objects { filename, contentType, size, content }
 */
async function analyzeAttachments(attachments = []) {
  if (!attachments || attachments.length === 0) {
    return {
      summary: {
        total_attachments: 0,
        has_high_risk_files: false,
        has_executable_types: false,
        has_macros_or_scripts: false,
        max_attachment_risk_score: 0,
        overall_status: "LOW"
      },
      attachments: []
    };
  }

  const processed = [];
  let maxScore = 0;
  let hasExecutable = false;
  let hasMacroScript = false;

  for (const file of attachments) {
    const filename = file.filename || "unnamed_attachment";
    const ext = path.extname(filename).toLowerCase();
    const indicators = [];
    let riskScore = 0;

    // 1. Extension & File Type Checks
    const isExecutable = DANGEROUS_EXTENSIONS.includes(ext);
    const isArchive = ARCHIVE_EXTENSIONS.includes(ext);
    const hasMacro = MACRO_OFFICE_EXTENSIONS.includes(ext);

    // Double extension check (e.g., invoice.pdf.exe)
    const nameParts = filename.split(".");
    const hasDoubleExtension = nameParts.length > 2 && isExecutable;

    if (isExecutable) {
      riskScore += 80;
      indicators.push(`High-risk executable extension detected (${ext})`);
      hasExecutable = true;
    }

    if (hasDoubleExtension) {
      riskScore += 15;
      indicators.push("Suspicious double file extension detected");
    }

    if (isArchive) {
      riskScore += 30;
      indicators.push("Archive file format; may conceal executable payloads");
    }

    if (hasMacro) {
      riskScore += 60;
      indicators.push("Macro-enabled Microsoft Office file detected");
      hasMacroScript = true;
    }

    // Cap maximum score at 100
    riskScore = Math.min(riskScore, 100);
    maxScore = Math.max(maxScore, riskScore);

    // 2. Risk Level Assignment
    let riskLevel = "LOW";
    if (riskScore >= 80) riskLevel = "CRITICAL";
    else if (riskScore >= 50) riskLevel = "HIGH";
    else if (riskScore >= 20) riskLevel = "MEDIUM";

    // 3. Hash Calculation
    let hashes = { md5: "", sha256: "" };
    const rawData = file.content || file.buffer || file.data;

    try {
      let buffer = null;

      if (rawData) {
        if (Buffer.isBuffer(rawData)) {
          buffer = rawData;
        } else if (typeof rawData === "string" && rawData.length > 0) {
          const cleanBase64 = rawData.replace(/\s+/g, "");
          buffer = Buffer.from(cleanBase64, "base64");
        }
      } else if (file.path && require("fs").existsSync(file.path)) {
        buffer = require("fs").readFileSync(file.path);
      }

      if (buffer && buffer.length > 0) {
        hashes.md5 = crypto.createHash("md5").update(buffer).digest("hex");
        hashes.sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
      }
    } catch (err) {
      console.error(`❌ Hash calculation error for ${filename}:`, err.message);
    }

    processed.push({
      filename,
      contentType: file.contentType || "application/octet-stream",
      size: file.size || 0,
      hashes,
      risk_score: riskScore,
      risk_level: riskLevel,
      indicators,
      structural_analysis: {
        is_executable: isExecutable,
        is_archive: isArchive,
        has_macro: hasMacro,
        has_embedded_javascript: false,
        has_double_extension: hasDoubleExtension,
        extension_mime_mismatch: false
      }
    });
  }

  // Determine overall status
  let overallStatus = "LOW";
  if (maxScore >= 80) overallStatus = "CRITICAL";
  else if (maxScore >= 50) overallStatus = "HIGH";
  else if (maxScore >= 20) overallStatus = "MEDIUM";

  return {
    summary: {
      total_attachments: attachments.length,
      has_high_risk_files: maxScore >= 50,
      has_executable_types: hasExecutable,
      has_macros_or_scripts: hasMacroScript,
      max_attachment_risk_score: maxScore,
      overall_status: overallStatus
    },
    attachments: processed
  };
}

module.exports = { analyzeAttachments };