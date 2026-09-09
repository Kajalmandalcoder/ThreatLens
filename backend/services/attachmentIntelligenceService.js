
const {
  findPreviousAttachmentCases
} = require("./attachment/caseCorrelationService");

const {
  calculateAttachmentVerdict
} = require("./attachment/verdictService");
const { inspectZipBuffer } = require("./attachment/archiveService");
const { analyzeOfficeDocument, isOfficeDocument } = require("./attachment/officeService");
const { analyzePdf } = require("./attachment/pdfService");
const { analyzeEmbeddedUrls } = require("./attachment/embeddedUrlService");
const path = require("path");
const { analyzeFileIdentity } = require("./attachment/fileIdentityService");
const { analyzeEntropy } = require("./attachment/entropyService");
const { calculateHashes } = require("./attachment/hashService");

const DANGEROUS_EXTENSIONS = new Set([
  ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".msi", 
  ".jar", ".hta", ".lnk", ".com", ".pif", ".cpl", ".reg"
]);

const ARCHIVE_EXTENSIONS = new Set([
  ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"
]);

const MACRO_EXTENSIONS = new Set([
  ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"
]);

function decodeAttachmentContent(file) {
  const rawData = file.content || file.buffer || file.data;
  if (!rawData) return null;

  try {
    if (Buffer.isBuffer(rawData)) return rawData;
    if (typeof rawData === "string") {
      return Buffer.from(rawData.replace(/\s+/g, ""), "base64");
    }
    return null;
  } catch {
    return null;
  }
}

function detectDoubleExtension(filename) {
  const parts = String(filename).toLowerCase().split(".");
  if (parts.length < 3) return false;
  const finalExtension = "." + parts[parts.length - 1];
  return DANGEROUS_EXTENSIONS.has(finalExtension);
}

function calculateBaseRisk({
  isExecutable, isArchive, hasMacro, doubleExtension,
  extensionMismatch, magicMismatch, entropyLevel
}) {
  let score = 0;
  if (isExecutable) score += 60;
  if (isArchive) score += 15;
  if (hasMacro) score += 45;
  if (doubleExtension) score += 25;
  if (extensionMismatch) score += 35;
  if (magicMismatch) score += 45;
  if (entropyLevel === "VERY_HIGH") score += 10;
  return Math.min(score, 100);
}

function riskLevel(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 20) return "MEDIUM";
  return "LOW";
}

async function analyzeAttachments(attachments = [], options = {}) {
  const analyzeUrls = options.analyzeUrls;
  const senderEmail = options.senderEmail || "";
  const caseId = options.caseId || null;
  const userId = options.userId || null;

  if (!Array.isArray(attachments)) attachments = [];

  if (attachments.length === 0) {
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
    const contentType = file.contentType || "application/octet-stream";
    const buffer = decodeAttachmentContent(file);
    const extension = path.extname(filename).toLowerCase();

    const isExecutable = DANGEROUS_EXTENSIONS.has(extension);
    const isArchive = ARCHIVE_EXTENSIONS.has(extension);
    const hasMacro = MACRO_EXTENSIONS.has(extension);
    const hasDoubleExtension = detectDoubleExtension(filename);

    const identity = analyzeFileIdentity(filename, contentType, buffer);
    const entropy = analyzeEntropy(buffer);
    const hashes = calculateHashes(buffer);

    // 1. ADDED: Run the deep analysis services
    const archiveAnalysis = await inspectZipBuffer(buffer, 0, filename);
    const officeAnalysis = await analyzeOfficeDocument(buffer, filename);
    const pdfAnalysis = analyzePdf(buffer);
    const embeddedUrls = [
      ...(officeAnalysis.internal_urls || []),
      ...(pdfAnalysis.urls || [])
    ];
    const embeddedUrlAnalysis = analyzeEmbeddedUrls(embeddedUrls);
    

    let embeddedUrlIntelligence = null;

    if (
      typeof analyzeUrls === "function" &&
      embeddedUrls.length > 0
    ) {
      try {
        embeddedUrlIntelligence = await analyzeUrls(
          embeddedUrls,
          senderEmail
        );
      } catch (error) {
        console.warn(
          "Embedded URL Intelligence failed:",
          error.message
        );

        embeddedUrlIntelligence = {
          summary: {
            total_urls: embeddedUrls.length,
            critical_risk_urls: 0,
            high_risk_urls: 0,
            medium_risk_urls: 0,
            low_risk_urls: 0,
            max_risk_score: 0,
            overall_status: "UNKNOWN"
          },
          urls: [],
          error: error.message
        };
      }
    }

    

    const indicators = [];
    if (isExecutable) {
      indicators.push(`Executable file extension detected (${extension})`);
      hasExecutable = true;
    }
    if (isArchive) indicators.push("Archive file detected; contents require inspection");
    if (hasMacro) {
      indicators.push("Macro-enabled Office document detected");
      hasMacroScript = true;
    }
    if (hasDoubleExtension) indicators.push("Suspicious double file extension detected");
    if (identity.extension_mime_mismatch) indicators.push("Declared MIME type does not match the filename extension");
    if (identity.magic_mime_mismatch) indicators.push("Declared MIME type does not match file signature");
    if (identity.extension_magic_mismatch) indicators.push("Filename extension does not match detected file signature");
    if (entropy.level === "VERY_HIGH") indicators.push("Very high file entropy detected");

    let score = calculateBaseRisk({
      isExecutable,
      isArchive,
      hasMacro,
      doubleExtension: hasDoubleExtension,
      extensionMismatch: identity.extension_mime_mismatch || identity.extension_magic_mismatch,
      magicMismatch: identity.magic_mime_mismatch,
      entropyLevel: entropy.level
    });

    // 2. ADDED: Internal risk evaluation based on the analysis
    const internalExecutable = archiveAnalysis.dangerous_files.length > 0;
    const internalScripts = archiveAnalysis.script_files.length > 0;
    const nestedArchive = archiveAnalysis.nested_archives.length > 0;
    const embeddedObjects = officeAnalysis.has_embedded_objects || pdfAnalysis.has_embedded_files;
    const embeddedJavascript = officeAnalysis.has_vba || pdfAnalysis.has_javascript;

    // 3. ADDED: Adding evidence to the score
    if (internalExecutable) {
      score += 50;
      indicators.push("Executable file discovered inside attachment");
    }
    if (internalScripts) {
      score += 30;
      indicators.push("Script file discovered inside attachment");
    }
    if (nestedArchive) {
      score += 15;
      indicators.push("Nested archive detected");
    }
    if (embeddedObjects) {
      score += 20;
      indicators.push("Embedded object/file detected");
    }
    if (embeddedJavascript) {
      score += 35;
      indicators.push("Active content or JavaScript indicators detected");
    }
    if (embeddedUrlAnalysis.total_urls > 0) {
      indicators.push(`${embeddedUrlAnalysis.total_urls} URL(s) extracted from attachment`);
    }

    // 4. ADDED: Cap score at 100
    score = Math.min(score, 100);
    maxScore = Math.max(maxScore, score);


    // Previous case correlation
    let previousCases = [];
    try {
      previousCases = await findPreviousAttachmentCases({
        sha256: hashes.sha256,
        currentCaseId: caseId,
        userId
      });
    } catch (error) {
      console.warn(
        `Previous case correlation failed for ${filename}:`,
        error.message
      );
    }

    const attachmentForVerdict = {
      risk_score: score,

      structural_analysis: {
        has_internal_executables:
          archiveAnalysis.dangerous_files.some(
            file =>
              /\.(exe|dll|scr|com|pif|cpl|msi|jar|lnk|reg)$/i.test(
                file.name ||
                file.path ||
                file.filename ||
                ""
              )
          ),

        has_internal_scripts:
          archiveAnalysis.script_files.length > 0,

        has_nested_archives:
          archiveAnalysis.nested_archives.length > 0,

        has_embedded_objects:
          officeAnalysis.has_embedded_objects ||
          pdfAnalysis.has_embedded_files,

        magic_mime_mismatch:
          identity.magic_mime_mismatch,

        extension_magic_mismatch:
          identity.extension_magic_mismatch,

        extension_mime_mismatch:
          identity.extension_mime_mismatch,

        double_extension:
          hasDoubleExtension
      },

      archive_analysis: archiveAnalysis,

      office_analysis: officeAnalysis,

      pdf_analysis: pdfAnalysis,

      embedded_url_analysis: embeddedUrlAnalysis,

      embedded_url_intelligence: embeddedUrlIntelligence,

      previous_cases: previousCases
    };

    const malwareVerdict =calculateAttachmentVerdict(attachmentForVerdict);

    // ============================================================
// UNIFIED ATTACHMENT RISK SCORE
// ============================================================

    let unifiedScore = Number(malwareVerdict.score || score);

    // Add risk from embedded URL intelligence
    const embeddedUrlMaxScore =
      Number(
        embeddedUrlIntelligence?.summary?.max_risk_score || 0
      );

    if (embeddedUrlMaxScore >= 80) {
      unifiedScore += 30;
    } else if (embeddedUrlMaxScore >= 60) {
      unifiedScore += 20;
    } else if (embeddedUrlMaxScore >= 30) {
      unifiedScore += 10;
    }

    // Previous-case correlation
    if (previousCases.length > 0) {
      unifiedScore += 15;
    }

    // Cap between 0 and 100
    unifiedScore = Math.min(
      100,
      Math.max(0, unifiedScore)
    );

    const unifiedRiskLevel = riskLevel(unifiedScore);
    // 5. ADDED: The replaced processed.push object
    processed.push({
      filename,

      contentType,

      size: buffer?.length || file.size || 0,

      hashes,

      file_identity: identity,

      entropy,

      archive_analysis: archiveAnalysis,

      office_analysis: officeAnalysis,

      pdf_analysis: pdfAnalysis,

      embedded_url_analysis: embeddedUrlAnalysis,

      embedded_url_intelligence: embeddedUrlIntelligence,

      previous_cases: previousCases,

      malware_verdict: malwareVerdict,

      risk_score: unifiedScore,

      risk_level: unifiedRiskLevel,

      indicators,

      structural_analysis: {
        has_executable: isExecutable,
        has_archive: isArchive || archiveAnalysis.is_archive,
        has_macro: hasMacro || officeAnalysis.has_vba,

        has_embedded_javascript:
          officeAnalysis.suspicious_parts.some(part =>
            /javascript|customUI/i.test(part)
          ) ||
          pdfAnalysis.has_javascript,

        double_extension: hasDoubleExtension,

        extension_mime_mismatch:
          identity.extension_mime_mismatch,

        magic_mime_mismatch:
          identity.magic_mime_mismatch,

        extension_magic_mismatch:
          identity.extension_magic_mismatch,

        has_embedded_objects:
          officeAnalysis.has_embedded_objects ||
          pdfAnalysis.has_embedded_files,

        has_nested_archives:
          archiveAnalysis.nested_archives.length > 0,

        has_internal_executables:
          archiveAnalysis.dangerous_files.some(
            file =>
              /\.(exe|dll|scr|com|pif|cpl|msi|jar|lnk|reg)$/i.test(
                file.name ||
                file.path ||
                file.filename ||
                ""
              )
          ),

        has_internal_scripts:
          archiveAnalysis.script_files.length > 0
      }
    });
  }



// ============================================================
// FINAL ATTACHMENT SUMMARY
// ============================================================

  const maxRiskScore = processed.reduce(
    (max, attachment) =>
      Math.max(max, Number(attachment.risk_score || 0)),
    0
  );

  const maliciousCount = processed.filter(
    attachment =>
      attachment.malware_verdict?.verdict === "MALICIOUS"
  ).length;

  const suspiciousCount = processed.filter(
    attachment =>
      attachment.malware_verdict?.verdict === "SUSPICIOUS"
  ).length;

  const benignCount = processed.filter(
    attachment =>
      attachment.malware_verdict?.verdict === "BENIGN"
  ).length;

  const unknownCount = processed.filter(
    attachment =>
      attachment.malware_verdict?.verdict === "UNKNOWN"
  ).length;

  const executableCount = processed.filter(
    attachment =>
      attachment.structural_analysis?.has_executable ||
      attachment.structural_analysis?.has_internal_executables
  ).length;

  const archiveCount = processed.filter(
    attachment =>
      attachment.structural_analysis?.has_archive
  ).length;

  const macroCount = processed.filter(
    attachment =>
      attachment.structural_analysis?.has_macro
  ).length;

  const embeddedObjectCount = processed.filter(
    attachment =>
      attachment.structural_analysis?.has_embedded_objects
  ).length;

  const nestedArchiveCount = processed.filter(
    attachment =>
      attachment.structural_analysis?.has_nested_archives
  ).length;

  const scriptCount = processed.filter(
    attachment =>
      attachment.structural_analysis?.has_internal_scripts ||
      attachment.structural_analysis?.has_embedded_javascript
  ).length;

  const previousCaseCount = processed.reduce(
    (total, attachment) =>
      total + (attachment.previous_cases?.length || 0),
    0
  );

  const embeddedUrlCount = processed.reduce(
    (total, attachment) =>
      total +
      Number(
        attachment.embedded_url_analysis?.total_urls || 0
      ),
    0
  );

  const overallStatus = riskLevel(maxRiskScore);

  return {
    summary: {
      total_attachments: processed.length,

      max_attachment_risk_score: maxRiskScore,
      overall_status: overallStatus,

      malicious_count: maliciousCount,
      suspicious_count: suspiciousCount,
      benign_count: benignCount,
      unknown_count: unknownCount,

      has_high_risk_files: maxRiskScore >= 50,

      has_executable_types: executableCount > 0,
      has_macros_or_scripts:
        macroCount > 0 || scriptCount > 0,

      executable_count: executableCount,
      archive_count: archiveCount,
      macro_count: macroCount,
      embedded_object_count: embeddedObjectCount,
      nested_archive_count: nestedArchiveCount,
      script_count: scriptCount,

      previous_case_count: previousCaseCount,
      embedded_url_count: embeddedUrlCount
    },

    attachments: processed
  };
}

module.exports = {
  analyzeAttachments
};