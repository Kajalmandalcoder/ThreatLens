const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const JSZip = require("jszip");

const DANGEROUS_EXTENSIONS = [
  ".exe",
  ".scr",
  ".vbs",
  ".js",
  ".bat",
  ".ps1",
  ".cmd",
  ".hqx",
  ".msi",
  ".jar",
  ".iso",
  ".img"
];

const ARCHIVE_EXTENSIONS = [
  ".zip",
  ".rar",
  ".7z",
  ".tar",
  ".gz"
];

const MACRO_OFFICE_EXTENSIONS = [
  ".docm",
  ".xlsm",
  ".pptm"
];

const OFFICE_EXTENSIONS = [
  ".docx",
  ".docm",
  ".xlsx",
  ".xlsm",
  ".pptx",
  ".pptm"
];

/**
 * ---------------------------------------------------------
 * Convert parser attachment content into Buffer
 * ---------------------------------------------------------
 */
function getAttachmentBuffer(file) {
  const rawData = file.content || file.buffer || file.data;

  if (Buffer.isBuffer(rawData)) {
    return rawData;
  }

  if (typeof rawData === "string" && rawData.length > 0) {
    const cleanBase64 = rawData.replace(/\s+/g, "");

    try {
      return Buffer.from(cleanBase64, "base64");
    } catch (error) {
      console.warn(
        `⚠️ Base64 decoding failed for ${file.filename}:`,
        error.message
      );
    }
  }

  if (file.path && fs.existsSync(file.path)) {
    return fs.readFileSync(file.path);
  }

  return null;
}

/**
 * ---------------------------------------------------------
 * Magic byte / file signature detection
 * ---------------------------------------------------------
 */
function detectFileType(buffer) {
  if (!buffer || buffer.length === 0) {
    return {
      detected_type: "EMPTY",
      mime_type: "application/octet-stream"
    };
  }

  // PDF
  if (buffer.subarray(0, 5).toString() === "%PDF-") {
    return {
      detected_type: "PDF",
      mime_type: "application/pdf"
    };
  }

  // ZIP / OOXML
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    buffer[2] === 0x03 &&
    buffer[3] === 0x04
  ) {
    return {
      detected_type: "ZIP",
      mime_type: "application/zip"
    };
  }

  // Windows PE / EXE
  if (
    buffer.length >= 2 &&
    buffer[0] === 0x4d &&
    buffer[1] === 0x5a
  ) {
    return {
      detected_type: "EXE",
      mime_type: "application/vnd.microsoft.portable-executable"
    };
  }

  // RAR4
  if (
    buffer.length >= 7 &&
    buffer
      .subarray(0, 7)
      .equals(
        Buffer.from([
          0x52,
          0x61,
          0x72,
          0x21,
          0x1a,
          0x07,
          0x00
        ])
      )
  ) {
    return {
      detected_type: "RAR",
      mime_type: "application/x-rar-compressed"
    };
  }

  // RAR5
  if (
    buffer.length >= 8 &&
    buffer
      .subarray(0, 8)
      .equals(
        Buffer.from([
          0x52,
          0x61,
          0x72,
          0x21,
          0x1a,
          0x07,
          0x01,
          0x00
        ])
      )
  ) {
    return {
      detected_type: "RAR",
      mime_type: "application/x-rar-compressed"
    };
  }

  // 7-Zip
  if (
    buffer.length >= 6 &&
    buffer
      .subarray(0, 6)
      .equals(
        Buffer.from([
          0x37,
          0x7a,
          0xbc,
          0xaf,
          0x27,
          0x1c
        ])
      )
  ) {
    return {
      detected_type: "7Z",
      mime_type: "application/x-7z-compressed"
    };
  }

  // GZIP
  if (
    buffer.length >= 2 &&
    buffer[0] === 0x1f &&
    buffer[1] === 0x8b
  ) {
    return {
      detected_type: "GZIP",
      mime_type: "application/gzip"
    };
  }

  // Windows shortcut (.lnk)
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x4c &&
    buffer[1] === 0x00 &&
    buffer[2] === 0x00 &&
    buffer[3] === 0x00
  ) {
    return {
      detected_type: "LNK",
      mime_type: "application/x-ms-shortcut"
    };
  }

  // OLE Compound File
  if (
    buffer.length >= 8 &&
    buffer
      .subarray(0, 8)
      .equals(
        Buffer.from([
          0xd0,
          0xcf,
          0x11,
          0xe0,
          0xa1,
          0xb1,
          0x1a,
          0xe1
        ])
      )
  ) {
    return {
      detected_type: "OLE",
      mime_type: "application/x-ole-storage"
    };
  }

  // PNG
  if (
    buffer.length >= 8 &&
    buffer
      .subarray(0, 8)
      .equals(
        Buffer.from([
          0x89,
          0x50,
          0x4e,
          0x47,
          0x0d,
          0x0a,
          0x1a,
          0x0a
        ])
      )
  ) {
    return {
      detected_type: "PNG",
      mime_type: "image/png"
    };
  }

  // JPEG
  if (
    buffer.length >= 3 &&
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {
    return {
      detected_type: "JPEG",
      mime_type: "image/jpeg"
    };
  }

  // GIF
  const gifHeader = buffer.subarray(0, 6).toString();

  if (gifHeader === "GIF89a" || gifHeader === "GIF87a") {
    return {
      detected_type: "GIF",
      mime_type: "image/gif"
    };
  }

  return {
    detected_type: "UNKNOWN",
    mime_type: "application/octet-stream"
  };
}

/**
 * ---------------------------------------------------------
 * Extension -> expected actual type
 * ---------------------------------------------------------
 */
function getExpectedTypes(extension) {
  const mapping = {
    ".pdf": ["PDF"],

    ".zip": ["ZIP"],
    ".rar": ["RAR"],
    ".7z": ["7Z"],
    ".gz": ["GZIP"],

    ".exe": ["EXE"],
    ".dll": ["EXE"],
    ".scr": ["EXE"],

    ".docx": ["ZIP"],
    ".docm": ["ZIP"],
    ".xlsx": ["ZIP"],
    ".xlsm": ["ZIP"],
    ".pptx": ["ZIP"],
    ".pptm": ["ZIP"],

    ".jpg": ["JPEG"],
    ".jpeg": ["JPEG"],
    ".png": ["PNG"],
    ".gif": ["GIF"]
  };

  return mapping[extension] || [];
}

/**
 * ---------------------------------------------------------
 * Extension vs actual file type
 * ---------------------------------------------------------
 */
function checkExtensionMatch(extension, detectedType) {
  const expectedTypes = getExpectedTypes(extension);

  if (
    expectedTypes.length === 0 ||
    detectedType === "EMPTY" ||
    detectedType === "UNKNOWN"
  ) {
    return {
      matches: null,
      reason: null
    };
  }

  const matches = expectedTypes.includes(detectedType);

  return {
    matches,
    reason: matches
      ? null
      : "Extension does not match detected file type"
  };
}

/**
 * ---------------------------------------------------------
 * Shannon entropy
 * ---------------------------------------------------------
 */
function calculateEntropy(buffer) {
  if (!buffer || buffer.length === 0) {
    return 0;
  }

  const frequencies = new Array(256).fill(0);

  for (const byte of buffer) {
    frequencies[byte]++;
  }

  let entropy = 0;

  for (const count of frequencies) {
    if (count === 0) continue;

    const probability = count / buffer.length;

    entropy -= probability * Math.log2(probability);
  }

  return Number(entropy.toFixed(3));
}

/**
 * ---------------------------------------------------------
 * Entropy risk
 *
 * Entropy is ONLY a supporting signal.
 * It should never make a normal file HIGH/CRITICAL alone.
 * ---------------------------------------------------------
 */
function getEntropyRisk(entropy, detectedType) {
  if (!entropy) {
    return {
      score: 0,
      indicator: "No entropy data available"
    };
  }

  /*
   * Normal compressed/container formats naturally have
   * high entropy. Therefore we are conservative.
   */

  const compressedTypes = [
    "ZIP",
    "RAR",
    "7Z",
    "GZIP",
    "JPEG",
    "PNG",
    "GIF"
  ];

  if (compressedTypes.includes(detectedType)) {
    return {
      score: 0,
      indicator: "Entropy is expected for compressed/binary content"
    };
  }

  if (entropy >= 7.8) {
    return {
      score: 5,
      indicator:
        "High entropy detected; file may contain packed or encrypted data"
    };
  }

  if (entropy >= 7.2) {
    return {
      score: 2,
      indicator:
        "Moderately elevated entropy detected; weak supporting signal"
    };
  }

  return {
    score: 0,
    indicator: "Entropy within expected range"
  };
}

/**
 * ---------------------------------------------------------
 * ZIP / Office structural analysis
 * ---------------------------------------------------------
 */
async function analyzeZipStructure(buffer, extension) {
  const result = {
    is_zip_container: false,
    embedded_objects: false,
    macros: false,
    nested_archives: false,
    suspicious_internal_files: [],
    internal_file_count: 0,
    internal_files: []
  };

  if (!buffer || buffer.length === 0) {
    return result;
  }

  try {
    const zip = await JSZip.loadAsync(buffer);

    result.is_zip_container = true;

    const files = Object.keys(zip.files);

    result.internal_file_count = files.length;

    // Keep first 100 internal files for explainability
    result.internal_files = files.slice(0, 100);

    for (const fileName of files) {
      const lower = fileName.toLowerCase();

      // Executable/script files
      if (
        lower.endsWith(".exe") ||
        lower.endsWith(".dll") ||
        lower.endsWith(".scr") ||
        lower.endsWith(".js") ||
        lower.endsWith(".vbs") ||
        lower.endsWith(".bat") ||
        lower.endsWith(".cmd") ||
        lower.endsWith(".ps1")
      ) {
        result.suspicious_internal_files.push(fileName);
      }

      // Nested archives
      if (
        lower.endsWith(".zip") ||
        lower.endsWith(".rar") ||
        lower.endsWith(".7z") ||
        lower.endsWith(".tar") ||
        lower.endsWith(".gz")
      ) {
        result.nested_archives = true;
      }

      // OOXML embedded objects
      if (
        lower.includes("/embeddings/") ||
        lower.includes("\\embeddings\\")
      ) {
        result.embedded_objects = true;
      }

      // VBA macro
      if (lower.includes("vbaproject.bin")) {
        result.macros = true;
      }

      // ActiveX / OLE
      if (
        lower.includes("activex") ||
        lower.includes("oleobject")
      ) {
        result.embedded_objects = true;
      }
    }

    // VBA macro detection only meaningful for Office files
    if (!OFFICE_EXTENSIONS.includes(extension)) {
      result.macros = false;
    }
  } catch (error) {
    result.is_zip_container = false;
  }

  return result;
}

/**
 * ---------------------------------------------------------
 * PDF structural analysis
 * ---------------------------------------------------------
 */
function analyzePdfStructure(buffer) {
  if (!buffer) {
    return {
      embedded_objects: false,
      embedded_javascript: false,
      open_action: false,
      launch_action: false
    };
  }

  const text = buffer.toString("latin1");

  return {
    embedded_objects:
      /\/EmbeddedFile\b/i.test(text) ||
      /\/Filespec\b/i.test(text),

    embedded_javascript:
      /\/JavaScript\b/i.test(text) ||
      /\/JS\b/i.test(text),

    open_action:
      /\/OpenAction\b/i.test(text),

    launch_action:
      /\/Launch\b/i.test(text)
  };
}

/**
 * ---------------------------------------------------------
 * Analyze one attachment
 * ---------------------------------------------------------
 */
async function analyzeSingleAttachment(file) {
  const filename =
    file.filename || "unnamed_attachment";

  const extension =
    path.extname(filename).toLowerCase();

  const indicators = [];
  const riskFactors = [];

  let riskScore = 0;

  const isExecutable =
    DANGEROUS_EXTENSIONS.includes(extension);

  const isArchive =
    ARCHIVE_EXTENSIONS.includes(extension);

  const hasMacroExtension =
    MACRO_OFFICE_EXTENSIONS.includes(extension);

  /*
   * Example:
   * invoice.pdf.exe
   */
  const nameParts = filename.split(".");

  const hasDoubleExtension =
    nameParts.length > 2 && isExecutable;

  // -------------------------------------------------------
  // Get actual bytes
  // -------------------------------------------------------

  const buffer = getAttachmentBuffer(file);

  // -------------------------------------------------------
  // Actual file type
  // -------------------------------------------------------

  const detected = detectFileType(buffer);

  // -------------------------------------------------------
  // Hashes
  // -------------------------------------------------------

  let hashes = {
    md5: "",
    sha256: ""
  };

  if (buffer && buffer.length > 0) {
    hashes.md5 = crypto
      .createHash("md5")
      .update(buffer)
      .digest("hex");

    hashes.sha256 = crypto
      .createHash("sha256")
      .update(buffer)
      .digest("hex");
  }

  // -------------------------------------------------------
  // Extension vs magic bytes
  // -------------------------------------------------------

  const extensionCheck =
    checkExtensionMatch(
      extension,
      detected.detected_type
    );

  if (extensionCheck.matches === false) {
    riskScore += 35;

    indicators.push(
      "Extension does not match detected file type"
    );

    riskFactors.push({
      reason:
        "Extension does not match detected file type",
      score: 35
    });
  }

  // -------------------------------------------------------
  // Actual executable
  // -------------------------------------------------------

  if (detected.detected_type === "EXE") {
    riskScore += 80;

    indicators.push(
      "Executable file detected from file signature"
    );

    riskFactors.push({
      reason:
        "Executable file detected from file signature",
      score: 80
    });
  }

  // -------------------------------------------------------
  // Dangerous extension
  // -------------------------------------------------------

  if (
    isExecutable &&
    detected.detected_type !== "EXE"
  ) {
    riskScore += 50;

    indicators.push(
      `High-risk executable extension detected (${extension})`
    );

    riskFactors.push({
      reason:
        `High-risk executable extension detected (${extension})`,
      score: 50
    });
  }

  // -------------------------------------------------------
  // Double extension
  // -------------------------------------------------------

  if (hasDoubleExtension) {
    riskScore += 15;

    indicators.push(
      "Suspicious double file extension detected"
    );

    riskFactors.push({
      reason:
        "Suspicious double file extension detected",
      score: 15
    });
  }

  // -------------------------------------------------------
  // ZIP / Office structural analysis
  // -------------------------------------------------------

  let zipAnalysis = {
    is_zip_container: false,
    embedded_objects: false,
    macros: false,
    nested_archives: false,
    suspicious_internal_files: [],
    internal_file_count: 0,
    internal_files: []
  };

  if (
    isArchive ||
    detected.detected_type === "ZIP"
  ) {
    zipAnalysis =
      await analyzeZipStructure(
        buffer,
        extension
      );

    // Executable/script inside archive
    if (
      zipAnalysis
        .suspicious_internal_files
        .length > 0
    ) {
      riskScore += 45;

      indicators.push(
        "Executable or script found inside archive"
      );

      riskFactors.push({
        reason:
          "Executable or script found inside archive",
        score: 45,
        files:
          zipAnalysis.suspicious_internal_files
      });
    }

    // Nested archive
    if (zipAnalysis.nested_archives) {
      riskScore += 15;

      indicators.push(
        "Nested archive detected"
      );

      riskFactors.push({
        reason:
          "Nested archive detected",
        score: 15
      });
    }

    // Embedded objects
    if (zipAnalysis.embedded_objects) {
      riskScore += 20;

      indicators.push(
        "Embedded object detected"
      );

      riskFactors.push({
        reason:
          "Embedded object detected",
        score: 20
      });
    }

    // VBA
    if (zipAnalysis.macros) {
      riskScore += 40;

      indicators.push(
        "VBA macro detected"
      );

      riskFactors.push({
        reason:
          "VBA macro detected",
        score: 40
      });
    }
  }

  // -------------------------------------------------------
  // Macro-enabled Office extension
  // -------------------------------------------------------

  if (hasMacroExtension) {
    riskScore += 35;

    indicators.push(
      "Macro-enabled Microsoft Office file detected"
    );

    riskFactors.push({
      reason:
        "Macro-enabled Microsoft Office file detected",
      score: 35
    });
  }

  // -------------------------------------------------------
  // PDF analysis
  // -------------------------------------------------------

  let pdfAnalysis = {
    embedded_objects: false,
    embedded_javascript: false,
    open_action: false,
    launch_action: false
  };

  if (
    detected.detected_type === "PDF" &&
    buffer
  ) {
    pdfAnalysis =
      analyzePdfStructure(buffer);

    if (pdfAnalysis.embedded_objects) {
      riskScore += 20;

      indicators.push(
        "Embedded object detected in PDF"
      );

      riskFactors.push({
        reason:
          "Embedded object detected in PDF",
        score: 20
      });
    }

    if (pdfAnalysis.embedded_javascript) {
      riskScore += 35;

      indicators.push(
        "JavaScript detected inside PDF"
      );

      riskFactors.push({
        reason:
          "JavaScript detected inside PDF",
        score: 35
      });
    }

    if (pdfAnalysis.open_action) {
      riskScore += 10;

      indicators.push(
        "Automatic PDF OpenAction detected"
      );

      riskFactors.push({
        reason:
          "Automatic PDF OpenAction detected",
        score: 10
      });
    }

    if (pdfAnalysis.launch_action) {
      riskScore += 40;

      indicators.push(
        "PDF launch action detected"
      );

      riskFactors.push({
        reason:
          "PDF launch action detected",
        score: 40
      });
    }
  }

  // -------------------------------------------------------
  // Entropy
  // -------------------------------------------------------

  const entropy =
    calculateEntropy(buffer);

  const entropyRisk =
    getEntropyRisk(
      entropy,
      detected.detected_type
    );

  if (entropyRisk.score > 0) {
    riskScore += entropyRisk.score;

    indicators.push(
      `${entropyRisk.indicator} (entropy: ${entropy})`
    );

    riskFactors.push({
      reason:
        "Elevated file entropy detected",
      score: entropyRisk.score,
      value: entropy,
      explanation:
        "Entropy is a weak supporting signal and does not by itself indicate malware"
    });
  }

  // -------------------------------------------------------
  // Cap score
  // -------------------------------------------------------

  riskScore =
    Math.min(riskScore, 100);

  // -------------------------------------------------------
  // Risk level
  // -------------------------------------------------------

  let riskLevel = "LOW";

  if (riskScore >= 80) {
    riskLevel = "CRITICAL";
  } else if (riskScore >= 50) {
    riskLevel = "HIGH";
  } else if (riskScore >= 20) {
    riskLevel = "MEDIUM";
  }

  // -------------------------------------------------------
  // Structural analysis
  // -------------------------------------------------------

  const structuralAnalysis = {
    is_executable:
      isExecutable ||
      detected.detected_type === "EXE",

    is_archive:
      isArchive ||
      detected.detected_type === "ZIP" ||
      detected.detected_type === "RAR" ||
      detected.detected_type === "7Z" ||
      detected.detected_type === "GZIP",

    has_macro:
      hasMacroExtension ||
      zipAnalysis.macros ||
      false,

    has_embedded_javascript:
      pdfAnalysis.embedded_javascript,

    has_double_extension:
      hasDoubleExtension,

    extension_mime_mismatch:
      extensionCheck.matches === false,

    embedded_objects:
      zipAnalysis.embedded_objects ||
      pdfAnalysis.embedded_objects ||
      false,

    nested_archives:
      zipAnalysis.nested_archives,

    suspicious_internal_files:
      zipAnalysis.suspicious_internal_files,

    internal_file_count:
      zipAnalysis.internal_file_count,

    internal_files:
      zipAnalysis.internal_files
  };

  // -------------------------------------------------------
  // Final result
  // -------------------------------------------------------

  return {
    filename,

    extension,

    contentType:
      file.contentType ||
      "application/octet-stream",

    size:
      file.size ||
      buffer?.length ||
      0,

    file_type_detection: {
      detected_type:
        detected.detected_type,

      detected_mime_type:
        detected.mime_type,

      declared_mime_type:
        file.contentType ||
        "application/octet-stream",

      extension_matches_content:
        extensionCheck.matches
    },

    hashes,

    entropy_analysis: {
      entropy,

      indicator:
        entropyRisk.indicator
    },

    structural_analysis:
      structuralAnalysis,

    risk_score:
      riskScore,

    risk_level:
      riskLevel,

    indicators,

    risk_factors:
      riskFactors
  };
}

/**
 * ---------------------------------------------------------
 * Main attachment intelligence
 * ---------------------------------------------------------
 */
async function analyzeAttachments(
  attachments = []
) {
  if (
    !attachments ||
    attachments.length === 0
  ) {
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
    try {
      const result =
        await analyzeSingleAttachment(file);

      processed.push(result);

      maxScore =
        Math.max(
          maxScore,
          result.risk_score
        );

      if (
        result.structural_analysis
          .is_executable
      ) {
        hasExecutable = true;
      }

      if (
        result.structural_analysis.has_macro ||
        result.structural_analysis
          .has_embedded_javascript
      ) {
        hasMacroScript = true;
      }
    } catch (error) {
      console.error(
        `❌ Attachment analysis failed for ${file.filename}:`,
        error.message
      );

      processed.push({
        filename:
          file.filename ||
          "unnamed_attachment",

        size:
          file.size || 0,

        risk_score: 0,

        risk_level: "UNKNOWN",

        indicators: [
          "Attachment analysis could not be completed"
        ],

        risk_factors: [],

        analysis_error:
          error.message
      });
    }
  }

  // -------------------------------------------------------
  // Overall status
  // -------------------------------------------------------

  let overallStatus = "LOW";

  if (maxScore >= 80) {
    overallStatus = "CRITICAL";
  } else if (maxScore >= 50) {
    overallStatus = "HIGH";
  } else if (maxScore >= 20) {
    overallStatus = "MEDIUM";
  }

  return {
    summary: {
      total_attachments:
        attachments.length,

      has_high_risk_files:
        maxScore >= 50,

      has_executable_types:
        hasExecutable,

      has_macros_or_scripts:
        hasMacroScript,

      max_attachment_risk_score:
        maxScore,

      overall_status:
        overallStatus
    },

    attachments: processed
  };
}

module.exports = {
  analyzeAttachments
};