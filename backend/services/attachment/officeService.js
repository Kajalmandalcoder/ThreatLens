const JSZip = require("jszip");

const OFFICE_EXTENSIONS = new Set([
  ".docx",
  ".docm",
  ".dotx",
  ".dotm",
  ".xlsx",
  ".xlsm",
  ".xltx",
  ".xltm",
  ".pptx",
  ".pptm",
  ".potx",
  ".potm"
]);

function getExtension(filename) {
  const value =
    String(filename || "")
      .toLowerCase();

  const index =
    value.lastIndexOf(".");

  return index === -1
    ? ""
    : value.slice(index);
}

function isOfficeDocument(filename) {
  return OFFICE_EXTENSIONS.has(
    getExtension(filename)
  );
}

function includesAny(
  filenames,
  patterns
) {
  return filenames.some(filename =>
    patterns.some(pattern =>
      filename
        .toLowerCase()
        .includes(pattern)
    )
  );
}

async function analyzeOfficeDocument(
  buffer,
  filename
) {
  const result = {
    is_office_document:
      isOfficeDocument(filename),

    office_type:
      getExtension(filename),

    is_ooxml_container: false,

    has_vba: false,

    has_embedded_objects: false,

    has_external_relationships: false,

    embedded_files: [],

    relationship_files: [],

    suspicious_parts: [],

    internal_urls: [],

    errors: []
  };

  if (
    !result.is_office_document
  ) {
    return result;
  }

  if (!Buffer.isBuffer(buffer)) {
    result.errors.push(
      "Invalid Office document buffer"
    );

    return result;
  }

  let zip;

  try {
    zip = await JSZip.loadAsync(
      buffer,
      {
        checkCRC32: false,
        createFolders: false
      }
    );
  } catch (error) {
    result.errors.push(
      `Office container parsing failed: ${error.message}`
    );

    return result;
  }

  result.is_ooxml_container = true;

  const filenames =
    Object.values(zip.files)
      .filter(entry => !entry.dir)
      .map(entry => entry.name);

  // ================================
  // VBA / MACROS
  // ================================

  const vbaFiles =
    filenames.filter(name =>
      name.toLowerCase()
        .includes("vbaproject.bin")
    );

  if (vbaFiles.length > 0) {
    result.has_vba = true;
  }

  // ================================
  // EMBEDDED OBJECTS
  // ================================

  result.embedded_files =
    filenames.filter(name =>
      /(^|\/)embeddings\//i.test(name)
    );

  result.has_embedded_objects =
    result.embedded_files.length > 0;

  // ================================
  // RELATIONSHIPS
  // ================================

  result.relationship_files =
    filenames.filter(name =>
      /(^|\/)_rels\/.*\.rels$/i.test(name)
    );

  for (const relationshipFile of
    result.relationship_files) {

    try {
      const content =
        await zip.files[
          relationshipFile
        ].async("text");

      if (
        /TargetMode\s*=\s*["']External["']/i
          .test(content)
      ) {
        result.has_external_relationships =
          true;
      }

      const urls =
        content.match(
          /https?:\/\/[^\s"'<>]+/gi
        ) || [];

      result.internal_urls.push(
        ...urls
      );
    } catch (error) {
      result.errors.push(
        `Could not inspect ${relationshipFile}`
      );
    }
  }

  // ================================
  // SUSPICIOUS PARTS
  // ================================

  const suspiciousPatterns = [
    "vbaproject.bin",
    "activex",
    "oleobject",
    "embeddings/",
    "externalLinks/",
    "customUI"
  ];

  result.suspicious_parts =
    filenames.filter(name =>
      suspiciousPatterns.some(
        pattern =>
          name.toLowerCase()
            .includes(pattern.toLowerCase())
      )
    );

  // ================================
  // SCAN XML FOR URLS
  // ================================

  for (const filenameEntry of
    filenames) {

    if (
      !filenameEntry.endsWith(".xml")
    ) {
      continue;
    }

    try {
      const content =
        await zip.files[
          filenameEntry
        ].async("text");

      const urls =
        content.match(
          /https?:\/\/[^\s"'<>]+/gi
        ) || [];

      result.internal_urls.push(
        ...urls
      );
    } catch {
      // Ignore individual unreadable XML parts.
    }
  }

  result.internal_urls =
    [...new Set(
      result.internal_urls
    )];

  return result;
}

module.exports = {
  analyzeOfficeDocument,
  isOfficeDocument
};