const JSZip = require("jszip");

const MAX_RECURSION_DEPTH = 3;
const MAX_FILES_PER_ARCHIVE = 500;
const MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024;

const DANGEROUS_EXTENSIONS = new Set([
  ".exe",
  ".dll",
  ".scr",
  ".com",
  ".pif",
  ".cpl",
  ".msi",
  ".jar",
  ".js",
  ".jse",
  ".vbs",
  ".vbe",
  ".wsf",
  ".wsh",
  ".bat",
  ".cmd",
  ".ps1",
  ".psm1",
  ".hta",
  ".lnk",
  ".reg",
  ".iso",
  ".img"
]);

const SCRIPT_EXTENSIONS = new Set([
  ".js",
  ".jse",
  ".vbs",
  ".vbe",
  ".wsf",
  ".wsh",
  ".bat",
  ".cmd",
  ".ps1",
  ".psm1",
  ".hta"
]);

const ARCHIVE_EXTENSIONS = new Set([
  ".zip",
  ".rar",
  ".7z",
  ".tar",
  ".gz",
  ".bz2",
  ".xz"
]);

function getExtension(filename) {
  const clean = String(filename || "")
    .split(/[\\/]/)
    .pop();

  const index = clean.lastIndexOf(".");

  if (index === -1) {
    return "";
  }

  return clean
    .slice(index)
    .toLowerCase();
}

function isDangerousFile(filename) {
  return DANGEROUS_EXTENSIONS.has(
    getExtension(filename)
  );
}

function isScriptFile(filename) {
  return SCRIPT_EXTENSIONS.has(
    getExtension(filename)
  );
}

function isArchiveFile(filename) {
  return ARCHIVE_EXTENSIONS.has(
    getExtension(filename)
  );
}

function suspiciousFilename(filename) {
  const name = String(filename || "").toLowerCase();

  const suspiciousPatterns = [
    /\.pdf\.(exe|scr|js|vbs|lnk)$/i,
    /\.docx\.(exe|scr|js|vbs|lnk)$/i,
    /\.xlsx\.(exe|scr|js|vbs|lnk)$/i,
    /\.jpg\.(exe|scr|js|vbs|lnk)$/i,
    /\.png\.(exe|scr|js|vbs|lnk)$/i,
    /invoice.*\.(exe|scr|js|vbs|lnk)$/i,
    /payment.*\.(exe|scr|js|vbs|lnk)$/i,
    /document.*\.(exe|scr|js|vbs|lnk)$/i,
    /urgent.*\.(exe|scr|js|vbs|lnk)$/i
  ];

  return suspiciousPatterns.some(
    pattern => pattern.test(name)
  );
}

async function inspectZipBuffer(
  buffer,
  depth = 0,
  parentPath = ""
) {
  const result = {
    is_archive: false,
    archive_type: "ZIP",
    recursion_depth: depth,
    file_count: 0,
    total_uncompressed_size: 0,

    dangerous_files: [],
    script_files: [],
    suspicious_files: [],
    nested_archives: [],

    files: [],

    limits: {
      max_depth_reached: false,
      max_files_reached: false,
      max_size_reached: false
    },

    errors: []
  };

  if (!Buffer.isBuffer(buffer)) {
    result.errors.push(
      "Invalid archive buffer"
    );

    return result;
  }

  if (depth > MAX_RECURSION_DEPTH) {
    result.limits.max_depth_reached = true;

    return result;
  }

//   let zip;

//   try {
//     zip = await JSZip.loadAsync(buffer, {
//       checkCRC32: false,
//       createFolders: false
//     });
//   } catch (error) {
//     result.errors.push(
//       `ZIP parsing failed: ${error.message}`
//     );

//     return result;
//   }
// Only attempt ZIP parsing when the buffer has a ZIP signature.
// This prevents normal TXT/PDF/JPG/etc. files from producing
// misleading ZIP parsing errors.

const isZipSignature =
  buffer.length >= 4 &&
  (
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    (
      (buffer[2] === 0x03 && buffer[3] === 0x04) ||
      (buffer[2] === 0x05 && buffer[3] === 0x06) ||
      (buffer[2] === 0x07 && buffer[3] === 0x08)
    )
  );

if (!isZipSignature) {
  result.archive_type = null;
  return result;
}

let zip;

try {
  zip = await JSZip.loadAsync(buffer, {
    checkCRC32: false,
    createFolders: false
  });
} catch (error) {
  result.errors.push(
    `ZIP parsing failed: ${error.message}`
  );
  return result;
}


  result.is_archive = true;

  const entries = Object.values(zip.files);

  for (const entry of entries) {
    if (result.file_count >= MAX_FILES_PER_ARCHIVE) {
      result.limits.max_files_reached = true;
      break;
    }

    const filename = entry.name;

    if (entry.dir) {
      continue;
    }

    result.file_count++;

    const extension =
      getExtension(filename);

    let size = 0;
    let fileBuffer = null;

    try {
      fileBuffer =
        await entry.async("nodebuffer");

      size = fileBuffer.length;
    } catch (error) {
      result.errors.push(
        `Could not read ${filename}: ${error.message}`
      );

      continue;
    }

    result.total_uncompressed_size += size;

    if (
      result.total_uncompressed_size >
      MAX_TOTAL_UNCOMPRESSED_BYTES
    ) {
      result.limits.max_size_reached = true;
      break;
    }

    const fullPath = parentPath
      ? `${parentPath}/${filename}`
      : filename;

    const fileInfo = {
      path: fullPath,
      filename,
      extension,
      size
    };

    result.files.push(fileInfo);

    if (isDangerousFile(filename)) {
      result.dangerous_files.push({
        path: fullPath,
        filename,
        extension,
        size
      });
    }

    if (isScriptFile(filename)) {
      result.script_files.push({
        path: fullPath,
        filename,
        extension,
        size
      });
    }

    if (suspiciousFilename(filename)) {
      result.suspicious_files.push({
        path: fullPath,
        filename,
        reason: "Suspicious filename pattern"
      });
    }

    if (isArchiveFile(filename)) {
      result.nested_archives.push({
        path: fullPath,
        filename,
        extension,
        depth: depth + 1
      });

      if (
        depth < MAX_RECURSION_DEPTH
      ) {
        const nested =
          await inspectZipBuffer(
            fileBuffer,
            depth + 1,
            fullPath
          );

        result.dangerous_files.push(
          ...nested.dangerous_files
        );

        result.script_files.push(
          ...nested.script_files
        );

        result.suspicious_files.push(
          ...nested.suspicious_files
        );

        result.nested_archives.push(
          ...nested.nested_archives
        );

        result.files.push(
          ...nested.files
        );

        result.total_uncompressed_size +=
          nested.total_uncompressed_size;

        if (
          nested.limits.max_depth_reached
        ) {
          result.limits.max_depth_reached =
            true;
        }

        if (
          nested.limits.max_files_reached
        ) {
          result.limits.max_files_reached =
            true;
        }

        if (
          nested.limits.max_size_reached
        ) {
          result.limits.max_size_reached =
            true;
        }
      } else {
        result.limits.max_depth_reached =
          true;
      }
    }
  }

  return result;
}

module.exports = {
  inspectZipBuffer,
  getExtension,
  isDangerousFile,
  isScriptFile,
  isArchiveFile
};