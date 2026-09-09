const path = require("path");

const SIGNATURES = [
  {
    name: "PDF",
    extension: ".pdf",
    mime: "application/pdf",
    magic: Buffer.from("%PDF-")
  },
  {
    name: "PNG",
    extension: ".png",
    mime: "image/png",
    magic: Buffer.from([0x89, 0x50, 0x4e, 0x47])
  },
  {
    name: "JPEG",
    extension: ".jpg",
    mime: "image/jpeg",
    magic: Buffer.from([0xff, 0xd8, 0xff])
  },
  {
    name: "GIF",
    extension: ".gif",
    mime: "image/gif",
    magic: Buffer.from("GIF8")
  },
  {
    name: "ZIP",
    extension: ".zip",
    mime: "application/zip",
    magic: Buffer.from([0x50, 0x4b, 0x03, 0x04])
  },
  {
    name: "GZIP",
    extension: ".gz",
    mime: "application/gzip",
    magic: Buffer.from([0x1f, 0x8b])
  },
  {
    name: "RAR",
    extension: ".rar",
    mime: "application/vnd.rar",
    magic: Buffer.from("Rar!\x1a\x07")
  },
  {
    name: "7ZIP",
    extension: ".7z",
    mime: "application/x-7z-compressed",
    magic: Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
  },
  {
    name: "ELF",
    extension: "",
    mime: "application/x-executable",
    magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46])
  },
  {
    name: "DOS_EXECUTABLE",
    extension: ".exe",
    mime: "application/vnd.microsoft.portable-executable",
    magic: Buffer.from("MZ")
  },
  {
    name: "OLE",
    extension: "",
    mime: "application/x-ole-storage",
    magic: Buffer.from([
      0xd0, 0xcf, 0x11, 0xe0,
      0xa1, 0xb1, 0x1a, 0xe1
    ])
  }
];

const EXTENSION_MIME_MAP = {
  ".pdf": ["application/pdf"],
  ".png": ["image/png"],
  ".jpg": ["image/jpeg"],
  ".jpeg": ["image/jpeg"],
  ".gif": ["image/gif"],
  ".zip": ["application/zip"],
  ".gz": ["application/gzip"],
  ".rar": ["application/vnd.rar"],
  ".7z": ["application/x-7z-compressed"],

  ".doc": ["application/msword"],
  ".xls": ["application/vnd.ms-excel"],
  ".ppt": ["application/vnd.ms-powerpoint"],

  ".docx": [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  ],

  ".xlsx": [
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
  ],

  ".pptx": [
    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
  ],

  ".docm": [
    "application/vnd.ms-word.document.macroEnabled.12"
  ],

  ".xlsm": [
    "application/vnd.ms-excel.sheet.macroEnabled.12"
  ],

  ".pptm": [
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12"
  ],

  ".exe": [
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload"
  ],

  ".js": [
    "application/javascript",
    "text/javascript"
  ],

  ".vbs": [
    "text/vbscript"
  ]
};

function startsWithMagic(buffer, magic) {
  if (!Buffer.isBuffer(buffer)) return false;

  if (buffer.length < magic.length) return false;

  return buffer.subarray(0, magic.length).equals(magic);
}

function detectMagicBytes(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return {
      detected: false,
      file_type: null,
      mime: null,
      extension: null
    };
  }

  for (const signature of SIGNATURES) {
    if (startsWithMagic(buffer, signature.magic)) {
      return {
        detected: true,
        file_type: signature.name,
        mime: signature.mime,
        extension: signature.extension
      };
    }
  }

  return {
    detected: false,
    file_type: "UNKNOWN",
    mime: "application/octet-stream",
    extension: null
  };
}

function analyzeFileIdentity(filename, declaredMime, buffer) {
  const extension = path.extname(filename || "").toLowerCase();

  const magic = detectMagicBytes(buffer);

  const allowedMimes = EXTENSION_MIME_MAP[extension] || [];

  const extensionMimeMismatch =
    allowedMimes.length > 0 &&
    declaredMime &&
    !allowedMimes.includes(declaredMime);

  const magicMimeMismatch =
    magic.detected &&
    declaredMime &&
    magic.mime !== declaredMime &&
    !(
      extension === ".docx" ||
      extension === ".xlsx" ||
      extension === ".pptx"
    );

  const extensionMagicMismatch =
    magic.detected &&
    magic.extension &&
    extension &&
    magic.extension !== extension;

  return {
    extension,
    declared_mime: declaredMime || null,

    magic_byte_detection: magic,

    extension_mime_mismatch: Boolean(extensionMimeMismatch),

    magic_mime_mismatch: Boolean(magicMimeMismatch),

    extension_magic_mismatch: Boolean(extensionMagicMismatch),

    trusted_file_type:
      magic.detected
        ? magic.mime
        : declaredMime || "application/octet-stream"
  };
}

module.exports = {
  detectMagicBytes,
  analyzeFileIdentity
};