const crypto = require("crypto");

function calculateHashes(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return {
      md5: null,
      sha1: null,
      sha256: null
    };
  }

  return {
    md5: crypto
      .createHash("md5")
      .update(buffer)
      .digest("hex"),

    sha1: crypto
      .createHash("sha1")
      .update(buffer)
      .digest("hex"),

    sha256: crypto
      .createHash("sha256")
      .update(buffer)
      .digest("hex")
  };
}

module.exports = {
  calculateHashes
};