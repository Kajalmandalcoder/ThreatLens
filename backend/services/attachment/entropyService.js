function calculateEntropy(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
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

  return Number(entropy.toFixed(4));
}

function classifyEntropy(entropy) {
  if (entropy >= 7.5) {
    return "VERY_HIGH";
  }

  if (entropy >= 7.0) {
    return "HIGH";
  }

  if (entropy >= 5.0) {
    return "NORMAL";
  }

  return "LOW";
}

function analyzeEntropy(buffer) {
  const value = calculateEntropy(buffer);

  return {
    value,
    level: classifyEntropy(value),
    interpretation:
      value >= 7.5
        ? "Very high entropy; file may be compressed, encrypted, packed, or obfuscated."
        : value >= 7.0
        ? "High entropy detected."
        : "No unusually high entropy detected."
  };
}

module.exports = {
  calculateEntropy,
  classifyEntropy,
  analyzeEntropy
};