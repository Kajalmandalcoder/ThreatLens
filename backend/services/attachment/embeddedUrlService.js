const IGNORE_DOMAINS = [
  "schemas.openxmlformats.org",
  "schemas.microsoft.com",
  "www.w3.org",
  "purl.org"
];

function shouldIgnoreUrl(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    
    return IGNORE_DOMAINS.some(
      (domain) => hostname === domain || hostname.endsWith("." + domain)
    );
  } catch {
    return true;
  }
}

function normalizeUrl(url) {
  try {
    const parsed = new URL(url.trim());

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      return null;
    }

    return parsed.href;
  } catch {
    return null;
  }
}

function analyzeEmbeddedUrls(urls = []) {
  const normalized = [...new Set(
    urls
      .map(normalizeUrl)
      .filter(Boolean)
  )];

  // 1. ADDED: Filter out benign schema and namespace URLs
  const filteredUrls = normalized.filter((url) => !shouldIgnoreUrl(url));

  const results = filteredUrls.map(url => {
    let parsed;

    try {
      parsed = new URL(url);
    } catch {
      return null;
    }

    const hostname = parsed.hostname;
    const indicators = [];

    if (parsed.protocol === "http:") {
      indicators.push("HTTP URL");
    }

    if (hostname && /^[0-9.]+$/.test(hostname)) {
      indicators.push("IP address used as hostname");
    }

    if (hostname && hostname.includes("xn--")) {
      indicators.push("Punycode hostname");
    }

    if (url.length > 200) {
      indicators.push("Unusually long URL");
    }

    return {
      url,
      hostname,
      source: "attachment",
      indicators
    };
  }).filter(Boolean);

  return {
    total_urls: results.length,
    urls: results
  };
}

module.exports = {
  analyzeEmbeddedUrls
};