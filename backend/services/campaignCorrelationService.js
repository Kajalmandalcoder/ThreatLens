const Email = require("../models/email");

/**
 * Normalize URL for exact comparison.
 */
function normalizeUrl(url) {
  if (!url || typeof url !== "string") return null;

  try {
    const parsed = new URL(url.trim());

    return `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}${parsed.pathname.replace(/\/+$/, "")}${parsed.search}`;
  } catch {
    return url.trim().toLowerCase().replace(/\/+$/, "");
  }
}

/**
 * Normalize domain.
 */
function normalizeDomain(domain) {
  if (!domain || typeof domain !== "string") return null;

  return domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\.$/, "");
}

/**
 * Get all relevant domains from a case.
 */
function extractDomains(email) {
  const domains = new Set();

  const addDomain = (value) => {
    const normalized = normalizeDomain(value);
    if (normalized) domains.add(normalized);
  };

  const domainIntel = email.domainIntelligence;

  // Sender / Reply-To / Return-Path domains
  if (domainIntel?.sender_domain) {
    addDomain(domainIntel.sender_domain);
  }

  if (domainIntel?.reply_to_domain) {
    addDomain(domainIntel.reply_to_domain);
  }

  if (domainIntel?.return_path_domain) {
    addDomain(domainIntel.return_path_domain);
  }

  // Body / URL domains
  if (Array.isArray(email.links)) {
    email.links.forEach((link) => {
      if (typeof link === "string") {
        try {
          addDomain(new URL(link).hostname);
        } catch {}
      } else if (link?.domain) {
        addDomain(link.domain);
      } else if (link?.url) {
        try {
          addDomain(new URL(link.url).hostname);
        } catch {}
      }
    });
  }

  return domains;
}

/**
 * Extract observed IP addresses.
 */
function extractIPs(email) {
  const ips = new Set();

  const addIP = (ip) => {
    if (ip && typeof ip === "string") {
      ips.add(ip.trim());
    }
  };

  const networkHops = email.headerForensics?.network_hops;

  if (Array.isArray(networkHops?.all_extracted_ips)) {
    networkHops.all_extracted_ips.forEach(addIP);
  }

  if (networkHops?.origin_ip_candidate) {
    addIP(networkHops.origin_ip_candidate);
  }

  return ips;
}

/**
 * Extract normalized URLs.
 */
function extractURLs(email) {
  const urls = new Set();

  if (Array.isArray(email.links)) {
    email.links.forEach((link) => {
      const rawUrl =
        typeof link === "string"
          ? link
          : link?.url;

      const normalized = normalizeUrl(rawUrl);

      if (normalized) {
        urls.add(normalized);
      }
    });
  }

  if (Array.isArray(email.urlIntelligence?.urls)) {
    email.urlIntelligence.urls.forEach((item) => {
      const normalized = normalizeUrl(item?.url);

      if (normalized) {
        urls.add(normalized);
      }
    });
  }

  return urls;
}

/**
 * Extract attachment SHA-256 hashes.
 *
 * SHA-256 is preferred over filename because
 * identical filenames do not necessarily mean
 * identical files.
 */
function extractAttachmentHashes(email) {
  const hashes = new Set();

  const attachments =
    email.attachmentIntelligence?.attachments || [];

  attachments.forEach((attachment) => {
    const sha256 = attachment?.hashes?.sha256;

    if (sha256) {
      hashes.add(sha256.trim().toLowerCase());
    }
  });

  return hashes;
}

/**
 * Create a simplified authentication pattern.
 */
function getAuthenticationPattern(email) {
  const auth =
    email.headerForensics?.authentication_matrix ||
    email.authentication ||
    {};

  return [
    auth.spf || "",
    auth.dkim || "",
    auth.dmarc || ""
  ]
    .map((value) => String(value).trim().toLowerCase())
    .join("|");
}

/**
 * Create a simplified anomaly pattern.
 */
function getAnomalyPattern(email) {
  const anomalies =
    email.headerForensics?.identity_analysis?.anomalies || [];

  return anomalies
    .map((item) => item?.type)
    .filter(Boolean)
    .map((type) => String(type).trim().toLowerCase())
    .sort()
    .join("|");
}

/**
 * Create routing pattern.
 *
 * We intentionally don't compare exact IPs here because
 * IP correlation is already counted separately.
 */
function getRoutingPattern(email) {
  const hops =
    email.headerForensics?.network_hops?.hop_chain || [];

  if (!Array.isArray(hops) || hops.length === 0) {
    return "";
  }

  return hops
    .map((hop) => {
      const from = hop?.raw_received || "";

      return String(from)
        .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "<IP>")
        .replace(/\s+/g, " ")
        .trim()
        .toLowerCase();
    })
    .join(" -> ");
}

/**
 * Header Forensics correlation.
 *
 * Header Match = 1 point when:
 * - routing pattern matches
 * OR
 * - authentication pattern + anomaly pattern match
 *
 * Header correlation contributes MAXIMUM 1 point.
 */
function checkHeaderMatch(currentEmail, otherEmail) {
  const currentRouting = getRoutingPattern(currentEmail);
  const otherRouting = getRoutingPattern(otherEmail);

  if (
    currentRouting &&
    otherRouting &&
    currentRouting === otherRouting
  ) {
    return {
      matched: true,
      evidence: "Matching routing pattern"
    };
  }

  const currentAuth = getAuthenticationPattern(currentEmail);
  const otherAuth = getAuthenticationPattern(otherEmail);

  const currentAnomaly = getAnomalyPattern(currentEmail);
  const otherAnomaly = getAnomalyPattern(otherEmail);

  if (
    currentAuth &&
    otherAuth &&
    currentAuth === otherAuth &&
    currentAnomaly &&
    otherAnomaly &&
    currentAnomaly === otherAnomaly
  ) {
    return {
      matched: true,
      evidence: "Matching authentication and header anomaly pattern"
    };
  }

  return {
    matched: false,
    evidence: null
  };
}

/**
 * Calculate correlation strength.
 */
function getCorrelationStrength(matchCount) {
  if (matchCount >= 4) return "STRONG";
  if (matchCount === 3) return "MEDIUM";
  if (matchCount >= 1) return "WEAK";

  return "NONE";
}

/**
 * Find common values between two Sets.
 */
function getIntersection(setA, setB) {
  return [...setA].filter((value) => setB.has(value));
}

/**
 * Compare current case against another case.
 */
function compareCases(currentEmail, otherEmail) {
  const currentIPs = extractIPs(currentEmail);
  const otherIPs = extractIPs(otherEmail);

  const currentDomains = extractDomains(currentEmail);
  const otherDomains = extractDomains(otherEmail);

  const currentURLs = extractURLs(currentEmail);
  const otherURLs = extractURLs(otherEmail);

  const currentAttachments =
    extractAttachmentHashes(currentEmail);

  const otherAttachments =
    extractAttachmentHashes(otherEmail);

  const commonIPs = getIntersection(
    currentIPs,
    otherIPs
  );

  const commonDomains = getIntersection(
    currentDomains,
    otherDomains
  );

  const commonURLs = getIntersection(
    currentURLs,
    otherURLs
  );

  const commonAttachments = getIntersection(
    currentAttachments,
    otherAttachments
  );

  const headerResult = checkHeaderMatch(
    currentEmail,
    otherEmail
  );

  const matches = {
    ip: commonIPs,
    domain: commonDomains,
    url: commonURLs,
    header: headerResult.matched
      ? [headerResult.evidence]
      : [],
    attachment: commonAttachments
  };

  const ipMatch = commonIPs.length > 0;
  const domainMatch = commonDomains.length > 0;
  const urlMatch = commonURLs.length > 0;
  const headerMatch = headerResult.matched;
  const attachmentMatch = commonAttachments.length > 0;

  const matchCount = [
    ipMatch,
    domainMatch,
    urlMatch,
    headerMatch,
    attachmentMatch
  ].filter(Boolean).length;

  if (matchCount === 0) {
    return null;
  }

  return {
    caseId: otherEmail.caseId,
    emailId: otherEmail._id.toString(),

    subject: otherEmail.headers?.subject || "",
    sender: otherEmail.headers?.from || "",

    classification:
      otherEmail.threatAnalysis?.classification ||
      otherEmail.mlAnalysis?.prediction ||
      null,

    riskScore:
      otherEmail.threatAnalysis?.riskScore ??
      null,

    matchCount,

    strength: getCorrelationStrength(matchCount),

    matches: {
      ip: commonIPs,
      domain: commonDomains,
      url: commonURLs,
      header: headerResult.matched
        ? [headerResult.evidence]
        : [],
      attachment: commonAttachments
    }
  };
}

/**
 * Main campaign correlation function.
 */
async function findRelatedCases(caseId) {
  const currentEmail = await Email.findOne({ caseId });

  if (!currentEmail) {
    throw new Error("Current case not found");
  }

  // Don't compare the case with itself.
  const otherEmails = await Email.find({
    caseId: { $ne: caseId }
  }).lean();

  const relatedCases = [];

  for (const otherEmail of otherEmails) {
    const correlation = compareCases(
      currentEmail,
      otherEmail
    );

    if (correlation) {
      relatedCases.push(correlation);
    }
  }

  // Strongest / highest match first.
  relatedCases.sort((a, b) => {
    if (b.matchCount !== a.matchCount) {
      return b.matchCount - a.matchCount;
    }

    return a.caseId.localeCompare(b.caseId);
  });

  return {
    currentCase: {
      caseId: currentEmail.caseId,
      emailId: currentEmail._id.toString(),
      subject: currentEmail.headers?.subject || "",
      sender: currentEmail.headers?.from || ""
    },

    totalRelatedCases: relatedCases.length,

    relatedCases
  };
}

module.exports = {
  findRelatedCases
};