const Email = require("../../models/email");

/**
 * Find previous ThreatLens cases containing the same
 * attachment SHA-256 hash.
 *
 * The search is restricted to the current user's cases
 * for privacy.
 */
async function findPreviousAttachmentCases({
  sha256,
  currentCaseId = null,
  userId = null
}) {
  if (!sha256) {
    return [];
  }

  const query = {
    "attachmentIntelligence.attachments.hashes.sha256": sha256
  };

  // Keep correlation within the current user's cases.
  if (userId) {
    query.userId = userId;
  }

  // Don't return the case currently being analyzed.
  if (currentCaseId) {
    query.caseId = { $ne: currentCaseId };
  }

  const cases = await Email.find(query)
    .select(
      "caseId userId createdAt attachmentIntelligence.attachments"
    )
    .sort({ createdAt: -1 })
    .limit(20)
    .lean();

  const results = [];

  for (const email of cases) {
    const attachments =
      email.attachmentIntelligence?.attachments || [];

    for (const attachment of attachments) {
      if (attachment.hashes?.sha256 === sha256) {
        results.push({
          caseId: email.caseId,
          filename: attachment.filename || null,
          first_seen: email.createdAt || null,
          risk_score: attachment.risk_score ?? null,
          risk_level: attachment.risk_level || null
        });
      }
    }
  }

  return results;
}

module.exports = {
  findPreviousAttachmentCases
};