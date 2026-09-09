/**
 * ============================================================
 * ATTACHMENT VERDICT SERVICE
 * ============================================================
 *
 * Converts static attachment-analysis evidence into a unified
 * malware verdict.
 *
 * Verdicts:
 *   MALICIOUS
 *   SUSPICIOUS
 *   BENIGN
 *   UNKNOWN
 *
 * IMPORTANT:
 * Static indicators alone do not prove malware.
 * This engine therefore distinguishes:
 *
 *   - MALICIOUS  -> strong evidence of malicious behavior/content
 *   - SUSPICIOUS -> potentially dangerous characteristics
 *   - BENIGN     -> no meaningful suspicious indicators
 *   - UNKNOWN    -> insufficient evidence
 */

function addReason(reasons, evidence, reason, value) {
  reasons.push(reason);

  if (value !== undefined) {
    evidence.push({
      signal: reason,
      value
    });
  } else {
    evidence.push({
      signal: reason
    });
  }
}

function calculateAttachmentVerdict(attachment) {
  const reasons = [];
  const evidence = [];

  let score = Number(attachment?.risk_score || 0);

  const structural = attachment?.structural_analysis || {};
  const archive = attachment?.archive_analysis || {};
  const office = attachment?.office_analysis || {};
  const pdf = attachment?.pdf_analysis || {};
  const embeddedUrls = attachment?.embedded_url_analysis || {};

  // ============================================================
  // STRONG MALICIOUS EVIDENCE
  // ============================================================

  let strongMaliciousEvidence = false;

  /*
   * Internal executable files are dangerous, especially when
   * hidden inside an archive/document.
   */
  if (structural.has_internal_executables) {
    score += 40;

    addReason(
      reasons,
      evidence,
      "Archive contains internal executable files",
      true
    );
  }

  /*
   * VBA/macros are potentially dangerous active content.
   */
  if (office.has_vba) {
    score += 30;

    addReason(
      reasons,
      evidence,
      "Office document contains VBA macros",
      true
    );
  }

  /*
   * PDF JavaScript can be abused for exploitation.
   */
  if (pdf.has_javascript) {
    score += 35;

    addReason(
      reasons,
      evidence,
      "PDF contains JavaScript",
      true
    );
  }

  /*
   * Launch actions can cause external programs/files to execute.
   */
  if (pdf.has_launch_action) {
    score += 45;

    addReason(
      reasons,
      evidence,
      "PDF contains a Launch action",
      true
    );
  }

  /*
   * Embedded executable or suspicious objects.
   */
  if (office.has_embedded_objects) {
    score += 25;

    addReason(
      reasons,
      evidence,
      "Office document contains embedded objects",
      true
    );
  }

  // ============================================================
  // ARCHIVE THREATS
  // ============================================================

  if (
    Array.isArray(archive.dangerous_files) &&
    archive.dangerous_files.length > 0
  ) {
    score += 50;

    addReason(
      reasons,
      evidence,
      "Archive contains potentially dangerous files",
      archive.dangerous_files.length
    );
  }

  if (
    Array.isArray(archive.script_files) &&
    archive.script_files.length > 0
  ) {
    score += 30;

    addReason(
      reasons,
      evidence,
      "Archive contains script files",
      archive.script_files.length
    );
  }

  if (
    Array.isArray(archive.nested_archives) &&
    archive.nested_archives.length > 0
  ) {
    score += 15;

    addReason(
      reasons,
      evidence,
      "Archive contains nested archives",
      archive.nested_archives.length
    );
  }

  // ============================================================
  // FILE IDENTITY ANOMALIES
  // ============================================================

  if (structural.magic_mime_mismatch) {
    score += 35;

    addReason(
      reasons,
      evidence,
      "File magic bytes do not match declared MIME type",
      true
    );
  }

  if (structural.extension_magic_mismatch) {
    score += 40;

    addReason(
      reasons,
      evidence,
      "File extension does not match detected file type",
      true
    );
  }

  if (structural.extension_mime_mismatch) {
    score += 25;

    addReason(
      reasons,
      evidence,
      "File extension does not match declared MIME type",
      true
    );
  }

  if (structural.double_extension) {
    score += 25;

    addReason(
      reasons,
      evidence,
      "Attachment uses a suspicious double extension",
      true
    );
  }

  // ============================================================
  // INTERNAL SCRIPTS
  // ============================================================

  if (structural.has_internal_scripts) {
    score += 30;

    addReason(
      reasons,
      evidence,
      "Attachment contains internal script files",
      true
    );
  }

  // ============================================================
  // EMBEDDED URLs
  // ============================================================

  if (Number(embeddedUrls.total_urls || 0) > 0) {
    addReason(
      reasons,
      evidence,
      "Attachment contains embedded URLs",
      embeddedUrls.total_urls
    );
  }

  /*
   * Check whether the embedded URL analyzer found high-risk URLs.
   *
   * The exact URL object structure may evolve later, so we
   * support common risk_score/risk_level fields.
   */
  if (Array.isArray(embeddedUrls.urls)) {
    for (const url of embeddedUrls.urls) {
      const urlScore = Number(url?.risk_score || 0);

      if (urlScore >= 80) {
        score += 35;

        addReason(
          reasons,
          evidence,
          "Attachment contains a high-risk embedded URL",
          url?.url || null
        );
      } else if (urlScore >= 60) {
        score += 20;

        addReason(
          reasons,
          evidence,
          "Attachment contains a suspicious embedded URL",
          url?.url || null
        );
      }
    }
  }

  // ============================================================
  // CAP SCORE
  // ============================================================

  score = Math.min(100, Math.max(0, score));

  // ============================================================
  // DETERMINE VERDICT
  // ============================================================

  let verdict;
  let confidence;

  /*
   * Extremely strong structural evidence.
   *
   * We don't call something MALICIOUS merely because it is an
   * executable. The combination of multiple dangerous signals
   * is required.
   */
  const dangerousSignalCount = [
    structural.has_internal_executables,
    structural.has_internal_scripts,
    office.has_vba,
    office.has_embedded_objects,
    pdf.has_javascript,
    pdf.has_launch_action,
    structural.magic_mime_mismatch,
    structural.extension_magic_mismatch,
    structural.double_extension
  ].filter(Boolean).length;

  if (
    dangerousSignalCount >= 3 ||
    pdf.has_launch_action ||
    (
      structural.has_internal_executables &&
      structural.extension_magic_mismatch
    )
  ) {
    verdict = "MALICIOUS";
    confidence = Math.min(
      98,
      70 + dangerousSignalCount * 5
    );

    strongMaliciousEvidence = true;
  } else if (score >= 60 || dangerousSignalCount >= 1) {
    verdict = "SUSPICIOUS";
    confidence = Math.min(
      90,
      55 + Math.floor(score * 0.35)
    );
  } else if (score <= 20) {
    verdict = "BENIGN";
    confidence = 75;
  } else {
    verdict = "UNKNOWN";
    confidence = 50;
  }

  // ============================================================
  // FINAL RESULT
  // ============================================================

  return {
    verdict,
    confidence,
    score,
    strong_malicious_evidence: strongMaliciousEvidence,
    reasons,
    evidence
  };
}

module.exports = {
  calculateAttachmentVerdict
};