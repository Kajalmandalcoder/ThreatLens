const mongoose = require("mongoose");
const headerForensicsSchema = require("./header_forensics");

// ============================================================
// URL INTELLIGENCE RESULT SCHEMA
// ============================================================

const urlIntelligenceResultSchema = new mongoose.Schema(
  {
    url: String,
    status: String,
    error: String,
    hostname: String,
    registered_domain: String,
    risk_score: Number,
    risk_level: String,
    indicators: [String],

    components: {
      scheme: String,
      port: Number,
      path: String,
      query: String,
      fragment: String
    },

    features: {
      url_length: Number,
      is_http_only: Boolean,
      is_ip_hostname: Boolean,
      is_shortener: Boolean,
      subdomain_count: Number,
      has_excessive_subdomains: Boolean,
      is_unusually_long: Boolean,
      has_at_symbol: Boolean,
      has_hex_encoding: Boolean,
      has_suspicious_chars: Boolean,
      is_punycode: Boolean,
      matched_keywords: [String],
      is_sender_mismatch: Boolean
    },

    external_reputation: {
      provider: String,
      is_malicious: Boolean,
      note: String
    }
  },
  {
    _id: false
  }
);

// ============================================================
// URL INTELLIGENCE SCHEMA
// ============================================================

const urlIntelligenceSchema = new mongoose.Schema(
  {
    summary: {
      total_urls: { type: Number, default: 0 },
      critical_risk_urls: { type: Number, default: 0 },
      high_risk_urls: { type: Number, default: 0 },
      medium_risk_urls: { type: Number, default: 0 },
      low_risk_urls: { type: Number, default: 0 },
      max_risk_score: { type: Number, default: 0 },
      overall_status: { type: String, default: "LOW" }
    },

    urls: [urlIntelligenceResultSchema]
  },
  {
    _id: false
  }
);

// ============================================================
// EMAIL SCHEMA
// ============================================================

const emailSchema = new mongoose.Schema(
  {
    headers: {
      from: String,
      to: [String],
      cc: [String],
      bcc: [String],
      subject: String,
      date: String,
      messageId: String,
      replyTo: String,
      returnPath: String,
      received: [String]
    },

    body: {
      plainText: String,
      html: String
    },

    links: [
      {
        url: String,
        domain: String
      }
    ],

    attachments: [
      {
        filename: String,
        contentType: String,
        size: Number
      }
    ],

    // ========================================================
    // HEADER FORENSICS
    // ========================================================

    headerForensics: headerForensicsSchema,

    // ========================================================
    // ML THREAT ANALYSIS
    // ========================================================

    mlAnalysis: {
      success: Boolean,
      prediction: String,
      confidence: Number,
      raw_label: String
    },

    // ========================================================
    // URL INTELLIGENCE
    // ========================================================

    urlIntelligence: urlIntelligenceSchema,

    // ========================================================
    // ATTACHMENT INTELLIGENCE
    // ========================================================
    // ========================================================
    // ATTACHMENT INTELLIGENCE
    // ========================================================

    attachmentIntelligence: {
      summary: {
        total_attachments: { type: Number, default: 0 },
        has_high_risk_files: { type: Boolean, default: false },
        has_executable_types: { type: Boolean, default: false },
        has_macros_or_scripts: { type: Boolean, default: false },
        max_attachment_risk_score: { type: Number, default: 0 },
        overall_status: {
          type: String,
          default: "LOW"
        }
      },

      attachments: [
        {
          filename: String,
          contentType: String,
          size: Number,

          // NEW: detected extension
          extension: String,

          // NEW: actual file type vs declared MIME
          file_type_detection: {
            detected_type: String,
            detected_mime_type: String,
            declared_mime_type: String,
            extension_matches_content: Boolean
          },

          // Hashes
          hashes: {
            md5: String,
            sha256: String
          },

          // NEW: entropy analysis
          entropy_analysis: {
            entropy: Number,
            indicator: String
          },

          // Risk
          risk_score: Number,

          risk_level: String, // LOW | MEDIUM | HIGH | CRITICAL

          // Explainable indicators
          indicators: [String],

          // NEW: explainable risk factors
          risk_factors: [
            {
              reason: String,
              score: Number,
              value: mongoose.Schema.Types.Mixed,
              explanation: String
            }
          ],

          // Structural analysis
          structural_analysis: {
            is_executable: Boolean,
            is_archive: Boolean,
            has_macro: Boolean,
            has_embedded_javascript: Boolean,
            has_double_extension: Boolean,
            extension_mime_mismatch: Boolean,

            // NEW
            embedded_objects: Boolean,
            nested_archives: Boolean,
            suspicious_internal_files: [String]
          }
        }
      ]
    },

    // ========================================================
    // EMAIL JOURNEY
    // ========================================================

    emailJourney: {
      hops: [
        {
          hop_id: Number,
          from: String,
          by: String,
          ip: String,
          timestamp: String
        }
      ]
    },

    // ========================================================
    // DOMAIN & IP INTELLIGENCE
    // ========================================================

    domainIntelligence: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },

    ipIntelligence: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },

    intelligenceSignals: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },

    // ========================================================
    // AUTHENTICATION
    // ========================================================

    authentication: {
      spf: String,
      dkim: String,
      dmarc: String
    },

    // ========================================================
    // THREAT ANALYSIS
    // ========================================================

    threatAnalysis: {
      classification: String,
      riskScore: Number,
      reasons: [String]
    }
  },

  {
    timestamps: true
  }
);

module.exports = mongoose.model(
  "Email",
  emailSchema
);