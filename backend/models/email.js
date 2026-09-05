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

    caseId: {
        type: String,
        unique: true,
        index: true
    },

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

    attachmentIntelligence: {
      summary: {
        total_attachments: { type: Number, default: 0 },
        has_high_risk_files: { type: Boolean, default: false },
        has_executable_types: { type: Boolean, default: false },
        has_macros_or_scripts: { type: Boolean, default: false },
        max_attachment_risk_score: { type: Number, default: 0 },
        overall_status: { type: String, default: "LOW" } // LOW | MEDIUM | HIGH | CRITICAL
      },
      attachments: [
        {
          filename: String,
          contentType: String,
          size: Number,
          hashes: {
            md5: String,
            sha256: String
          },
          risk_score: Number,
          risk_level: String, // LOW | MEDIUM | HIGH | CRITICAL
          indicators: [String],
          structural_analysis: {
            is_executable: Boolean,
            is_archive: Boolean,
            has_macro: Boolean,
            has_embedded_javascript: Boolean,
            has_double_extension: Boolean,
            extension_mime_mismatch: Boolean
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