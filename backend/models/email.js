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

    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
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
        senderIdentity: {
        displayName: String,
        email: String,
        domain: String,
        mismatch: Boolean,
        reason: String
    },

    body: {
      plainText: String,
      html: String
    },
    bodyStructure: {
    hasPlainText: Boolean,
    hasHtml: Boolean,
    plainTextLength: Number,
    htmlLength: Number,
    linkCount: Number,
    externalLinkCount: Number,
    imageCount: Number,
    formCount: Number,
    buttonCount: Number,
    hiddenElementCount: Number,
    scriptCount: Number,
    iframeCount: Number
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
  raw_label: String,
  threatScore: Number,
  riskLevel: String,
  technicalReasons: [String],
  recommendedActions: [String]
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
            sha1: String,
            sha256: String
          },
          file_identity: mongoose.Schema.Types.Mixed,

          entropy: mongoose.Schema.Types.Mixed,


          risk_score: Number,
          risk_level: String,
          indicators: [String],

          structural_analysis: {
            has_executable: Boolean,
            has_archive: Boolean,
            has_macro: Boolean,
            has_embedded_javascript: Boolean,
            double_extension: Boolean,
            extension_mime_mismatch: Boolean,

            has_embedded_objects: Boolean,
            has_nested_archives: Boolean,
            has_internal_executables: Boolean,
            has_internal_scripts: Boolean,
            magic_mime_mismatch: Boolean,
            extension_magic_mismatch: Boolean
          },

          archive_analysis: {
            is_archive: Boolean,
            archive_type: String,
            recursion_depth: Number,
            file_count: Number,
            total_uncompressed_size: Number,

            dangerous_files: [mongoose.Schema.Types.Mixed],
            script_files: [mongoose.Schema.Types.Mixed],
            suspicious_files: [mongoose.Schema.Types.Mixed],
            nested_archives: [mongoose.Schema.Types.Mixed],

            files: [mongoose.Schema.Types.Mixed],

            limits: mongoose.Schema.Types.Mixed,
            errors: [String]
          },

          office_analysis: {
            is_office_document: Boolean,
            office_type: String,
            is_ooxml_container: Boolean,
            has_vba: Boolean,
            has_embedded_objects: Boolean,
            has_external_relationships: Boolean,
            embedded_files: [String],
            relationship_files: [String],
            suspicious_parts: [String],
            internal_urls: [String],
            errors: [String]
          },

          pdf_analysis: {
            is_pdf: Boolean,
            has_javascript: Boolean,
            has_embedded_files: Boolean,
            has_launch_action: Boolean,
            has_open_action: Boolean,
            has_uri_actions: Boolean,
            urls: [String],
            indicators: [String]
          },

          embedded_url_analysis: {
            total_urls: Number,
            urls: [mongoose.Schema.Types.Mixed]
          },
          embedded_url_intelligence: {
            type: mongoose.Schema.Types.Mixed,
            default: null
          },
          previous_cases: [mongoose.Schema.Types.Mixed],
          malware_verdict: {
            verdict: String,
            confidence: Number,
            score: Number,
            strong_malicious_evidence: Boolean,
            reasons: [String],
            evidence: [mongoose.Schema.Types.Mixed]
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