const mongoose = require("mongoose");
const headerForensicsSchema = require("./header_forensics");

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

    // ==============================
    // HEADER FORENSICS - AKANKCHA
    // ==============================
    headerForensics: headerForensicsSchema,

    // ==============================
    // ML THREAT ANALYSIS - KAJAL
    // ==============================
    mlAnalysis: {
      success: Boolean,
      prediction: String,
      confidence: Number,
      raw_label: String
    },

    // ==============================
    // URL INTELLIGENCE - HIMANSHI
    // ==============================
    urlIntelligence: {
      summary: {
        total_urls: { type: Number, default: 0 },
        critical_risk_urls: { type: Number, default: 0 },
        high_risk_urls: { type: Number, default: 0 },
        medium_risk_urls: { type: Number, default: 0 },
        low_risk_urls: { type: Number, default: 0 },
        max_risk_score: { type: Number, default: 0 },
        overall_status: { type: String, default: "LOW" }
      },
      urls: [
        {
          url: String,
          status: String,
          hostname: String,
          registered_domain: String,
          risk_score: Number,
          risk_level: String,
          indicators: [String],
          components: {
            scheme: String,
            port: mongoose.Schema.Types.Mixed,
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
            provider: mongoose.Schema.Types.Mixed,
            is_malicious: mongoose.Schema.Types.Mixed,
            note: String
          }
        }
      ]
    },

    // ==============================
    // DOMAIN & IP INTELLIGENCE
    // ==============================
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

    authentication: {
      spf: String,
      dkim: String,
      dmarc: String
    },

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

module.exports = mongoose.model("Email", emailSchema);