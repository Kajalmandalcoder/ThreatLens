const mongoose = require("mongoose");

const anomalySchema = new mongoose.Schema(
  {
    type: String,
    severity: String,
    details: String
  },
  { _id: false }
);

const hopSchema = new mongoose.Schema(
  {
    hop_id: Number,
    raw_received: String,
    extracted_public_ips: [String]
  },
  { _id: false }
);

const headerForensicsSchema = new mongoose.Schema(
  {
    module: {
      type: String,
      default: "B. HEADER FORENSICS"
    },

    owner: {
      type: String,
      default: "Akankcha"
    },

    header_risk_score: {
      type: Number,
      default: 0
    },

    identity_analysis: {
      from_domain: String,
      reply_to_domain: String,
      return_path_domain: String,

      is_spoofed: {
        type: Boolean,
        default: false
      },

      anomalies: [anomalySchema]
    },

    authentication_matrix: {
      spf: String,
      dkim: String,
      dmarc: String,
      raw_auth_header: String
    },

    live_dns_verification: {
      spf_record: {
        type: Boolean,
        default: false
      },

      dmarc_record: {
        type: Boolean,
        default: false
      }
    },

    network_hops: {
      total_hops: {
        type: Number,
        default: 0
      },

      hop_chain: [hopSchema],

      all_extracted_ips: [String],

      origin_ip_candidate: String
    },

    header_findings_summary: String,

    error: String
  },
  {
    _id: false
  }
);

module.exports = headerForensicsSchema;