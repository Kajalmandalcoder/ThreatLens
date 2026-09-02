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
      returnPath: String
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