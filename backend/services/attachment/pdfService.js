function analyzePdf(buffer) {
  const result = {
    is_pdf: false,

    has_javascript: false,

    has_embedded_files: false,

    has_launch_action: false,

    has_open_action: false,

    has_uri_actions: false,

    urls: [],

    indicators: []
  };

  if (!Buffer.isBuffer(buffer)) {
    return result;
  }

  const header =
    buffer
      .subarray(0, 1024)
      .toString(
        "latin1"
      );

  if (!header.startsWith("%PDF-")) {
    return result;
  }

  result.is_pdf = true;

  // PDF JavaScript indicators
  if (
    /\/JavaScript\b/i.test(
      buffer.toString("latin1")
    ) ||
    /\/JS\b/i.test(
      buffer.toString("latin1")
    )
  ) {
    result.has_javascript = true;

    result.indicators.push(
      "PDF contains JavaScript-related objects"
    );
  }

  // Embedded files
  if (
    /\/EmbeddedFile\b/i.test(
      buffer.toString("latin1")
    ) ||
    /\/Filespec\b/i.test(
      buffer.toString("latin1")
    )
  ) {
    result.has_embedded_files = true;

    result.indicators.push(
      "PDF contains embedded-file indicators"
    );
  }

  // Launch action
  if (
    /\/Launch\b/i.test(
      buffer.toString("latin1")
    )
  ) {
    result.has_launch_action = true;

    result.indicators.push(
      "PDF contains a Launch action"
    );
  }

  // OpenAction
  if (
    /\/OpenAction\b/i.test(
      buffer.toString("latin1")
    )
  ) {
    result.has_open_action = true;

    result.indicators.push(
      "PDF contains an OpenAction"
    );
  }

  // URI actions
  if (
    /\/URI\b/i.test(
      buffer.toString("latin1")
    )
  ) {
    result.has_uri_actions = true;

    result.indicators.push(
      "PDF contains URI actions"
    );
  }

  // URL extraction
  const text =
    buffer.toString(
      "latin1"
    );

  const urls =
    text.match(
      /https?:\/\/[^\s<>()"'\\]+/gi
    ) || [];

  result.urls =
    [...new Set(urls)];

  return result;
}

module.exports = {
  analyzePdf
};