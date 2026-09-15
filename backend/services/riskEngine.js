const RISK_WEIGHTS = {
    ml: 0.20,
    header: 0.15,
    ip: 0.15,
    domain: 0.10,
    url: 0.15,
    attachment: 0.10,
    image: 0.15
};

function normalizeScore(value) {
    const score = Number(value);

    if (Number.isNaN(score)) {
        return 0;
    }

    return Math.max(0, Math.min(100, score));
}

function calculateFinalRiskScore({
    mlScore = 0,
    headerScore = 0,
    ipScore = 0,
    domainScore = 0,
    urlScore = 0,
    attachmentScore = 0,
    imageScore = 0
}) {

    const finalScore =
        (normalizeScore(mlScore) * RISK_WEIGHTS.ml) +
        (normalizeScore(headerScore) * RISK_WEIGHTS.header) +
        (normalizeScore(ipScore) * RISK_WEIGHTS.ip) +
        (normalizeScore(domainScore) * RISK_WEIGHTS.domain) +
        (normalizeScore(urlScore) * RISK_WEIGHTS.url) +
        (normalizeScore(attachmentScore) * RISK_WEIGHTS.attachment) +
        (normalizeScore(imageScore) * RISK_WEIGHTS.image);

    return Math.round(
        Math.max(0, Math.min(100, finalScore))
    );
}

function getRiskLevel(score) {

    if (score < 30) {
        return "LOW";
    }

    if (score < 60) {
        return "MEDIUM";
    }

    return "HIGH";
}

function getClassification(score) {

    if (score >= 60) {
        return "PHISHING";
    }

    if (score >= 30) {
        return "SUSPICIOUS";
    }

    return "LEGITIMATE";
}

function calculateRiskAssessment(scores = {}) {

    const moduleScores = {
        ml: normalizeScore(scores.mlScore),
        header: normalizeScore(scores.headerScore),
        ip: normalizeScore(scores.ipScore),
        domain: normalizeScore(scores.domainScore),
        url: normalizeScore(scores.urlScore),
        attachment: normalizeScore(scores.attachmentScore),
        image: normalizeScore(scores.imageScore)
    };

    const finalRiskScore = calculateFinalRiskScore({
        mlScore: moduleScores.ml,
        headerScore: moduleScores.header,
        ipScore: moduleScores.ip,
        domainScore: moduleScores.domain,
        urlScore: moduleScores.url,
        attachmentScore: moduleScores.attachment,
        imageScore: moduleScores.image
    });

    return {
        finalRiskScore,

        riskLevel: getRiskLevel(finalRiskScore),

        classification: getClassification(finalRiskScore),

        scoreComposition: moduleScores,

        weights: RISK_WEIGHTS
    };
}

module.exports = {
    calculateFinalRiskScore,
    calculateRiskAssessment,
    getRiskLevel,
    getClassification,
    RISK_WEIGHTS
};