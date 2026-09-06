const Email = require("../models/email");

/*
========================================================
CAMPAIGN CORRELATION SERVICE

Purpose:
- MongoDB se emails fetch karna
- Current/latest email ke saath related emails find karna
- Sender, domain, URL, IP, attachment hash aur subject
  ke basis par correlation banana
- Campaign Journey ke liye timeline + evidence return karna

IMPORTANT:
- No hardcoded cases
- No hardcoded dates
- No fake correlation score
- Data MongoDB se aayega
========================================================
*/


/* ======================================================
   HELPERS
====================================================== */

function normalize(value) {
    if (!value) return "";

    return String(value)
        .trim()
        .toLowerCase();
}


function extractEmailAddress(value) {
    if (!value) return "";

    const match = String(value).match(
        /<([^>]+)>/
    );

    return normalize(
        match ? match[1] : value
    );
}


function extractDomain(value) {
    const email = extractEmailAddress(value);

    if (!email.includes("@")) return "";

    return email.split("@")[1];
}


function getSender(email) {
    return extractEmailAddress(
        email?.headers?.from
    );
}


function getSenderDomain(email) {
    return extractDomain(
        email?.headers?.from
    );
}


/* ======================================================
   URL EXTRACTION
====================================================== */

function getEmailUrls(email) {
    const urls = new Set();

    if (Array.isArray(email?.links)) {

        email.links.forEach(link => {

            if (link?.url) {
                urls.add(
                    normalize(link.url)
                );
            }

            if (link?.domain) {
                urls.add(
                    normalize(link.domain)
                );
            }

        });
    }

    /*
    Also check URL intelligence if available
    */

    if (Array.isArray(email?.urlIntelligence)) {

        email.urlIntelligence.forEach(item => {

            if (item?.url) {
                urls.add(
                    normalize(item.url)
                );
            }

            if (item?.domain) {
                urls.add(
                    normalize(item.domain)
                );
            }

        });
    }

    return [...urls];
}


function getEmailDomains(email) {

    const domains = new Set();

    const senderDomain =
        getSenderDomain(email);

    if (senderDomain) {
        domains.add(senderDomain);
    }

    getEmailUrls(email).forEach(value => {

        /*
        If value looks like a URL
        */

        try {

            const url = new URL(value);

            if (url.hostname) {

                domains.add(
                    normalize(url.hostname)
                );

            }

        } catch {

            /*
            If it is already a domain
            */

            if (
                value.includes(".") &&
                !value.includes(" ")
            ) {

                domains.add(
                    normalize(value)
                );

            }
        }

    });

    return [...domains];
}


/* ======================================================
   IP EXTRACTION
====================================================== */

function getEmailIPs(email) {

    const ips = new Set();

    /*
    Header forensics origin IP
    */

    const originIP =
        email?.headerForensics
            ?.received
            ?.origin_ip_candidate;

    if (originIP) {

        ips.add(
            normalize(originIP)
        );

    }


    /*
    Some implementations may store it directly
    */

    if (email?.origin_ip_candidate) {

        ips.add(
            normalize(
                email.origin_ip_candidate
            )
        );

    }


    /*
    Received headers
    */

    if (
        Array.isArray(
            email?.headers?.received
        )
    ) {

        email.headers.received.forEach(
            received => {

                if (!received) return;

                const matches =
                    String(received).match(
                        /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
                    );

                if (matches) {

                    matches.forEach(ip => {

                        ips.add(
                            normalize(ip)
                        );

                    });

                }

            }
        );
    }

    return [...ips];
}


/* ======================================================
   ATTACHMENT HASH EXTRACTION
====================================================== */

function getAttachmentHashes(email) {

    const hashes = new Set();

    /*
    Standard attachments
    */

    if (
        Array.isArray(
            email?.attachments
        )
    ) {

        email.attachments.forEach(
            attachment => {

                if (
                    attachment?.sha256
                ) {

                    hashes.add(
                        normalize(
                            attachment.sha256
                        )
                    );

                }

                if (
                    attachment?.hash
                ) {

                    hashes.add(
                        normalize(
                            attachment.hash
                        )
                    );

                }

            }
        );
    }


    /*
    Attachment Intelligence
    */

    if (
        Array.isArray(
            email?.attachmentIntelligence
        )
    ) {

        email.attachmentIntelligence
            .forEach(item => {

                if (item?.sha256) {

                    hashes.add(
                        normalize(
                            item.sha256
                        )
                    );

                }

                if (item?.hash) {

                    hashes.add(
                        normalize(
                            item.hash
                        )
                    );

                }

                if (
                    item?.hashes?.sha256
                ) {

                    hashes.add(
                        normalize(
                            item.hashes.sha256
                        )
                    );

                }

            });
    }

    return [...hashes];
}


/* ======================================================
   SUBJECT
====================================================== */

function getSubject(email) {

    return normalize(
        email?.headers?.subject
    );
}


/* ======================================================
   CONTENT SIMILARITY
====================================================== */

function cleanText(value) {

    if (!value) return "";

    return String(value)
        .replace(/<[^>]*>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&#39;/gi, "'")
        .replace(/&quot;/gi, '"')
        .replace(/[^a-zA-Z0-9\s]/g, " ")
        .toLowerCase()
        .replace(/\s+/g, " ")
        .trim();
}


function getBody(email) {

    return cleanText(
        email?.body?.plainText ||
        email?.body?.html ||
        ""
    );
}


function calculateTextSimilarity(
    textA,
    textB
) {

    const a = cleanText(textA);
    const b = cleanText(textB);

    if (!a || !b) return 0;

    const wordsA = new Set(
        a
            .split(/\s+/)
            .filter(word => word.length >= 3)
    );

    const wordsB = new Set(
        b
            .split(/\s+/)
            .filter(word => word.length >= 3)
    );

    if (
        !wordsA.size ||
        !wordsB.size
    ) {
        return 0;
    }

    let common = 0;

    wordsA.forEach(word => {

        if (wordsB.has(word)) {
            common++;
        }

    });

    const union = new Set([
        ...wordsA,
        ...wordsB
    ]).size;

    return union
        ? common / union
        : 0;
}


/* ======================================================
   CORRELATION
====================================================== */

function calculateCorrelation(
    currentEmail,
    previousEmail
) {

    const matches = [];


    /* ---------- SENDER ---------- */

    const currentSender =
        getSender(currentEmail);

    const previousSender =
        getSender(previousEmail);

    if (
        currentSender &&
        previousSender &&
        currentSender === previousSender
    ) {

        matches.push({

            type: "sender",

            label:
                "Same sender observed",

            strength: 25

        });

    }


    /* ---------- DOMAIN ---------- */

    const currentDomains =
        getEmailDomains(currentEmail);

    const previousDomains =
        getEmailDomains(previousEmail);

    const commonDomains =
        currentDomains.filter(
            domain =>
                previousDomains.includes(domain)
        );

    if (commonDomains.length > 0) {

        matches.push({

            type: "domain",

            label:
                "Same domain observed",

            value:
                commonDomains[0],

            strength: 15

        });

    }


    /* ---------- URL ---------- */

    const currentUrls =
        getEmailUrls(currentEmail);

    const previousUrls =
        getEmailUrls(previousEmail);

    const commonUrls =
        currentUrls.filter(
            url =>
                previousUrls.includes(url)
        );

    if (commonUrls.length > 0) {

        matches.push({

            type: "url",

            label:
                "Same URL observed",

            value:
                commonUrls[0],

            strength: 20

        });

    }


    /* ---------- IP ---------- */

    const currentIPs =
        getEmailIPs(currentEmail);

    const previousIPs =
        getEmailIPs(previousEmail);

    const commonIPs =
        currentIPs.filter(
            ip =>
                previousIPs.includes(ip)
        );

    if (commonIPs.length > 0) {

        matches.push({

            type: "ip",

            label:
                "Same IP observed",

            value:
                commonIPs[0],

            strength: 15

        });

    }


    /* ---------- ATTACHMENT HASH ---------- */

    const currentHashes =
        getAttachmentHashes(
            currentEmail
        );

    const previousHashes =
        getAttachmentHashes(
            previousEmail
        );

    const commonHashes =
        currentHashes.filter(
            hash =>
                previousHashes.includes(hash)
        );

    if (commonHashes.length > 0) {

        matches.push({

            type: "attachment",

            label:
                "Same attachment hash observed",

            value:
                commonHashes[0],

            strength: 30

        });

    }


    /* ---------- SUBJECT / BODY ---------- */

    const currentSubject =
        getSubject(currentEmail);

    const previousSubject =
        getSubject(previousEmail);

    const currentBody =
        getBody(currentEmail);

    const previousBody =
        getBody(previousEmail);


    const subjectSimilarity =
        calculateTextSimilarity(
            currentSubject,
            previousSubject
        );

    const bodySimilarity =
        calculateTextSimilarity(
            currentBody,
            previousBody
        );


    const subjectMatch =
        subjectSimilarity >= 0.65;

    const bodyMatch =
        bodySimilarity >= 0.60;


    if (
        subjectMatch ||
        bodyMatch
    ) {

        const strongestSimilarity =
            Math.max(
                subjectSimilarity,
                bodySimilarity
            );

        let strength = 10;

        if (
            subjectSimilarity >= 0.65 &&
            bodySimilarity >= 0.60
        ) {

            strength = 15;

        }


        matches.push({

            type: "content",

            label:
                "Similar subject / body observed",

            value: {

                subject_similarity:
                    Math.round(
                        subjectSimilarity * 100
                    ),

                body_similarity:
                    Math.round(
                        bodySimilarity * 100
                    ),

                strongest_similarity:
                    Math.round(
                        strongestSimilarity * 100
                    )

            },

            strength

        });

    }


    /*
    Calculate correlation score

    Maximum is capped at 100
    */

    const rawScore =
        matches.reduce(
            (total, match) =>
                total + match.strength,
            0
        );

    const score =
        Math.min(
            rawScore,
            100
        );


    return {

        score,

        matches

    };
}


/* ======================================================
   DATE
====================================================== */

function getEmailDate(email) {

    const date =
        email?.headers?.date ||
        email?.createdAt;

    if (!date) {
        return null;
    }

    const parsed =
        new Date(date);

    if (
        Number.isNaN(
            parsed.getTime()
        )
    ) {

        return null;

    }

    return parsed;
}


/* ======================================================
   BUILD CAMPAIGN GRAPH
====================================================== */

async function buildCampaignGraph(emailId = null ) {

    /*
    Fetch emails from MongoDB
    We only need fields required for correlation.
    */

    const emails =
        await Email.find({})
            .sort({
                createdAt: 1
            })
            .lean();


    if (!emails.length) {

        return {

            currentEmail: null,

            stats: {

                relatedCases: 0,

                matchingIndicators: 0,

                correlationStrength: 0

            },

            timeline: [],

            evidence: [],

            relatedEmails: []

        };

    }


    /*
    Latest email = current email
    */
   const currentEmail =
    emailId
        ? emails.find(
            email =>
                String(email._id) ===
                String(emailId)
        )
        : emails[emails.length - 1];
    if (!currentEmail) {
        return {
            currentEmail: null,
            stats: {
                relatedCases: 0,
                matchingIndicators: 0,
                correlationStrength: 0
            },

            timeline: [],
            evidence: [],
            relatedEmails: []

        };

    }
    const relatedEmails = [];
    /*
    Compare current email
    against every previous email
    */

    emails.forEach(email => {

        if (
            String(email._id) ===
            String(currentEmail._id)
        ) {

            return;

        }


        const correlation =
            calculateCorrelation(
                currentEmail,
                email
            );


        /*
        At least one meaningful match
        */

        if (
            correlation.matches.length > 0
        ) {

            relatedEmails.push({

                email,

                correlation

            });

        }

    });


    /*
    Sort strongest correlation first
    */

    relatedEmails.sort(
        (a, b) =>
            b.correlation.score -
            a.correlation.score
    );


    /* ==================================================
       UNIQUE INDICATORS
    ================================================== */

    const indicatorTypes =
        new Set();

    relatedEmails.forEach(item => {

        item.correlation.matches
            .forEach(match => {

                indicatorTypes.add(
                    match.type
                );

            });

    });


    /* ==================================================
       OVERALL CORRELATION
    ================================================== */

    let overallScore = 0;

    if (
        relatedEmails.length > 0
    ) {

        const total =
            relatedEmails.reduce(
                (sum, item) =>
                    sum +
                    item.correlation.score,
                0
            );

        overallScore =
            Math.round(
                total /
                relatedEmails.length
            );

    }


    /* ==================================================
       TIMELINE
    ================================================== */

    const timeline = [];


    relatedEmails
        .sort((a, b) => {

            const dateA =
                getEmailDate(
                    a.email
                )?.getTime() || 0;

            const dateB =
                getEmailDate(
                    b.email
                )?.getTime() || 0;

            return dateA - dateB;

        })
        .forEach(item => {

            const email =
                item.email;

            const date =
                getEmailDate(email);


            /*
            Create one timeline event
            for every matched indicator
            */

            item.correlation.matches
                .forEach(match => {

                    timeline.push({

                        date:
                            date
                                ? date.toISOString()
                                : null,

                        title:
                            match.label,

                        type:
                            match.type,

                        caseId:
                            String(
                                email._id
                            ),

                        emailId:
                            String(
                                email._id
                            ),

                        value:
                            match.value || null

                    });

                });

        });


    /*
    Current email at end
    */

    const currentDate =
        getEmailDate(
            currentEmail
        );


    timeline.push({

        date:
            currentDate
                ? currentDate.toISOString()
                : null,

        title:
            "Current email",

        type:
            "current",

        caseId:
            String(
                currentEmail._id
            ),

        emailId:
            String(
                currentEmail._id
            )

    });


    /* ==================================================
       EVIDENCE
    ================================================== */

    const evidence = [];


    relatedEmails.forEach(item => {

        item.correlation.matches
            .forEach(match => {

                evidence.push({

                    indicator:
                        match.type,

                    label:
                        match.label,

                    currentValue:
                        match.value ||
                        getSender(
                            currentEmail
                        ),

                    relatedCase:
                        String(
                            item.email._id
                        ),

                    relatedValue:
                        match.value ||
                        getSender(
                            item.email
                        ),

                    match: true,

                    score:
                        match.strength

                });

            });

    });


    /* ==================================================
       FINAL RESPONSE
    ================================================== */

    return {

        currentEmail: {

            id:
                String(
                    currentEmail._id
                ),

            caseId:
                String(
                    currentEmail._id
                ),

            subject:
                currentEmail
                    ?.headers
                    ?.subject ||
                "",

            sender:
                getSender(
                    currentEmail
                ),

            date:
                currentDate
                    ? currentDate.toISOString()
                    : null

        },


        stats: {

            relatedCases:
                relatedEmails.length,

            matchingIndicators:
                indicatorTypes.size,

            correlationStrength:
                overallScore

        },


        timeline,

        evidence,


        relatedEmails:
            relatedEmails.map(item => ({

                id:
                    String(
                        item.email._id
                    ),

                caseId:
                    String(
                        item.email._id
                    ),

                subject:
                    item.email
                        ?.headers
                        ?.subject ||
                    "",

                sender:
                    getSender(
                        item.email
                    ),

                date:
                    getEmailDate(
                        item.email
                    )
                        ?.toISOString() ||
                    null,

                correlationScore:
                    item.correlation.score,

                matches:
                    item.correlation.matches

            }))

    };

}
async function buildCampaignClusters() {

    const emails =
        await Email.find({})
            .sort({
                createdAt: 1
            })
            .lean();


    if (!emails.length) {

        return {
            clusters: []
        };

    }


    const visited =
        new Set();

    const clusters =
        [];


    for (const email of emails) {

        const emailId =
            String(email._id);


        if (
            visited.has(emailId)
        ) {
            continue;
        }


        const cluster = [];


        /*
         * Start a new campaign group
         * with this email.
         */

        const queue = [
            email
        ];


        visited.add(
            emailId
        );


        /*
         * Expand through connected
         * emails.
         *
         * Example:
         * A matches B
         * B matches C
         * => A, B, C are same cluster
         */

        while (
            queue.length > 0
        ) {

            const current =
                queue.shift();


            cluster.push(
                current
            );


            for (const other of emails) {

                const otherId =
                    String(other._id);


                if (
                    visited.has(otherId)
                ) {
                    continue;
                }


                const correlation =
                    calculateCorrelation(
                        current,
                        other
                    );


                if (
                    correlation.matches.length > 0
                ) {

                    visited.add(
                        otherId
                    );


                    queue.push(
                        other
                    );

                }

            }

        }


        /*
         * Only call it a campaign
         * when at least 2 emails are
         * connected.
         */

        if (
            cluster.length >= 2
        ) {

            clusters.push(
                cluster
            );

        }

    }


    return {

        clusters:
            clusters.map(
                (cluster, index) => ({

                    clusterId:
                        `CAMPAIGN-${String(
                            index + 1
                        ).padStart(
                            3,
                            "0"
                        )}`,

                    emailCount:
                        cluster.length,

                    emails:
                        cluster.map(
                            email => ({

                                id:
                                    String(
                                        email._id
                                    ),

                                subject:
                                    email
                                        ?.headers
                                        ?.subject ||
                                    "",

                                sender:
                                    getSender(
                                        email
                                    ),

                                date:
                                    getEmailDate(
                                        email
                                    )
                                        ?.toISOString() ||
                                    null

                            })
                        )

                })
            )

    };

}


module.exports = {
    buildCampaignGraph,
    buildCampaignClusters
};