"""
ThreadLens - Domain Intelligence Module

Analyzes:
- Sender domain
- Reply-To alignment
- Return-Path alignment
- Body-link domain mismatch
- Lookalike / typosquatting
- MX health
- Domain age
- Suspicious TLD
- Domain reputation

Provides backward-compatible signals plus
normalized 0-100 domain risk scoring.
"""

import difflib
import json
import os
import re
from typing import Any, Dict, List, Optional

import dns.resolver
import tldextract


# ============================================================
# BRAND TARGETS
# ============================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

BRAND_TARGETS_FILE = os.path.join(
    CURRENT_DIR,
    "brand_targets.json"
)


def load_brand_targets() -> List[str]:
    """Load protected brand names safely."""

    if not os.path.exists(BRAND_TARGETS_FILE):
        return [
            "paypal",
            "microsoft",
            "google",
            "apple",
            "amazon",
        ]

    try:
        with open(
            BRAND_TARGETS_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

            if isinstance(data, list):
                return [
                    str(item).strip().lower()
                    for item in data
                    if str(item).strip()
                ]

    except Exception:
        pass

    return [
        "paypal",
        "microsoft",
        "google",
        "apple",
        "amazon",
    ]


# ============================================================
# EMAIL ADDRESS EXTRACTION
# ============================================================

def extract_email_address(
    raw_header: Optional[str],
) -> Optional[str]:
    """
    Extract an email address from a header.

    Examples:
        Motorq <hrishikesh@codechef.com>
        hrishikesh@codechef.com
    """

    if (
        not raw_header
        or not isinstance(raw_header, str)
    ):
        return None

    match = re.search(
        r"[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}",
        raw_header,
    )

    if not match:
        return None

    return match.group(0).lower()


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain_parts(
    domain_or_email: Any,
) -> Dict[str, Optional[str]]:
    """
    Extract:
        registered_domain
        domain_name
        suffix
    """

    empty = {
        "registered_domain": None,
        "domain_name": None,
        "suffix": None,
    }

    if not domain_or_email:
        return empty

    raw_target = domain_or_email

    if isinstance(raw_target, dict):
        raw_target = (
            raw_target.get("url")
            or raw_target.get("href")
            or raw_target.get("link")
            or ""
        )

    if (
        not isinstance(raw_target, str)
        or not raw_target.strip()
    ):
        return empty

    raw_target = raw_target.strip()

    email_value = extract_email_address(
        raw_target
    )

    target = (
        email_value
        if email_value
        else raw_target.lower()
    )

    try:
        extracted = tldextract.extract(
            target
        )

        if (
            not extracted.domain
            or not extracted.suffix
        ):
            return empty

        registered_domain = (
            getattr(
                extracted,
                "top_domain_under_public_suffix",
                None,
            )
            or getattr(
                extracted,
                "registered_domain",
                None,
            )
        )

        return {
            "registered_domain": registered_domain,
            "domain_name": extracted.domain,
            "suffix": extracted.suffix,
        }

    except Exception:
        return empty


# ============================================================
# MX RECORD CHECK
# ============================================================

def check_mx_record(
    domain: Optional[str],
    timeout_sec: float = 2.0,
) -> Optional[bool]:
    """
    Returns:

        True  -> MX exists
        False -> domain has no MX
        None  -> lookup unavailable/failed
    """

    if not domain:
        return None

    resolver = dns.resolver.Resolver()

    resolver.lifetime = timeout_sec
    resolver.timeout = timeout_sec

    try:
        answers = resolver.resolve(
            domain,
            "MX",
        )

        return len(list(answers)) > 0

    except dns.resolver.NXDOMAIN:
        return False

    except dns.resolver.NoAnswer:
        return False

    except dns.resolver.NoNameservers:
        return None

    except dns.exception.Timeout:
        return None

    except Exception:
        return None


# ============================================================
# LOOKALIKE / TYPOSQUATTING
# ============================================================

LEET_TRANSLATIONS = str.maketrans({
    "1": "l",
    "0": "o",
    "3": "e",
    "5": "s",
    "8": "b",
    "@": "a",
})


def detect_lookalike_brand(
    domain_name: str,
    brand_list: List[str],
    threshold: float = 0.80,
) -> Dict[str, Any]:
    """
    Detect brand lookalike / typosquatting domains.
    """

    if not domain_name:
        return {
            "is_lookalike": False,
            "matched_brand": None,
            "similarity": 0.0,
        }

    domain_clean = (
        domain_name
        .lower()
        .replace("vv", "w")
    )

    normalized_candidate = (
        domain_clean.translate(
            LEET_TRANSLATIONS
        )
    )

    tokens = set(
        domain_clean.split("-")
        + normalized_candidate.split("-")
        + [
            domain_clean,
            normalized_candidate,
        ]
    )

    for brand in brand_list:

        brand_clean = (
            str(brand)
            .lower()
            .strip()
        )

        if not brand_clean:
            continue

        # Exact legitimate brand
        if domain_clean == brand_clean:
            return {
                "is_lookalike": False,
                "matched_brand": brand,
                "similarity": 1.0,
            }

        for token in tokens:

            if not token:
                continue

            # Exact match after leet normalization
            if (
                token == brand_clean
                and domain_clean != brand_clean
            ):
                return {
                    "is_lookalike": True,
                    "matched_brand": brand,
                    "similarity": 0.95,
                }

            ratio = difflib.SequenceMatcher(
                None,
                token,
                brand_clean,
            ).ratio()

            if (
                ratio >= threshold
                and token != brand_clean
            ):
                return {
                    "is_lookalike": True,
                    "matched_brand": brand,
                    "similarity": round(
                        ratio,
                        2,
                    ),
                }

    return {
        "is_lookalike": False,
        "matched_brand": None,
        "similarity": 0.0,
    }


# ============================================================
# SUSPICIOUS TLD
# ============================================================

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "shop",
    "support",
    "live",
    "buzz",
    "icu",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "work",
    "fit",
    "zip",
    "mov",
}


def is_suspicious_tld(
    suffix: Optional[str],
) -> Optional[bool]:
    """
    Returns:

        True  -> suspicious TLD
        False -> not in suspicious list
        None  -> unavailable
    """

    if not suffix:
        return None

    return (
        suffix.lower().strip()
        in SUSPICIOUS_TLDS
    )


# ============================================================
# DOMAIN AGE
# ============================================================

def get_domain_age_days(
    registered_domain: Optional[str],
) -> Optional[int]:
    """
    Domain age lookup placeholder.

    No WHOIS provider is currently connected.
    Therefore None is returned rather than guessing.
    """

    return None


def is_new_domain(
    age_days: Optional[int],
    threshold_days: int = 30,
) -> Optional[bool]:

    if age_days is None:
        return None

    return age_days <= threshold_days


# ============================================================
# DOMAIN RISK SCORING
# ============================================================

def calculate_domain_risk(
    domain_data: Optional[Dict[str, Any]],
    api_failed: bool = False,
) -> Dict[str, Any]:
    """
    Calculate normalized 0-100 domain risk score.

    Weights:

        malicious       +50
        lookalike       +50
        Reply-To        +25
        Return-Path     +20
        missing MX      +20
        new domain      +20
        suspicious TLD  +15
        body mismatch   +10

    Final score is capped at 100.
    """

    if not domain_data:

        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "Domain intelligence unavailable",
            ],
        }

    if api_failed:

        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "Domain intelligence unavailable",
            ],
        }

    score = 0
    reasons = []
    known_signal = False

    # --------------------------------------------------------
    # MALICIOUS REPUTATION +50
    # --------------------------------------------------------

    if domain_data.get(
        "is_malicious"
    ) is True:

        score += 50
        known_signal = True

        reasons.append(
            "Domain flagged as malicious by reputation intelligence"
        )

    # --------------------------------------------------------
    # LOOKALIKE +50
    # --------------------------------------------------------

    if domain_data.get(
        "is_lookalike"
    ) is True:

        score += 50
        known_signal = True

        brand = domain_data.get(
            "matched_brand"
        )

        if brand:
            reasons.append(
                f"Lookalike domain detected for {brand}"
            )
        else:
            reasons.append(
                "Lookalike or typosquatting domain detected"
            )

    # --------------------------------------------------------
    # REPLY-TO MISMATCH +25
    # --------------------------------------------------------

    if domain_data.get(
        "reply_to_mismatch"
    ) is True:

        score += 25
        known_signal = True

        reasons.append(
            "Reply-To domain does not match sender domain"
        )

    # --------------------------------------------------------
    # RETURN-PATH MISMATCH +20
    # --------------------------------------------------------

    if domain_data.get(
        "return_path_mismatch"
    ) is True:

        score += 20
        known_signal = True

        reasons.append(
            "Return-Path domain does not match sender domain"
        )

    # --------------------------------------------------------
    # MISSING MX +20
    # --------------------------------------------------------

    if domain_data.get(
        "missing_mx"
    ) is True:

        score += 20
        known_signal = True

        reasons.append(
            "Sender domain has no valid MX record"
        )

    # --------------------------------------------------------
    # NEW DOMAIN +20
    # --------------------------------------------------------

    if domain_data.get(
        "is_new_domain"
    ) is True:

        score += 20
        known_signal = True

        reasons.append(
            "Sender domain appears newly registered"
        )

    # --------------------------------------------------------
    # SUSPICIOUS TLD +15
    # --------------------------------------------------------

    if domain_data.get(
        "suspicious_tld"
    ) is True:

        score += 15
        known_signal = True

        reasons.append(
            "Domain uses a suspicious top-level domain"
        )

    # --------------------------------------------------------
    # BODY DOMAIN MISMATCH +10
    # --------------------------------------------------------

    if domain_data.get(
        "body_mismatch"
    ) is True:

        score += 10
        known_signal = True

        reasons.append(
            "Body links do not match the sender domain"
        )

    # --------------------------------------------------------
    # CAP SCORE
    # --------------------------------------------------------

    final_score = min(
        max(score, 0),
        100,
    )

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    if not known_signal:

        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "No conclusive domain risk intelligence available",
            ],
        }

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if final_score >= 70:
        risk_level = "HIGH"

    elif final_score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_reasons": reasons,
    }


# ============================================================
# MAIN DOMAIN INTELLIGENCE
# ============================================================

def analyze_domain_intelligence(
    from_header: Optional[str],
    reply_to_header: Optional[str] = None,
    return_path_header: Optional[str] = None,
    body_urls: Optional[List[str]] = None,
    offline_mode: bool = False,
) -> Dict[str, Any]:
    """
    Main Domain Intelligence entry point.

    Existing fields/signals are preserved.
    Normalized risk output is added.
    """

    body_urls = (
        body_urls
        if isinstance(body_urls, list)
        else []
    )

    brand_targets = load_brand_targets()

    # ========================================================
    # EXTRACT HEADER DOMAINS
    # ========================================================

    from_parts = extract_domain_parts(
        from_header
    )

    reply_to_parts = extract_domain_parts(
        reply_to_header
    )

    return_path_parts = extract_domain_parts(
        return_path_header
    )

    from_domain = from_parts[
        "registered_domain"
    ]

    reply_to_domain = reply_to_parts[
        "registered_domain"
    ]

    return_path_domain = return_path_parts[
        "registered_domain"
    ]

    # ========================================================
    # EXTRACT BODY DOMAINS
    # ========================================================

    body_domains = set()

    for url in body_urls:

        parts = extract_domain_parts(
            url
        )

        body_domain = parts[
            "registered_domain"
        ]

        if body_domain:
            body_domains.add(
                body_domain
            )

    # ========================================================
    # LOOKALIKE CHECK
    # ========================================================

    lookalike_info = detect_lookalike_brand(
        from_parts["domain_name"] or "",
        brand_targets,
    )

    # ========================================================
    # REPLY-TO MISMATCH
    # ========================================================

    reply_to_mismatch = bool(
        reply_to_domain
        and from_domain
        and reply_to_domain != from_domain
    )

    # ========================================================
    # RETURN-PATH MISMATCH
    # ========================================================

    return_path_mismatch = bool(
        return_path_domain
        and from_domain
        and return_path_domain != from_domain
    )

    # ========================================================
    # BODY DOMAIN MISMATCH
    # ========================================================

    body_domain_mismatch = False

    if (
        from_domain
        and body_domains
    ):
        body_domain_mismatch = (
            from_domain not in body_domains
        )

    # ========================================================
    # MX LOOKUP
    # ========================================================

    if offline_mode:

        has_mx = None
        mx_lookup_available = False

    else:

        has_mx = check_mx_record(
            from_domain
        )

        mx_lookup_available = (
            has_mx is not None
        )

    # ========================================================
    # DOMAIN AGE
    # ========================================================

    domain_age_days = get_domain_age_days(
        from_domain
    )

    new_domain_flag = is_new_domain(
        domain_age_days
    )

    # ========================================================
    # SUSPICIOUS TLD
    # ========================================================

    suspicious_tld = is_suspicious_tld(
        from_parts["suffix"]
    )

    # ========================================================
    # REPUTATION
    # ========================================================

    # No external reputation provider is currently connected.
    # Keep unavailable intelligence as None.
    is_malicious = None

    # ========================================================
    # SCORING INPUT
    # ========================================================

    signals_for_scoring = {

        "is_malicious":
            is_malicious,

        "is_lookalike":
            lookalike_info[
                "is_lookalike"
            ],

        "matched_brand":
            lookalike_info[
                "matched_brand"
            ],

        "reply_to_mismatch":
            reply_to_mismatch,

        "return_path_mismatch":
            return_path_mismatch,

        "missing_mx":
            has_mx is False,

        "is_new_domain":
            new_domain_flag,

        "suspicious_tld":
            suspicious_tld,

        "body_mismatch":
            body_domain_mismatch,
    }

    # ========================================================
    # CALCULATE RISK
    # ========================================================

    risk_assessment = calculate_domain_risk(
        signals_for_scoring,
        api_failed=offline_mode,
    )

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    return {

        "status":
            "success",

        # ----------------------------------------------------
        # DOMAINS
        # ----------------------------------------------------

        "domains": {

            "from_domain":
                from_domain,

            "reply_to_domain":
                reply_to_domain,

            "return_path_domain":
                return_path_domain,

            "body_domains":
                sorted(
                    list(body_domains)
                ),
        },

        # ----------------------------------------------------
        # DOMAIN METADATA
        # ----------------------------------------------------

        "domain_metadata": {

            "domain_age_days":
                domain_age_days,

            "is_new_domain":
                new_domain_flag,

            "suspicious_tld":
                suspicious_tld,

            "reputation_available":
                is_malicious is not None,
        },

        # ----------------------------------------------------
        # IDENTITY ALIGNMENT
        # ----------------------------------------------------

        "identity_alignment": {

            "from_matches_reply_to":
                not reply_to_mismatch,

            "from_matches_return_path":
                not return_path_mismatch,

            "from_matches_body_links":
                not body_domain_mismatch,
        },

        # ----------------------------------------------------
        # LOOKALIKE
        # ----------------------------------------------------

        "lookalike_analysis":
            lookalike_info,

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        "dns_health": {

            "from_has_mx":
                has_mx,

            "mx_lookup_available":
                mx_lookup_available,
        },

        # ----------------------------------------------------
        # EXISTING SIGNALS
        # ----------------------------------------------------

        "signals": {

            "reply_to_mismatch":
                reply_to_mismatch,

            "return_path_mismatch":
                return_path_mismatch,

            "is_brand_lookalike":
                lookalike_info[
                    "is_lookalike"
                ],

            "body_domain_mismatch":
                body_domain_mismatch,

            "from_missing_mx":
                has_mx is False,

            "is_malicious":
                is_malicious,

            "is_new_domain":
                new_domain_flag,

            "suspicious_tld":
                suspicious_tld,
        },

        # ----------------------------------------------------
        # NEW NORMALIZED RISK
        # ----------------------------------------------------

        "risk_score":
            risk_assessment[
                "risk_score"
            ],

        "risk_level":
            risk_assessment[
                "risk_level"
            ],

        "risk_reasons":
            risk_assessment[
                "risk_reasons"
            ],

        # ----------------------------------------------------
        # GROUPED NORMALIZED OUTPUT
        # ----------------------------------------------------

        "normalized_output":
            risk_assessment,
    }