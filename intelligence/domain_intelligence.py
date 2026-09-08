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


# def load_brand_targets() -> List[str]:
#     """Load protected brand names safely."""

#     if not os.path.exists(BRAND_TARGETS_FILE):
#         return [
#             "paypal",
#             "microsoft",
#             "google",
#             "apple",
#             "amazon",
#         ]

#     try:
#         with open(
#             BRAND_TARGETS_FILE,
#             "r",
#             encoding="utf-8",
#         ) as file:

#             data = json.load(file)

#             if isinstance(data, list):
#                 return [
#                     str(item).strip().lower()
#                     for item in data
#                     if str(item).strip()
#                 ]

#     except Exception:
#         pass

#     return [
#         "paypal",
#         "microsoft",
#         "google",
#         "apple",
#         "amazon",
#     ]

def load_brand_targets() -> List[Dict[str, Any]]:
    """Load protected brand targets with official domains and display names."""

    fallback = [
        {
            "brand": "paypal",
            "display_names": ["paypal", "paypal security", "paypal support"],
            "official_domains": ["paypal.com"],
        },
        {
            "brand": "microsoft",
            "display_names": ["microsoft", "microsoft support", "microsoft account"],
            "official_domains": ["microsoft.com", "live.com", "office.com", "outlook.com"],
        },
        {
            "brand": "google",
            "display_names": ["google", "google security", "google support"],
            "official_domains": ["google.com"],
        },
        {
            "brand": "apple",
            "display_names": ["apple", "apple support", "apple ID"],
            "official_domains": ["apple.com"],
        },
        {
            "brand": "amazon",
            "display_names": ["amazon", "amazon support", "amazon pay"],
            "official_domains": ["amazon.com"],
        },
    ]

    if not os.path.exists(BRAND_TARGETS_FILE):
        return fallback

    try:
        with open(BRAND_TARGETS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, list) and len(data) > 0:
                return data
    except Exception:
        pass

    return fallback


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
        extracted = tldextract.extract(target)

        registered_domain = (
            getattr(extracted, "top_domain_under_public_suffix", None)
            or getattr(extracted, "registered_domain", None)
        )

        # Fallback for synthetic/testing domains like .invalid, .test, or custom TLDs
        if not extracted.domain or not extracted.suffix or not registered_domain:
            # Strip email prefix if present (e.g. user@paypa1.invalid -> paypa1.invalid)
            clean_target = target.split("@")[-1].split("/")[0].strip()
            
            parts = clean_target.rsplit(".", 1)
            if len(parts) == 2 and parts[0] and parts[1]:
                domain_body = parts[0].split(".")[-1] # extract main domain name
                suffix = parts[1]
                return {
                    "registered_domain": f"{domain_body}.{suffix}",
                    "domain_name": domain_body,
                    "suffix": suffix,
                }
            return empty

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
    domain_name: Optional[str],
    brand_list: List[Any],
    threshold: float = 0.80,
) -> Dict[str, Any]:
    """
    Detect brand lookalike / typosquatting domains and classify the attack type.
    """
    if not domain_name or not isinstance(domain_name, str):
        return {
            "is_lookalike": False,
            "matched_brand": None,
            "similarity": 0.0,
            "attack_type": None,
        }

    domain_clean = domain_name.lower().strip()

    # De-leet transformation (e.g. paypa1 -> paypal)
    normalized_candidate = (
        domain_clean.replace("vv", "w").translate(LEET_TRANSLATIONS)
    )

    tokens = set(
        domain_clean.split("-")
        + normalized_candidate.split("-")
        + [domain_clean, normalized_candidate]
    )

    for brand_entry in brand_list:
        if isinstance(brand_entry, dict):
            brand_name = brand_entry.get("brand", "")
        else:
            brand_name = str(brand_entry)

        brand_clean = brand_name.lower().strip()

        if not brand_clean:
            continue

        # 1. Exact Legitimate Domain Match
        if domain_clean == brand_clean:
            return {
                "is_lookalike": False,
                "matched_brand": brand_name,
                "similarity": 1.0,
                "attack_type": None,
            }

        # 2. Character Substitution / Homoglyph / Leetspeak (e.g., paypa1 -> paypal)
        if normalized_candidate == brand_clean and domain_clean != brand_clean:
            return {
                "is_lookalike": True,
                "matched_brand": brand_name,
                "similarity": 0.95,
                "attack_type": "character_substitution",
            }

        # 3. Token Combination / Keyword Injection (e.g., paypal-security)
        if brand_clean in domain_clean and domain_clean != brand_clean:
            return {
                "is_lookalike": True,
                "matched_brand": brand_name,
                "similarity": 0.90,
                "attack_type": "token_injection",
            }

        # 4. Fuzzy Match / Typosquatting (e.g., paypal -> paypal)
        for token in tokens:
            if not token:
                continue

            ratio = difflib.SequenceMatcher(
                None,
                token,
                brand_clean,
            ).ratio()

            if ratio >= threshold and token != brand_clean:
                return {
                    "is_lookalike": True,
                    "matched_brand": brand_name,
                    "similarity": round(ratio, 2),
                    "attack_type": "typosquatting",
                }

    return {
        "is_lookalike": False,
        "matched_brand": None,
        "similarity": 0.0,
        "attack_type": None,
    }

# ============================================================
# BRAND IDENTIFICATION & SPOOFING HELPERS
# ============================================================
def calculate_brand_impersonation_confidence(
    brand_info: Dict[str, Any],
    lookalike_info: Dict[str, Any],
    display_spoof_info: Dict[str, Any],
    official_comparison: Dict[str, Any],
    body_mismatch: bool,
    reply_to_mismatch: bool,
) -> Dict[str, Any]:
    """
    Calculate weighted Brand Impersonation Confidence score and level.
    """
    score = 0

    # +10: Brand identified in email
    if brand_info.get("identified"):
        score += 10

    # +20: Display name claims brand
    if brand_info.get("source") == "display_name":
        score += 20

    # +20: Sender domain does not match official domains
    if brand_info.get("identified") and not official_comparison.get("matches_official"):
        score += 20

    # +20: Lookalike domain detected
    if lookalike_info.get("is_lookalike"):
        score += 20

    # +15: Typosquatting / Character substitution detected
    if lookalike_info.get("attack_type") in ["character_substitution", "typosquatting"]:
        score += 15

    # +20: Display name spoofing active
    if display_spoof_info.get("display_name_spoofing"):
        score += 20

    # +10: Body links mismatch sender/brand
    if body_mismatch:
        score += 10

    # +10: Reply-To mismatch
    if reply_to_mismatch:
        score += 10

    # Cap score at 100
    final_score = min(score, 100)

    # Classify confidence level
    if final_score >= 80:
        level = "HIGH"
    elif final_score >= 50:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": final_score,
        "level": level,
    }
def identify_claimed_brand(
    display_name: Optional[str] = None,
    sender_domain: Optional[str] = None,
    body_urls: Optional[List[str]] = None,
    brand_targets: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Identify target brand from display name, sender domain, or body URLs.
    """
    if not brand_targets:
        return {
            "identified": False,
            "brand": None,
            "source": None,
            "official_domains": [],
        }

    # 1. CHECK DISPLAY NAME
    if display_name and isinstance(display_name, str):
        name_clean = display_name.lower().strip()

        for target in brand_targets:
            if not isinstance(target, dict):
                continue

            brand = target.get("brand", "").lower()
            display_names = [
                dn.lower() for dn in target.get("display_names", [])
            ]

            if name_clean == brand or any(
                dn in name_clean for dn in display_names
            ):
                return {
                    "identified": True,
                    "brand": target.get("brand"),
                    "source": "display_name",
                    "official_domains": target.get("official_domains", []),
                }

    # 2. CHECK SENDER DOMAIN
    if sender_domain and isinstance(sender_domain, str):
        domain_clean = sender_domain.lower().strip()

        for target in brand_targets:
            if not isinstance(target, dict):
                continue

            official_domains = [
                d.lower() for d in target.get("official_domains", [])
            ]

            if domain_clean in official_domains:
                return {
                    "identified": True,
                    "brand": target.get("brand"),
                    "source": "sender_domain",
                    "official_domains": official_domains,
                }

    # 3. CHECK BODY URLS
    if body_urls and isinstance(body_urls, list):
        for url in body_urls:
            if not isinstance(url, str):
                continue

            url_clean = url.lower()

            for target in brand_targets:
                if not isinstance(target, dict):
                    continue

                official_domains = [
                    d.lower() for d in target.get("official_domains", [])
                ]

                if any(domain in url_clean for domain in official_domains):
                    return {
                        "identified": True,
                        "brand": target.get("brand"),
                        "source": "body_urls",
                        "official_domains": official_domains,
                    }

    # FALLBACK: NO BRAND IDENTIFIED
    return {
        "identified": False,
        "brand": None,
        "source": None,
        "official_domains": [],
    }



def compare_official_domain(
    sender_domain: Optional[str],
    official_domains: Optional[List[str]],
) -> Dict[str, Any]:
    """
    Compare the extracted sender domain against a list of official brand domains.
    """
    official_list = (
        [d.lower().strip() for d in official_domains if isinstance(d, str)]
        if isinstance(official_domains, list)
        else []
    )

    if not sender_domain or not isinstance(sender_domain, str):
        return {
            "sender_domain": sender_domain,
            "official_domains": official_list,
            "matches_official": False,
        }

    domain_clean = sender_domain.lower().strip()
    matches = domain_clean in official_list

    return {
        "sender_domain": domain_clean,
        "official_domains": official_list,
        "matches_official": matches,
    }
def check_display_name_spoofing(
    display_name: Optional[str],
    from_domain: Optional[str],
    brand_targets: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Check if display name claims a known brand while sending from an unauthorized domain."""

    brand_info = identify_claimed_brand(
        display_name=display_name,
        sender_domain=from_domain,
        brand_targets=brand_targets,
    )

    domain_clean = from_domain.lower().strip() if from_domain else None

    # If no brand was claimed or display name is missing
    if not brand_info["identified"]:
        return {
            "display_name_spoofing": False,
            "claimed_brand": None,
            "actual_domain": domain_clean,
            "official_domains": [],
        }

    official_domains = [d.lower() for d in brand_info.get("official_domains", [])]
    
    # Check if sender domain matches official domains
    is_spoofed = domain_clean not in official_domains if domain_clean else False

    return {
        "display_name_spoofing": is_spoofed,
        "claimed_brand": brand_info.get("brand"),
        "actual_domain": domain_clean,
        "official_domains": official_domains,
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
        display_spoofed +40
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

        brand = domain_data.get("matched_brand")
        attack_type = domain_data.get("attack_type")


        if brand and attack_type:
            reasons.append(
                f"Lookalike domain detected targeting {brand} ({attack_type.replace('_', ' ')})"
            )
        elif brand:
            reasons.append(
                f"Lookalike domain detected for {brand}"
            )
        else:
            reasons.append(
                "Lookalike or typosquatting domain detected"
            )

    # --------------------------------------------------------
    # DISPLAY NAME SPOOFING +40
    # --------------------------------------------------------

    if domain_data.get("is_display_spoofed") is True:

        score += 40
        known_signal = True

        claimed_brand = domain_data.get("matched_brand")

        if claimed_brand:
            reasons.append(
                f"Display name impersonates {claimed_brand} from an unauthorized domain"
            )
        else:
            reasons.append(
                "Display name impersonates a known brand from an unauthorized domain"
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

import email.utils

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
    # PARSE DISPLAY NAME
    # ========================================================
    parsed_name, _ = email.utils.parseaddr(from_header or "")
    display_name = parsed_name if parsed_name else None

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
    # BRAND IDENTIFICATION
    # ========================================================

    brand_info = identify_claimed_brand(
        display_name=display_name,
        sender_domain=from_domain,
        body_urls=body_urls,
        brand_targets=brand_targets,
    )

    # ========================================================
    # LOOKALIKE CHECK
    # ========================================================

    lookalike_info = detect_lookalike_brand(
        from_parts["domain_name"] or "",
        brand_targets,
    )

    # ========================================================
    # DISPLAY NAME SPOOFING CHECK
    # ========================================================

    display_spoof_info = check_display_name_spoofing(
        display_name=display_name,
        from_domain=from_domain,
        brand_targets=brand_targets,
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

        "attack_type":
            lookalike_info.get(
                "attack_type"
            ),

        "matched_brand":
            lookalike_info.get("matched_brand") or display_spoof_info.get("claimed_brand"),

        "is_display_spoofed":
            display_spoof_info[
                "display_name_spoofing"
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

    # --------------------------------------------------------
    # BRAND IMPERSONATION ANALYSIS & CONFIDENCE
    # --------------------------------------------------------
    official_domains = brand_info.get("official_domains", [])
    official_comparison = compare_official_domain(from_domain, official_domains)

    confidence = calculate_brand_impersonation_confidence(
        brand_info=brand_info,
        lookalike_info=lookalike_info,
        display_spoof_info=display_spoof_info,
        official_comparison=official_comparison,
        body_mismatch=body_domain_mismatch,
        reply_to_mismatch=reply_to_mismatch,
    )

    brand_impersonation_payload = {
        "brand_identified": brand_info.get("identified", False),
        "identified_brand": brand_info.get("brand"),
        "claimed_brand": display_spoof_info.get("claimed_brand"),
        "sender_domain": from_domain,
        "official_domains": official_domains,
        "sender_vs_claimed_brand": {
            "matches": official_comparison.get("matches_official", False)
        },
        "official_domain_comparison": {
            "matches": official_comparison.get("matches_official", False)
        },
        "lookalike_detection": {
            "detected": lookalike_info.get("is_lookalike", False),
            "matched_brand": lookalike_info.get("matched_brand"),
            "similarity": lookalike_info.get("similarity", 0.0),
        },
        "typosquatting": {
            "detected": lookalike_info.get("is_lookalike", False) and lookalike_info.get("attack_type") is not None,
            "technique": lookalike_info.get("attack_type"),
        },
        "display_name_spoofing": {
            "detected": display_spoof_info.get("display_name_spoofing", False)
        },
        "confidence": confidence,
    }

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    return {

        "status":
            "success",

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

        "identity_alignment": {

            "from_matches_reply_to":
                not reply_to_mismatch,

            "from_matches_return_path":
                not return_path_mismatch,

            "from_matches_body_links":
                not body_domain_mismatch,
        },

        "lookalike_analysis":
            lookalike_info,

        "brand_impersonation":
            brand_impersonation_payload,

        "dns_health": {

            "from_has_mx":
                has_mx,

            "mx_lookup_available":
                mx_lookup_available,
        },

        "signals": {

            "reply_to_mismatch":
                reply_to_mismatch,

            "return_path_mismatch":
                return_path_mismatch,

            "is_brand_lookalike":
                lookalike_info[
                    "is_lookalike"
                ],

            "is_display_spoofed":
                display_spoof_info[
                    "display_name_spoofing"
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

        "normalized_output":
            risk_assessment,
    }