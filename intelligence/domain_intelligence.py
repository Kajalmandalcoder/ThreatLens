"""
ThreadLens - Domain Intelligence Module

Responsibilities:
- Sender domain analysis
- Reply-To / Return-Path alignment
- Body-link domain analysis
- MX / SPF / DMARC checks
- Brand lookalike / typosquatting detection
- Homograph detection
- Suspicious TLD detection
- RDAP domain age
- VirusTotal domain reputation
- Explainable 0-100 risk scoring

Important design rules:
- Unknown intelligence is never treated as clean.
- External domains are NOT automatically malicious.
- Missing Reply-To / Return-Path is NOT a mismatch.
- SPF/DMARC absence is supporting evidence only.
"""

import difflib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver
import requests
import tldextract


# ============================================================
# ENVIRONMENT
# ============================================================

try:
    from dotenv import load_dotenv

    PROJECT_ROOT = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            ".."
        )
    )

    BACKEND_ENV = os.path.join(
        PROJECT_ROOT,
        "backend",
        ".env"
    )

    if os.path.exists(BACKEND_ENV):
        load_dotenv(
            BACKEND_ENV,
            override=True
        )

except Exception:
    pass


# ============================================================
# CONFIGURATION
# ============================================================

RDAP_URL = (
    "https://rdap.org/domain/{}"
)

RDAP_TIMEOUT = float(
    os.getenv(
        "RDAP_TIMEOUT",
        "4.0"
    )
)

DOMAIN_NEW_THRESHOLD_DAYS = int(
    os.getenv(
        "DOMAIN_NEW_THRESHOLD_DAYS",
        "30"
    )
)

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)

VIRUSTOTAL_DOMAIN_URL = (
    "https://www.virustotal.com/api/v3/domains/{}"
)

VT_MALICIOUS_MIN_RATIO = float(
    os.getenv(
        "VT_MALICIOUS_MIN_RATIO",
        "0.10"
    )
)

VT_MALICIOUS_MIN_DETECTIONS = int(
    os.getenv(
        "VT_MALICIOUS_MIN_DETECTIONS",
        "3"
    )
)


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
    """
    Load protected brand names safely.
    """

    default_brands = [
        "paypal",
        "microsoft",
        "google",
        "apple",
        "amazon",
        "cisco",
        "linkedin",
        "adobe",
        "netflix",
        "docusign",
        "icloud",
        "dropbox",
        "onedrive",
        "outlook",
        "facebook",
        "instagram",
        "whatsapp",
        "github",
        "zoom",
        "wintermute",
    ]

    if not os.path.exists(
        BRAND_TARGETS_FILE
    ):
        return default_brands

    try:
        with open(
            BRAND_TARGETS_FILE,
            "r",
            encoding="utf-8"
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

    return default_brands


# ============================================================
# EMAIL ADDRESS EXTRACTION
# ============================================================

def extract_email_address(
    raw_header: Optional[str]
) -> Optional[str]:
    """
    Extract an email address from a header.
    """

    if not raw_header:
        return None

    if not isinstance(
        raw_header,
        str
    ):
        return None

    match = re.search(
        r"[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}",
        raw_header
    )

    if not match:
        return None

    return match.group(
        0
    ).lower()


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain_parts(
    domain_or_email: Any
) -> Dict[str, Optional[str]]:
    """
    Extract:

    - registered_domain
    - domain_name
    - suffix
    """

    empty = {
        "registered_domain": None,
        "domain_name": None,
        "suffix": None
    }

    if not domain_or_email:
        return empty

    raw_target = domain_or_email

    if isinstance(
        raw_target,
        dict
    ):
        raw_target = (
            raw_target.get("url")
            or raw_target.get("href")
            or raw_target.get("link")
            or ""
        )

    if (
        not isinstance(
            raw_target,
            str
        )
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
                None
            )
            or
            getattr(
                extracted,
                "registered_domain",
                None
            )
        )

        return {
            "registered_domain": (
                registered_domain.lower()
                if registered_domain
                else None
            ),
            "domain_name": (
                extracted.domain.lower()
                if extracted.domain
                else None
            ),
            "suffix": (
                extracted.suffix.lower()
                if extracted.suffix
                else None
            )
        }

    except Exception:
        return empty


# ============================================================
# DNS RESOLVER
# ============================================================

def _build_resolver(
    timeout_sec: float
) -> dns.resolver.Resolver:

    resolver = dns.resolver.Resolver()

    resolver.lifetime = timeout_sec
    resolver.timeout = timeout_sec

    return resolver


# ============================================================
# MX
# ============================================================

def check_mx_record(
    domain: Optional[str],
    timeout_sec: float = 3.0
) -> Optional[bool]:

    if not domain:
        return None

    resolver = _build_resolver(
        timeout_sec
    )

    try:
        answers = resolver.resolve(
            domain,
            "MX"
        )

        return len(
            list(answers)
        ) > 0

    except dns.resolver.NXDOMAIN:
        return False

    except dns.resolver.NoAnswer:
        return False

    except (
        dns.resolver.NoNameservers,
        dns.exception.Timeout
    ):
        return None

    except Exception:
        return None


# ============================================================
# TXT NORMALIZATION
# ============================================================

def _txt_record_to_text(
    record: Any
) -> str:

    try:
        strings = record.strings

        parts = []

        for item in strings:

            if isinstance(
                item,
                bytes
            ):
                parts.append(
                    item.decode(
                        "utf-8",
                        errors="ignore"
                    )
                )
            else:
                parts.append(
                    str(item)
                )

        return "".join(parts)

    except Exception:
        return str(record)


# ============================================================
# SPF
# ============================================================

def check_spf_record(
    domain: Optional[str],
    timeout_sec: float = 3.0
) -> Optional[bool]:
    """
    True  -> SPF exists
    False -> lookup succeeded, SPF absent
    None  -> DNS unavailable
    """

    if not domain:
        return None

    system_resolver = dns.resolver.Resolver()

    system_resolver.lifetime = (
        timeout_sec
    )

    system_resolver.timeout = (
        timeout_sec
    )

    fallback_resolvers = [
        "1.1.1.1",
        "8.8.8.8"
    ]

    resolvers = [
        system_resolver
    ]

    for nameserver in fallback_resolvers:

        fallback = dns.resolver.Resolver(
            configure=False
        )

        fallback.nameservers = [
            nameserver
        ]

        fallback.lifetime = (
            timeout_sec
        )

        fallback.timeout = (
            timeout_sec
        )

        resolvers.append(
            fallback
        )

    successful_lookup = False

    for resolver in resolvers:

        try:

            answers = resolver.resolve(
                domain,
                "TXT"
            )

            successful_lookup = True

            for record in answers:

                text = _txt_record_to_text(
                    record
                )

                normalized = (
                    text
                    .strip()
                    .replace('"', "")
                    .lower()
                )

                if re.search(
                    r"(^|\s)v=spf1(?:\s|$)",
                    normalized
                ):
                    return True

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ):
            continue

        except Exception:
            continue

    if successful_lookup:
        return False

    return None


# ============================================================
# DMARC
# ============================================================

def check_dmarc_record(
    domain: Optional[str],
    timeout_sec: float = 3.0
) -> Optional[bool]:
    """
    True  -> DMARC exists
    False -> lookup succeeded, DMARC absent
    None  -> DNS unavailable
    """

    if not domain:
        return None

    dmarc_domain = (
        f"_dmarc.{domain}"
    )

    resolver = _build_resolver(
        timeout_sec
    )

    try:

        answers = resolver.resolve(
            dmarc_domain,
            "TXT"
        )

        for record in answers:

            text = (
                _txt_record_to_text(
                    record
                )
                .strip()
                .lower()
            )

            if text.startswith(
                "v=dmarc1"
            ):
                return True

        return False

    except dns.resolver.NXDOMAIN:
        return False

    except dns.resolver.NoAnswer:
        return False

    except (
        dns.resolver.NoNameservers,
        dns.exception.Timeout
    ):
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
    "@": "a"
})


def detect_lookalike_brand(
    domain_name: str,
    brand_list: List[str],
    threshold: float = 0.86
) -> Dict[str, Any]:

    if not domain_name:
        return {
            "is_lookalike": False,
            "matched_brand": None,
            "similarity": 0.0
        }

    domain_clean = (
        domain_name
        .lower()
        .strip()
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
            normalized_candidate
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

        # Exact legitimate brand.
        if domain_clean == brand_clean:
            return {
                "is_lookalike": False,
                "matched_brand": brand,
                "similarity": 1.0
            }

        for token in tokens:

            if not token:
                continue

            # Exact match after leet normalization.
            if (
                token == brand_clean
                and domain_clean != brand_clean
            ):
                return {
                    "is_lookalike": True,
                    "matched_brand": brand,
                    "similarity": 0.95
                }

            ratio = difflib.SequenceMatcher(
                None,
                token,
                brand_clean
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
                        2
                    )
                }

    return {
        "is_lookalike": False,
        "matched_brand": None,
        "similarity": 0.0
    }


# ============================================================
# HOMOGRAPH
# ============================================================

COMMON_HOMOGRAPH_CHARS = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ⅼ": "l"
}


def detect_homograph(
    domain: Optional[str]
) -> Optional[bool]:

    if not domain:
        return None

    try:

        for char in domain:

            if char in COMMON_HOMOGRAPH_CHARS:
                return True

            if ord(char) > 127:
                return True

        return False

    except Exception:
        return None


# ============================================================
# SUSPICIOUS TLD
# ============================================================

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "shop",
    "support",
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
    "mov"
}


def is_suspicious_tld(
    suffix: Optional[str]
) -> Optional[bool]:

    if not suffix:
        return None

    return (
        suffix.lower().strip()
        in SUSPICIOUS_TLDS
    )


# ============================================================
# RDAP REGISTRATION DATE
# ============================================================

def get_domain_registration_date(
    registered_domain: Optional[str],
    timeout_sec: float = RDAP_TIMEOUT
) -> Optional[datetime]:

    if not registered_domain:
        return None

    try:

        response = requests.get(
            RDAP_URL.format(
                registered_domain
            ),
            timeout=timeout_sec,
            headers={
                "Accept":
                    "application/rdap+json"
            }
        )

        if response.status_code != 200:
            return None

        data = response.json()

        events = data.get(
            "events",
            []
        )

        if not isinstance(
            events,
            list
        ):
            return None

        registration_events = [
            event
            for event in events
            if isinstance(
                event,
                dict
            )
            and event.get(
                "eventAction"
            ) in {
                "registration",
                "registered"
            }
            and event.get(
                "eventDate"
            )
        ]

        if not registration_events:
            return None

        date_value = registration_events[0].get(
            "eventDate"
        )

        if not date_value:
            return None

        normalized = (
            str(date_value)
            .replace(
                "Z",
                "+00:00"
            )
        )

        parsed = datetime.fromisoformat(
            normalized
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ):
        return None

    except Exception:
        return None


def get_domain_age_days(
    registered_domain: Optional[str]
) -> Optional[int]:

    registration_date = (
        get_domain_registration_date(
            registered_domain
        )
    )

    if not registration_date:
        return None

    try:

        now = datetime.now(
            timezone.utc
        )

        return max(
            (
                now - registration_date
            ).days,
            0
        )

    except Exception:
        return None


def is_new_domain(
    age_days: Optional[int],
    threshold_days: int = DOMAIN_NEW_THRESHOLD_DAYS
) -> Optional[bool]:

    if age_days is None:
        return None

    return (
        age_days <= threshold_days
    )


# ============================================================
# VIRUSTOTAL DOMAIN REPUTATION
# ============================================================

def enrich_domain_reputation(
    domain: Optional[str],
    timeout_sec: float = 4.0
) -> Dict[str, Any]:

    result = {
        "reputation_status":
            "unavailable",

        "provider":
            "VirusTotal",

        "is_malicious":
            None,

        "malicious_detections":
            None,

        "suspicious_detections":
            None,

        "total_detections":
            None,

        "malicious_ratio":
            None,

        "reputation_score":
            None
    }

    if not domain:

        result[
            "reputation_status"
        ] = "domain_missing"

        return result

    if not VIRUSTOTAL_API_KEY:

        result[
            "reputation_status"
        ] = "api_key_missing"

        return result

    try:

        response = requests.get(
            VIRUSTOTAL_DOMAIN_URL.format(
                domain
            ),
            headers={
                "x-apikey":
                    VIRUSTOTAL_API_KEY,

                "Accept":
                    "application/json"
            },
            timeout=timeout_sec
        )

        if response.status_code != 200:

            result[
                "reputation_status"
            ] = (
                f"http_{response.status_code}"
            )

            return result

        payload = response.json()

        attributes = (
            payload
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        if not isinstance(
            stats,
            dict
        ):

            result[
                "reputation_status"
            ] = (
                "invalid_analysis_stats"
            )

            return result

        malicious = int(
            stats.get(
                "malicious",
                0
            )
        )

        suspicious = int(
            stats.get(
                "suspicious",
                0
            )
        )

        harmless = int(
            stats.get(
                "harmless",
                0
            )
        )

        undetected = int(
            stats.get(
                "undetected",
                0
            )
        )

        timeout_count = int(
            stats.get(
                "timeout",
                0
            )
        )

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
            + timeout_count
        )

        if total <= 0:

            result[
                "reputation_status"
            ] = (
                "no_analysis_data"
            )

            return result

        malicious_ratio = (
            malicious / total
        )

        strong_consensus = (
            malicious >=
            VT_MALICIOUS_MIN_DETECTIONS
            and
            malicious_ratio >=
            VT_MALICIOUS_MIN_RATIO
        )

        result.update({
            "reputation_status":
                "success",

            "is_malicious":
                strong_consensus,

            "malicious_detections":
                malicious,

            "suspicious_detections":
                suspicious,

            "total_detections":
                total,

            "malicious_ratio":
                round(
                    malicious_ratio,
                    4
                ),

            "reputation_score":
                round(
                    malicious_ratio * 100,
                    2
                )
        })

        return result

    except requests.Timeout:

        result[
            "reputation_status"
        ] = (
            "network_timeout_or_error"
        )

        return result

    except requests.RequestException:

        result[
            "reputation_status"
        ] = (
            "network_timeout_or_error"
        )

        return result

    except (
        ValueError,
        TypeError
    ):

        result[
            "reputation_status"
        ] = (
            "invalid_api_response"
        )

        return result

    except Exception:

        result[
            "reputation_status"
        ] = (
            "unexpected_error"
        )

        return result


# ============================================================
# DOMAIN RISK SCORING
# ============================================================

def calculate_domain_risk(
    domain_data: Optional[Dict[str, Any]],
    api_failed: bool = False
) -> Dict[str, Any]:
    """
    Domain score:

    Malicious reputation       +50
    Lookalike                  +50
    Reply-To mismatch          +25
    Return-Path mismatch       +20
    Missing MX                 +20
    New domain                 +20
    Suspicious TLD             +15
    Body-domain mismatch       +20
    SPF + DMARC both absent    +10

    Supporting-only:
    - SPF absence
    - DMARC absence
    - Homograph

    Unknown intelligence is never treated as clean.
    """

    if not domain_data:

        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "Domain intelligence unavailable"
            ]
        }

    if api_failed:

        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "Domain intelligence unavailable"
            ]
        }

    score = 0

    reasons: List[str] = []

    known_signal = False

    # ========================================================
    # 1. MALICIOUS REPUTATION
    # ========================================================

    if (
        domain_data.get(
            "is_malicious"
        )
        is True
    ):

        score += 50
        known_signal = True

        malicious = domain_data.get(
            "malicious_detections"
        )

        total = domain_data.get(
            "total_detections"
        )

        if (
            malicious is not None
            and total
        ):

            reasons.append(
                "Strong malicious reputation consensus "
                f"({malicious}/{total} scanners)"
            )

        else:

            reasons.append(
                "Domain has strong malicious reputation"
            )

    # ========================================================
    # 2. LOOKALIKE
    # ========================================================

    if (
        domain_data.get(
            "is_lookalike"
        )
        is True
    ):

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

    # ========================================================
    # 3. REPLY-TO
    # ========================================================

    if (
        domain_data.get(
            "reply_to_mismatch"
        )
        is True
    ):

        score += 25
        known_signal = True

        reasons.append(
            "Reply-To domain does not match sender domain"
        )

    # ========================================================
    # 4. RETURN-PATH
    # ========================================================

    if (
        domain_data.get(
            "return_path_mismatch"
        )
        is True
    ):

        score += 20
        known_signal = True

        reasons.append(
            "Return-Path domain does not match sender domain"
        )

    # ========================================================
    # 5. MISSING MX
    # ========================================================

    if (
        domain_data.get(
            "missing_mx"
        )
        is True
    ):

        score += 20
        known_signal = True

        reasons.append(
            "Sender domain has no valid MX record"
        )

    # ========================================================
    # 6. NEW DOMAIN
    # ========================================================

    if (
        domain_data.get(
            "is_new_domain"
        )
        is True
    ):

        score += 20
        known_signal = True

        age = domain_data.get(
            "domain_age_days"
        )

        if age is not None:

            reasons.append(
                f"Domain is newly registered ({age} days old)"
            )

        else:

            reasons.append(
                "Sender domain appears newly registered"
            )

    # ========================================================
    # 7. SUSPICIOUS TLD
    # ========================================================

    if (
        domain_data.get(
            "suspicious_tld"
        )
        is True
    ):

        score += 15
        known_signal = True

        tld = domain_data.get(
            "tld"
        )

        if tld:

            reasons.append(
                f"Domain uses suspicious TLD .{tld}"
            )

        else:

            reasons.append(
                "Domain uses a suspicious top-level domain"
            )

    # ========================================================
    # 8. BODY DOMAIN MISMATCH
    # ========================================================

    if (
        domain_data.get(
            "body_mismatch"
        )
        is True
    ):

        score += 20
        known_signal = True

        reasons.append(
            "Body links do not match the sender domain"
        )

    # ========================================================
    # 9. SPF + DMARC BOTH ABSENT
    # ========================================================

    spf_present = domain_data.get(
        "spf_present"
    )

    dmarc_present = domain_data.get(
        "dmarc_present"
    )

    # IMPORTANT:
    # Only charge +10 when BOTH lookups explicitly succeeded
    # and both records were absent.
    #
    # False + False => +10
    # None  + None  => +0
    # False + None  => +0
    # None  + False => +0

    if (
        spf_present is False
        and dmarc_present is False
    ):

        score += 10
        known_signal = True

        reasons.append(
            "Sender domain has neither SPF nor DMARC record"
        )

    # ========================================================
    # 10. HOMOGRAPH
    # ========================================================

    if (
        domain_data.get(
            "is_homograph"
        )
        is True
    ):

        # Supporting signal only.
        reasons.append(
            "Domain contains Unicode/lookalike characters"
        )

    # ========================================================
    # CAP
    # ========================================================

    final_score = min(
        max(score, 0),
        100
    )

    # ========================================================
    # UNKNOWN / LOW
    # ========================================================

    if not known_signal:

        reputation_known = (
            domain_data.get(
                "reputation_status"
            )
            == "success"
        )

        mx_known = (
            domain_data.get(
                "mx_status_known"
            )
            is True
        )

        spf_known = (
            domain_data.get(
                "spf_status_known"
            )
            is True
        )

        dmarc_known = (
            domain_data.get(
                "dmarc_status_known"
            )
            is True
        )

        age_known = (
            domain_data.get(
                "domain_age_days"
            ) is not None
        )

        if (
            reputation_known
            or mx_known
            or spf_known
            or dmarc_known
            or age_known
        ):

            return {
                "risk_score": 0,
                "risk_level": "LOW",
                "risk_reasons": [
                    "No known domain risk indicators detected"
                ]
            }

        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "No conclusive domain risk intelligence available"
            ]
        }

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if final_score >= 70:

        risk_level = "HIGH"

    elif final_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_reasons": reasons
    }


# ============================================================
# MAIN DOMAIN INTELLIGENCE
# ============================================================

def analyze_domain_intelligence(
    from_header: Optional[str],
    reply_to_header: Optional[str] = None,
    return_path_header: Optional[str] = None,
    body_urls: Optional[List[str]] = None,
    offline_mode: bool = False
) -> Dict[str, Any]:

    if not isinstance(
        body_urls,
        list
    ):
        body_urls = []

    brand_targets = load_brand_targets()

    # ========================================================
    # HEADER DOMAINS
    # ========================================================

    from_parts = extract_domain_parts(
        from_header
    )

    reply_parts = extract_domain_parts(
        reply_to_header
    )

    return_parts = extract_domain_parts(
        return_path_header
    )

    from_domain = (
        from_parts.get(
            "registered_domain"
        )
    )

    reply_domain = (
        reply_parts.get(
            "registered_domain"
        )
    )

    return_domain = (
        return_parts.get(
            "registered_domain"
        )
    )

    # ========================================================
    # BODY DOMAINS
    # ========================================================

    body_domains = set()

    for url in body_urls:

        parts = extract_domain_parts(
            url
        )

        body_domain = (
            parts.get(
                "registered_domain"
            )
        )

        if body_domain:

            body_domains.add(
                body_domain
            )

    # ========================================================
    # LOOKALIKE
    # ========================================================

    lookalike_info = detect_lookalike_brand(
        from_parts.get(
            "domain_name"
        ) or "",
        brand_targets
    )

    # ========================================================
    # HOMOGRAPH
    # ========================================================

    homograph = detect_homograph(
        from_parts.get(
            "domain_name"
        )
    )

    # ========================================================
    # REPLY-TO ALIGNMENT
    #
    # Missing Reply-To => None
    # NOT mismatch
    # ========================================================

    if (
        from_domain
        and reply_domain
    ):

        reply_to_mismatch = (
            reply_domain != from_domain
        )

    else:

        reply_to_mismatch = None

    # ========================================================
    # RETURN-PATH ALIGNMENT
    #
    # Missing Return-Path => None
    # NOT mismatch
    # ========================================================

    if (
        from_domain
        and return_domain
    ):

        return_path_mismatch = (
            return_domain != from_domain
        )

    else:

        return_path_mismatch = None

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
    # DNS
    # ========================================================

    if offline_mode:

        has_mx = None
        spf_present = None
        dmarc_present = None
        domain_age_days = None

    else:

        has_mx = check_mx_record(
            from_domain
        )

        spf_present = check_spf_record(
            from_domain
        )

        dmarc_present = check_dmarc_record(
            from_domain
        )

        domain_age_days = (
            get_domain_age_days(
                from_domain
            )
        )

    # ========================================================
    # NEW DOMAIN
    # ========================================================

    new_domain_flag = is_new_domain(
        domain_age_days
    )

    # ========================================================
    # TLD
    # ========================================================

    suspicious_tld = is_suspicious_tld(
        from_parts.get(
            "suffix"
        )
    )

    # ========================================================
    # REPUTATION
    # ========================================================

    if offline_mode:

        reputation = {
            "reputation_status":
                "offline_or_private",

            "provider":
                "VirusTotal",

            "is_malicious":
                None,

            "malicious_detections":
                None,

            "suspicious_detections":
                None,

            "total_detections":
                None,

            "malicious_ratio":
                None,

            "reputation_score":
                None
        }

    else:

        reputation = (
            enrich_domain_reputation(
                from_domain
            )
        )

    # ========================================================
    # SCORING INPUT
    # ========================================================

    scoring_data = {

        "is_malicious":
            reputation.get(
                "is_malicious"
            ),

        "reputation_status":
            reputation.get(
                "reputation_status"
            ),

        "malicious_detections":
            reputation.get(
                "malicious_detections"
            ),

        "total_detections":
            reputation.get(
                "total_detections"
            ),

        "is_lookalike":
            lookalike_info.get(
                "is_lookalike"
            ),

        "matched_brand":
            lookalike_info.get(
                "matched_brand"
            ),

        "reply_to_mismatch":
            reply_to_mismatch is True,

        "return_path_mismatch":
            return_path_mismatch is True,

        "missing_mx":
            has_mx is False,

        "is_new_domain":
            new_domain_flag,

        "suspicious_tld":
            suspicious_tld is True,

        "body_mismatch":
            body_domain_mismatch,

        "is_homograph":
            homograph,

        "domain_age_days":
            domain_age_days,

        "mx_status_known":
            has_mx is not None,

        "spf_status_known":
            spf_present is not None,

        "dmarc_status_known":
            dmarc_present is not None,

        "spf_present":
            spf_present,

        "dmarc_present":
            dmarc_present,

        "tld":
            from_parts.get(
                "suffix"
            )
    }

    # ========================================================
    # RISK
    # ========================================================

    risk = calculate_domain_risk(
        scoring_data,
        api_failed=False
    )

    # ========================================================
    # RETURN
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
                reply_domain,

            "return_path_domain":
                return_domain,

            "body_domains":
                sorted(
                    body_domains
                )
        },

        # ----------------------------------------------------
        # METADATA
        # ----------------------------------------------------

        "domain_metadata": {

            "domain_age_days":
                domain_age_days,

            "is_new_domain":
                new_domain_flag,

            "new_domain_threshold_days":
                DOMAIN_NEW_THRESHOLD_DAYS,

            "suspicious_tld":
                suspicious_tld,

            "tld":
                from_parts.get(
                    "suffix"
                ),

            "reputation_available":
                reputation.get(
                    "reputation_status"
                ) == "success",

            "reputation_provider":
                reputation.get(
                    "provider"
                ),

            "homograph_detected":
                homograph
        },

        # ----------------------------------------------------
        # REPUTATION
        # ----------------------------------------------------

        "reputation":
            reputation,

        # ----------------------------------------------------
        # ALIGNMENT
        # ----------------------------------------------------

        "identity_alignment": {

            "from_matches_reply_to":
                (
                    None
                    if reply_domain is None
                    else not reply_to_mismatch
                ),

            "from_matches_return_path":
                (
                    None
                    if return_domain is None
                    else not return_path_mismatch
                ),

            "from_matches_body_links":
                not body_domain_mismatch
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
                has_mx is not None,

            "spf_present":
                spf_present,

            "spf_lookup_available":
                spf_present is not None,

            "dmarc_present":
                dmarc_present,

            "dmarc_lookup_available":
                dmarc_present is not None
        },

        # ----------------------------------------------------
        # SIGNALS
        # ----------------------------------------------------

        "signals": {

            "reply_to_mismatch":
                (
                    None
                    if reply_domain is None
                    else reply_to_mismatch
                ),

            "return_path_mismatch":
                (
                    None
                    if return_domain is None
                    else return_path_mismatch
                ),

            "is_brand_lookalike":
                lookalike_info.get(
                    "is_lookalike"
                ),

            "body_domain_mismatch":
                body_domain_mismatch,

            "from_missing_mx":
                has_mx is False,

            "is_malicious":
                reputation.get(
                    "is_malicious"
                ),

            "is_new_domain":
                new_domain_flag,

            "suspicious_tld":
                suspicious_tld,

            "is_homograph":
                homograph
        },

        # ----------------------------------------------------
        # RISK
        # ----------------------------------------------------

        "risk_score":
            risk["risk_score"],

        "risk_level":
            risk["risk_level"],

        "risk_reasons":
            risk["risk_reasons"],

        "normalized_output":
            risk
    }